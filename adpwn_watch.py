#!/usr/bin/env python3
"""
adpwn_watch.py — AD▸PWN File Watcher v2.0
Streams terminal output to the AD▸PWN server via WebSocket.

Changes from v1.x:
  - Authenticates with challenge-response (password never in plaintext)
  - Sends set_name/auth_response on connect so server knows which operator
  - Works with adpwn_server.py (multi-operator mode) AND standalone mode
  - Watches any path — use /data/logs or a specific .raw file
  - Only watches *.raw files (script(1) recordings) by default

Usage:
    # Watch your own /data/logs directory
    python3 adpwn_watch.py /data/logs --name alice --password ops2024

    # Connect to remote server instead of localhost
    python3 adpwn_watch.py /data/logs --name bob --password ops2024 --host 192.168.56.10

    # Watch from beginning of existing files
    python3 adpwn_watch.py /data/logs --name carol --password ops2024 --tail

    # No password (if server has none)
    python3 adpwn_watch.py /data/logs --name dave

Requirements:
    pip install websockets watchdog
"""

import asyncio, sys, re, json, threading, time, argparse, hashlib, secrets
from pathlib import Path
from datetime import datetime

def log(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr, flush=True)

try:
    from websockets.asyncio.client import connect as ws_connect
except ImportError:
    try:
        from websockets.legacy.client import connect as ws_connect
    except ImportError:
        log("[!] pip install websockets"); sys.exit(1)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    log("[~] pip install watchdog  (using polling fallback)")

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_HOST        = 'localhost'
DEFAULT_PORT        = 8765
POLL_INTERVAL       = 1.0
WATCH_SUFFIX        = ('.raw', '.log', '.txt', '.out', '.typescript', '')
SESSION_REPLAY_MINS = 240
MAX_FILE_SIZE       = 100 * 1024 * 1024

NOISE = re.compile(
    r'^Running \w+ against \d+ targets'
    r'|^Script (started|done) on '
    r'|\bkeystrokes\b|\btiming\b|\btyped\b'
    r'|^\s*\[\d{2}:\d{2}:\d{2}\] .*\.raw: \d+ line'
    r'|^\[.\] .*\.raw'
    r'|AD.PWN|Watching\s*:|WebSocket\s*:|Watchdog active'
    r'|Waiting for connections|tail from end|replay on connect'
    r'|Client (connected|disconnected)|lines replayed|seek_end'
    r'|^[╔╠╚║│─═]|^\s*$', re.I)

_ANSI = re.compile(
    r'\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]'
    r'|\x1b[\x20-\x2f]*[\x40-\x7e]|\x1b|(?<!\x1b)\(B'
    r'|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

def strip_ansi(s):
    s = _ANSI.sub('', s)
    s = re.sub(r'\[\d+(?:;\d+)*m', '', s)
    return s.strip()

def clean(raw):
    line = strip_ansi(raw)
    return '' if (not line or NOISE.match(line)) else line

def should_watch(path):
    p = Path(path)
    if not p.is_file(): return False
    try:
        if p.stat().st_size > MAX_FILE_SIZE: return False
    except: return False
    return p.name.lower().endswith(WATCH_SUFFIX) or not p.suffix  # no extension = watch it too

# ── Auth ──────────────────────────────────────────────────────────────────────
async def sha256hex(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

async def do_auth(ws, name, password):
    """
    Receive challenge from server, respond with sha256(nonce+sha256(password)).
    Then send set_name so server knows who we are.
    Returns True on success.
    """
    raw = await ws.recv()
    msg = json.loads(raw)
    if msg.get('type') != 'auth_challenge':
        log(f"[!] Expected auth_challenge, got: {msg.get('type')}")
        return False

    nonce = msg.get('nonce', '')
    has_pw = msg.get('has_password', False)

    # Compute challenge response
    pw_hash  = await sha256hex(password if has_pw else '')
    response = await sha256hex(nonce + pw_hash)

    await ws.send(json.dumps({
        'type':  'auth_response',
        'hash':  response,
        'name':  name,
        'role':  'watcher',
    }))

    # Wait for welcome or auth_failed
    raw2 = await ws.recv()
    msg2 = json.loads(raw2)
    if msg2.get('type') == 'auth_failed':
        log(f"[!] Authentication failed — check --password")
        return False
    if msg2.get('type') == 'welcome':
        log(f"[+] Authenticated as '{msg2.get('name')}'")
        return True

    log(f"[?] Unexpected response: {msg2.get('type')}")
    return False

# ── File state ────────────────────────────────────────────────────────────────
file_offsets  = {}
file_buffers  = {}
_pending_lines = []
_ws_ref  = [None]   # current websocket
_loop_ref = [None]  # the asyncio event loop, set at startup

def _send_line(line):
    ws   = _ws_ref[0]
    loop = _loop_ref[0]
    if ws is None or loop is None:
        _pending_lines.append(line)
        return
    asyncio.run_coroutine_threadsafe(_ws_send(ws, line), loop)

async def _ws_send(ws, line):
    try:
        msg = json.dumps({'type': 'log_lines', 'text': line})
        if len(msg.encode('utf-8')) < 900_000:
            await ws.send(msg)
    except: pass

def read_new_lines(filepath):
    p = Path(filepath).resolve()
    fp = str(p)
    if not p.exists(): return
    if fp not in file_offsets:
        file_offsets[fp] = p.stat().st_size  # tail mode for new files
        return
    try:
        with open(fp, 'r', errors='replace') as f:
            f.seek(file_offsets[fp])
            chunk = f.read()
            file_offsets[fp] = f.tell()
        if not chunk: return
        chunk = file_buffers.pop(fp, '') + chunk
        parts = chunk.split('\n')
        file_buffers[fp] = parts[-1]  # incomplete last line
        for raw in parts[:-1]:
            line = clean(raw)
            if line: _send_line(line)
    except Exception as e:
        log(f'[!] {fp}: {e}')

def slurp(p):
    lines = []
    try:
        with open(p, 'r', errors='replace') as f:
            for raw in f:
                line = clean(raw.rstrip('\n'))
                if line: lines.append(line)
    except Exception as e:
        log(f'[slurp] {p.name}: {e}')
    return lines

# ── Watchdog ──────────────────────────────────────────────────────────────────
if HAS_WATCHDOG:
    class LogHandler(FileSystemEventHandler):
        def on_modified(self, ev):
            if not ev.is_directory and should_watch(ev.src_path):
                read_new_lines(str(Path(ev.src_path).resolve()))
        def on_created(self, ev):
            if not ev.is_directory and should_watch(ev.src_path):
                fp = str(Path(ev.src_path).resolve())
                file_offsets[fp] = 0
                read_new_lines(fp)

def poll_loop(target):
    while True:
        try:
            files = [target] if target.is_file() else [
                f for f in target.rglob('*') if f.is_file()]
            for f in files:
                if should_watch(str(f)): read_new_lines(str(f))
        except Exception as e:
            log(f'[!] Poll: {e}')
        time.sleep(POLL_INTERVAL)

# ── Main ──────────────────────────────────────────────────────────────────────
async def main(args):
    global _ws_ref
    global _loop_ref
    _loop_ref[0] = asyncio.get_event_loop()
    target   = Path(args.path)
    ws_url   = f'ws://{args.host}:{args.port}'
    name     = args.name or 'operator'
    password = args.password or ''

    if not target.exists():
        log(f'[!] {args.path} does not exist — creating')
        target.mkdir(parents=True, exist_ok=True)

    log(f"""
╔══════════════════════════════════════════════════════════════╗
║             AD▸PWN File Watcher v2.0                        ║
╠══════════════════════════════════════════════════════════════╣
║  Watching  : {str(args.path):<47}║
║  Server    : {ws_url:<47}║
║  Operator  : {name:<47}║
║  Auth      : {'password set' if password else 'no password':<47}║
╚══════════════════════════════════════════════════════════════╝
""")

    # Initialise file offsets
    now = time.time()
    existing = sorted(
        f for f in (target.rglob('*') if target.is_dir() else [target])
        if f.is_file() and (not target.is_dir() or should_watch(str(f)))
    )
    for ef in existing:
        fp = str(ef.resolve())
        age_mins = (now - ef.stat().st_mtime) / 60
        if args.tail or (args.since > 0 and age_mins <= args.since):
            file_offsets[fp] = 0
        else:
            file_offsets[fp] = ef.stat().st_size
        log(f'  watching: {ef.name} ({"from start" if file_offsets[fp]==0 else "tail"})')

    # Start file watcher
    if HAS_WATCHDOG:
        obs = Observer()
        obs.schedule(LogHandler(),
                     str(target if target.is_dir() else target.parent),
                     recursive=True)
        obs.start()
        log('[+] Watchdog active')
    else:
        threading.Thread(target=poll_loop, args=(target,), daemon=True).start()
        log(f'[~] Polling every {POLL_INTERVAL}s')

    # Connection loop — reconnects forever
    while True:
        try:
            log(f'[~] Connecting to {ws_url} as {name}…')
            async with ws_connect(ws_url, max_size=10*1024*1024) as ws:
                if not await do_auth(ws, name, password):
                    log('[!] Auth failed — waiting 10s before retry')
                    await asyncio.sleep(10)
                    continue

                _ws_ref[0] = ws
                log(f'[+] Connected — streaming {args.path}')

                # Drain any lines queued while disconnected
                while _pending_lines:
                    line = _pending_lines.pop(0)
                    try: await ws.send(json.dumps({'type':'log_lines','text':line}))
                    except: _pending_lines.insert(0, line); break

                # Replay recent files to server
                for ef in existing:
                    try:
                        age_mins = (now - ef.stat().st_mtime) / 60
                        if age_mins > SESSION_REPLAY_MINS: continue
                        lines = slurp(ef)
                        if lines:
                            # Chunk to stay under WS frame limit (~900 KB per message)
                            CHUNK = 500
                            sent = 0
                            for i in range(0, len(lines), CHUNK):
                                batch = '\n'.join(lines[i:i+CHUNK])
                                if len(batch.encode('utf-8')) > 900_000:
                                    # Further split if chunk still too big
                                    for line in lines[i:i+CHUNK]:
                                        try:
                                            await ws.send(json.dumps({'type':'log_lines','text':line}))
                                        except: pass
                                else:
                                    await ws.send(json.dumps({'type':'log_lines','text':batch}))
                                sent += min(CHUNK, len(lines)-i)
                            log(f'  replayed {len(lines)} lines from {ef.name}')
                    except Exception as e:
                        log(f'  [replay] {ef.name}: {e}')

                # Keepalive / receive loop
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                        if msg.get('type') == 'seek_end':
                            for fp in list(file_offsets):
                                try: file_offsets[fp] = Path(fp).stat().st_size
                                except: pass
                            file_buffers.clear()
                            log('[~] seek_end — watching from now')
                    except: pass

        except Exception as e:
            _ws_ref[0] = None
            log(f'[~] Disconnected ({e}) — retrying in 5s')
            await asyncio.sleep(5)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='AD▸PWN File Watcher v2.0')
    p.add_argument('path',    nargs='?', default='/data/logs',
                   help='File or directory to watch (default: /data/logs)')
    p.add_argument('--name',     default='', help='Your operator name/callsign')
    p.add_argument('--password', default='', help='Engagement password')
    p.add_argument('--host',     default=DEFAULT_HOST, help='Server host (default: localhost)')
    p.add_argument('--port',     type=int, default=DEFAULT_PORT, help='Server WS port — must match adpwn_server.py --ws-port (default: 8765)')
    p.add_argument('--tail',     action='store_true', help='Replay all existing content on connect')
    p.add_argument('--since',    type=int, default=0, metavar='MINUTES',
                   help='Replay files modified in last N minutes (default: 240)')
    args = p.parse_args()
    try: asyncio.run(main(args))
    except KeyboardInterrupt: log('\n[+] Stopped.')
