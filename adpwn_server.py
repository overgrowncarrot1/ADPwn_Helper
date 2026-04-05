#!/usr/bin/env python3
"""
adpwn_server.py — AD▸PWN Multi-Operator Collaboration Server v2.1

Changes from v2.0:
  - Challenge-response password auth (password never sent in plaintext)
  - adpwn_watch.py watcher connections work correctly (send set_name on connect)
  - All /data/logs paths watched by all connected watchers are aggregated

Usage:
    python3 adpwn_server.py --html ad_helper_fixed.html --password ops2024
    python3 adpwn_server.py --html ad_helper_fixed.html --password ops2024 --http-port 9090

Requirements:
    pip install websockets

Auth scheme (wireshark-safe):
    1. Server sends:  {"type":"auth_challenge","nonce":"<32 hex chars>"}
    2. Client sends:  {"type":"auth_response","hash":"sha256(nonce+sha256(password))","name":"...","role":"..."}
    3. Server verifies hash. Mismatch → close immediately.
    Password is never transmitted — only a one-time-use derived hash.
"""

import asyncio, hashlib, json, logging, re, secrets, sys, threading, time, argparse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

try:
    from websockets.asyncio.server import serve as ws_serve
except ImportError:
    try:
        from websockets.legacy.server import serve as ws_serve
    except ImportError:
        print("[!] pip install websockets", file=sys.stderr); sys.exit(1)

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger('adpwn')

# ── Auth ──────────────────────────────────────────────────────────────────────
PASSWORD_HASH = ''  # sha256(password), set at startup

def set_password(pw: str):
    global PASSWORD_HASH
    PASSWORD_HASH = hashlib.sha256(pw.encode('utf-8')).hexdigest()

def verify_response(nonce: str, client_hash: str) -> bool:
    if not PASSWORD_HASH:
        return True  # no password set — open access
    expected = hashlib.sha256((nonce + PASSWORD_HASH).encode('utf-8')).hexdigest()
    return secrets.compare_digest(expected, client_hash)

# ── Shared state ──────────────────────────────────────────────────────────────
shared = {
    'discoveries': [], 'harvested': [], 'access': [],
    'hosts': [], 'logs': [], 'thingsTried': {}, 'creds': {},
}
clients: dict = {}  # ws → {'name': str, 'role': str, 'authed': bool}
SAVE_FILE = 'adpwn_state.json'

def save_state():
    try:
        with open(SAVE_FILE, 'w') as f: json.dump(shared, f, indent=2)
    except Exception as e: log.warning(f"Save failed: {e}")

def load_state():
    if Path(SAVE_FILE).exists():
        try:
            with open(SAVE_FILE) as f: shared.update(json.load(f))
            log.info(f"Restored: {len(shared['discoveries'])} disc, "
                     f"{len(shared['harvested'])} creds, {len(shared['hosts'])} hosts")
        except Exception as e: log.warning(f"Load failed: {e}")

# ── Merge helpers ─────────────────────────────────────────────────────────────
def merge_discoveries(items, by):
    added = 0
    for d in items:
        if not any(x['type']==d['type'] and x['value']==d['value'] for x in shared['discoveries']):
            d['by'] = by; shared['discoveries'].append(d); added += 1
    return added

def merge_harvested(rows, by):
    added = 0
    for row in rows:
        nt = row.get('hash','').split(':')[-1] if ':' in row.get('hash','') else row.get('hash','')
        if not any(h['user']==row.get('user') and (
            (h.get('hash','').split(':')[-1] if ':' in h.get('hash','') else h.get('hash',''))==nt
            or h.get('password')==row.get('password')) for h in shared['harvested']):
            row['by'] = by; shared['harvested'].append(row); added += 1
    return added

def merge_access(items, by):
    for a in items:
        ex = next((x for x in shared['access']
                   if x['user']==a.get('user') and x['ip']==a.get('ip') and x['proto']==a.get('proto')), None)
        if not ex: a['by']=by; shared['access'].append(a)
        elif a.get('level')=='admin': ex['level']='admin'

def merge_hosts(items):
    RANK = {'host':0,'Admin Host':1,'ADCS':2,'Target':2,'Attacker':2,'Domain Controller':3}
    for h in items:
        ex = next((x for x in shared['hosts'] if x['ip']==h.get('ip')), None)
        if not ex: shared['hosts'].append(h)
        else:
            if h.get('name') and not ex.get('name'): ex['name']=h['name']
            if RANK.get(h.get('role',''),0)>RANK.get(ex.get('role',''),0): ex['role']=h['role']

def operator_list():
    return list(dict.fromkeys(  # deduplicate while preserving order
        v['name'] for v in clients.values()
        if v.get('role') == 'browser' and v.get('authed')
    ))

# ── Broadcast ─────────────────────────────────────────────────────────────────
async def broadcast(msg, exclude=None):
    dead, payload = set(), json.dumps(msg)
    for ws, info in list(clients.items()):
        if not info.get('authed') or info.get('role')!='browser' or ws is exclude: continue
        try: await ws.send(payload)
        except: dead.add(ws)
    for ws in dead: clients.pop(ws, None)

# ── WebSocket handler ─────────────────────────────────────────────────────────
async def ws_handler(websocket):
    addr   = getattr(websocket, 'remote_address', '?')
    nonce  = secrets.token_hex(16)
    clients[websocket] = {'name': '(pending)', 'role': 'browser', 'authed': False}

    try:
        await websocket.send(json.dumps({'type': 'auth_challenge', 'nonce': nonce,
                                         'has_password': bool(PASSWORD_HASH)}))
    except Exception: clients.pop(websocket, None); return

    name = None

    try:
        async for raw in websocket:
            try: msg = json.loads(raw)
            except: msg = {'type': 'log_lines', 'text': raw}

            mtype = msg.get('type', '')
            info  = clients.get(websocket, {})

            # ── Auth response (first real message) ────────────────────────
            if mtype == 'auth_response':
                client_hash = msg.get('hash', '')
                if not verify_response(nonce, client_hash):
                    log.warning(f"  {addr} — WRONG PASSWORD, closing")
                    await websocket.send(json.dumps({'type': 'auth_failed',
                                                     'reason': 'wrong password'}))
                    await websocket.close()
                    return

                name = (msg.get('name') or '').strip()[:32] or f'op{len(clients):02d}'
                role = msg.get('role', 'browser')
                clients[websocket] = {'name': name, 'role': role, 'authed': True}
                if role == 'browser':
                    log.info(f"[+] '{name}' joined")

                await websocket.send(json.dumps({
                    'type': 'welcome', 'name': name,
                    'state': shared, 'operators': operator_list(),
                }))
                await broadcast({'type': 'operator_joined', 'name': name}, exclude=websocket)
                continue

            # Block everything until authed
            if not info.get('authed') or name is None:
                continue

            # ── State patch ───────────────────────────────────────────────
            if mtype == 'patch':
                d = msg.get('delta', {}); changed = False
                if d.get('discoveries') and merge_discoveries(d['discoveries'], name): changed=True
                if d.get('harvested')   and merge_harvested(d['harvested'], name):    changed=True
                if d.get('access'):   merge_access(d['access'], name);   changed=True
                if d.get('hosts'):    merge_hosts(d['hosts']);            changed=True
                if d.get('logs'):
                    for l in d['logs']:
                        l['by']=name
                        if not any(x.get('atkKey')==l.get('atkKey') and x.get('target')==l.get('target')
                                   for x in shared['logs']):
                            shared['logs'].append(l); changed=True
                if changed:
                    save_state()
                    await broadcast({'type':'state_sync','by':name,'state':shared,
                                     'operators':operator_list()}, exclude=websocket)

            # ── Things to Try checkbox ────────────────────────────────────
            elif mtype == 'check_item':
                iid = msg.get('item_id')
                if iid:
                    if msg.get('done', True):
                        shared['thingsTried'][iid] = {'done':True,'operator':name,
                            'time':datetime.now().strftime('%H:%M:%S'),'note':msg.get('note','')}
                    elif iid in shared['thingsTried']:
                        del shared['thingsTried'][iid]
                    save_state()
                    await broadcast({'type':'item_checked','item_id':iid,'done':msg.get('done',True),
                                     'by':name,'data':shared['thingsTried'].get(iid,{})})

            # ── Shared network creds ──────────────────────────────────────
            # ── Clear vault (operator wiped creds in browser) ────────────────
            elif mtype == 'clear_vault':
                shared['harvested'] = []
                shared['access']    = []
                save_state()
                log.info(f"  '{name}' cleared the vault")
                # Broadcast empty state so all browsers wipe their vaults too
                await broadcast({
                    'type': 'clear_vault',
                    'by':   name,
                })

            elif mtype == 'set_cred':
                k, v = msg.get('key',''), msg.get('value','')
                if k in ('DC_IP','DOMAIN','TARGET_IP','ATTACKER_IP','CA_IP','CA_NAME','SUBNET'):
                    shared['creds'][k]=v; save_state()
                    await broadcast({'type':'cred_update','key':k,'value':v,'by':name}, exclude=websocket)

            # ── Terminal log lines (from browser paste or watcher) ────────
            elif mtype == 'log_lines':
                text = msg.get('text','')
                if text.strip():
                    parsed = parse_log_server(text, name)
                    changed = False
                    if parsed.get('discoveries') and merge_discoveries(parsed['discoveries'], name): changed=True
                    if parsed.get('harvested')   and merge_harvested(parsed['harvested'], name):    changed=True
                    if parsed.get('access'):   merge_access(parsed['access'], name);   changed=True
                    if parsed.get('hosts'):    merge_hosts(parsed['hosts']);            changed=True
                    if changed:
                        save_state()
                        await broadcast({'type':'state_sync','by':name,'state':shared,
                                         'operators':operator_list()}, exclude=websocket)

            elif mtype == 'ping':
                await websocket.send(json.dumps({'type':'pong'}))

    except Exception as e:
        if 'ConnectionClosed' not in type(e).__name__:
            log.error(f"[!] {name or addr}: {e}")
    finally:
        clients.pop(websocket, None)
        if name:
            if role == 'browser':
                log.info(f"[-] '{name}' left")
            await broadcast({'type':'operator_left','name':name,'role':role})

# ── Server-side log parser ────────────────────────────────────────────────────
_BLANK_NT   = '31d6cfe0d16ae931b73c59d7e0c089c0'
_SKIP_USERS = re.compile(r'^(Guest|DefaultAccount|WDAGUtilityAccount|krbtgt|\$)', re.I)
_ANSI       = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def strip_ansi(s): return _ANSI.sub('', s).strip()

def parse_log_server(text, op):
    result = {'discoveries':[], 'harvested':[], 'access':[], 'hosts':[]}
    ts = datetime.now().strftime('%H:%M:%S')
    def disc(t,v,s):
        if not any(d['type']==t and d['value']==v for d in result['discoveries']):
            result['discoveries'].append({'type':t,'value':v,'source':s,'time':ts})
    for raw in text.split('\n'):
        line = strip_ansi(raw).strip()
        if not line: continue
        # secretsdump NTDS
        sd = re.match(r'^(?:[^\\/]+[\\/])?([^:$\s]+):\d+:([a-f0-9]{32}):([a-f0-9]{32}):::', line, re.I)
        if sd:
            u,lm,nt=sd.group(1),sd.group(2),sd.group(3)
            if not _SKIP_USERS.match(u) and nt.lower()!=_BLANK_NT:
                result['harvested'].append({'user':u,'hash':f'{lm}:{nt}','password':'',
                    'source':'secretsdump','validOn':[],'adminOn':[],'time':ts})
                disc('username',u,'secretsdump')
            continue
        # hashcat --show --username
        hc = re.match(r'^([^:\s][^:]*):([a-f0-9]{32}):(.+)$', line, re.I)
        if hc:
            u,h,p=hc.group(1),hc.group(2),hc.group(3).strip()
            if p and not _SKIP_USERS.match(u) and h.lower()!=_BLANK_NT:
                result['harvested'].append({'user':u,'hash':h,'password':p,
                    'source':'hashcat','validOn':[],'adminOn':[],'time':ts})
                disc('username',u,'hashcat'); disc('password',p,'hashcat')
            continue
        # NXC [+]
        nxc = re.match(r'^(SMB|LDAP|WINRM|MSSQL|RDP|SSH)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+'
                       r'\[\+\]\s+([^\\]+)\\([^:]+):(.+?)(?:\s+\(([^)]*)\))?\s*$', line, re.I)
        if nxc:
            proto,ip,hn,dom,u,pw=(nxc.group(i) for i in range(1,7))
            flags=nxc.group(7) or ''; proto=proto.upper()
            lvl=('admin' if re.search(r'Pwn3d|Admin!',flags,re.I) else
                 'guest'  if re.search(r'Guest',flags,re.I) else 'user')
            pt=pw.strip()
            if pt and not _SKIP_USERS.match(u):
                result['harvested'].append({'user':u,'hash':'','password':pt,'source':'nxc',
                    'validOn':[f'{proto}\\{dom}\\{hn}'],'adminOn':[hn] if lvl=='admin' else [],'time':ts})
                disc('username',u,'nxc'); disc('password',pt,'nxc')
            result['access'].append({'user':u,'domain':dom,'ip':ip,'hostname':hn,
                                     'proto':proto,'level':lvl,'time':ts})
            result['hosts'].append({'ip':ip,'name':hn,'role':'Admin Host' if lvl=='admin' else 'host'})
            disc('ip',ip,'nxc')
    return result

# ── HTTP server ───────────────────────────────────────────────────────────────
HTML_CONTENT = ''
WS_PORT      = 8765

def inject_collab(html, ws_port, has_pw):
    script = COLLAB_JS.replace('__WS_PORT__', str(ws_port)) \
                      .replace('__HAS_PASSWORD__', 'true' if has_pw else 'false')
    return html.replace('</body>', script + '\n</body>', 1)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.rstrip('/') in ('','index.html','/adpwn','/ad_helper.html','/ad_helper_fixed.html'):
            content = HTML_CONTENT.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(content)))
            self.send_header('Cache-Control','no-cache')
            self.end_headers(); self.wfile.write(content)
        elif self.path == '/wiki.json':
            p = Path('wiki.json')
            if p.exists():
                content = p.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type','application/json; charset=utf-8')
                self.send_header('Content-Length',str(len(content)))
                self.send_header('Cache-Control','no-cache')
                self.end_headers(); self.wfile.write(content)
            else: self.send_error(404)
        elif self.path == '/wiki':
            p = Path('wiki.html')
            if p.exists():
                content = p.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type','text/html; charset=utf-8')
                self.send_header('Content-Length',str(len(content)))
                self.send_header('Cache-Control','no-cache')
                self.end_headers(); self.wfile.write(content)
            else: self.send_error(404)
        else: self.send_error(404)

async def main(args):
    global HTML_CONTENT, WS_PORT
    WS_PORT = args.ws_port
    if args.password:
        set_password(args.password)
    load_state()
    html_path = Path(args.html)
    if not html_path.exists():
        log.error(f"HTML not found: {args.html}"); sys.exit(1)
    HTML_CONTENT = html_path.read_text(encoding='utf-8')
    log.info(f"[+] Loaded {args.html} ({len(HTML_CONTENT):,} chars)")
    def run_http():
        server = HTTPServer((args.host, args.http_port), Handler)
        log.info(f"[+] HTTP  → http://{args.host}:{args.http_port}/")
        server.serve_forever()
    threading.Thread(target=run_http, daemon=True).start()
    async with ws_serve(ws_handler, args.host, args.ws_port, max_size=10*1024*1024):
        log.info(f"[+] WS    → ws://{args.host}:{args.ws_port}/")
        log.info("[+] Waiting for operators…\n")
        await asyncio.Future()

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='AD▸PWN Server v2.1')
    p.add_argument('--html',      default='adpwn.html')
    p.add_argument('--host',      default='0.0.0.0')
    p.add_argument('--http-port', type=int, default=8080, dest='http_port')
    p.add_argument('--ws-port',   type=int, default=8765, dest='ws_port')
    p.add_argument('--password',  default='', help='Engagement password (recommended)')
    p.add_argument('--reset',     action='store_true',
                   help='Wipe adpwn_state.json and start fresh (new engagement)')
    args = p.parse_args()
    try: asyncio.run(main(args))
    except KeyboardInterrupt: log.info('\n[+] Stopped.')
