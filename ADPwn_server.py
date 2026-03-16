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
            content = HTML_CONTENT.encode('utf-8')  # COLLAB_JS already baked in by build_adpwn.py
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(content)))
            self.send_header('Cache-Control','no-cache')
            self.end_headers(); self.wfile.write(content)
        else: self.send_error(404)

# ── Collaboration JS ──────────────────────────────────────────────────────────
COLLAB_JS = """
<style>
#adpwn-modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.78);z-index:9000;
  display:flex;align-items:center;justify-content:center;}
#adpwn-modal{background:#161b22;border:1px solid #2a3142;border-radius:8px;
  padding:28px 32px;min-width:340px;max-width:420px;width:90%;
  font-family:'Cascadia Code','Fira Code',monospace;}
#adpwn-modal h2{font-size:14px;font-weight:700;color:#00cfff;letter-spacing:1px;
  text-transform:uppercase;margin-bottom:8px;}
#adpwn-modal p{font-size:11px;color:#7a8499;margin-bottom:16px;line-height:1.6;}
.adpwn-lbl{font-size:9px;font-weight:700;color:#4a5268;letter-spacing:1px;
  text-transform:uppercase;margin-bottom:4px;}
.adpwn-inp{width:100%;background:#0d0f12;border:1px solid #3a4258;border-radius:4px;
  padding:8px 12px;color:#c9d1e0;font-family:inherit;font-size:13px;
  outline:none;margin-bottom:14px;box-sizing:border-box;}
.adpwn-inp:focus{border-color:#00cfff;}
.adpwn-inp.err{border-color:#ff4f5e !important;}
.adpwn-err{font-size:11px;color:#ff4f5e;margin-bottom:10px;display:none;}
#adpwn-join-btn{width:100%;padding:9px;background:rgba(0,207,255,0.12);
  border:1px solid #00cfff;border-radius:4px;color:#00cfff;
  font-family:inherit;font-size:12px;font-weight:700;cursor:pointer;
  letter-spacing:0.5px;transition:background 0.15s;}
#adpwn-join-btn:hover{background:rgba(0,207,255,0.22);}
#collab-ops-bar{position:fixed;bottom:52px;right:18px;z-index:500;
  display:flex;gap:4px;flex-wrap:wrap;justify-content:flex-end;
  max-width:320px;pointer-events:none;}
.cop{padding:2px 9px;border-radius:10px;font-size:9px;font-weight:700;
  font-family:'Cascadia Code',monospace;background:rgba(0,207,255,0.1);
  border:1px solid rgba(0,207,255,0.3);color:#00cfff;}
.cop.me{background:rgba(74,242,161,0.12);border-color:rgba(74,242,161,0.4);color:#4af2a1;}
</style>

<div id="adpwn-modal-bg">
  <div id="adpwn-modal">
    <h2>&#128309; Join Engagement</h2>
    <p id="adpwn-modal-desc">Enter your callsign and the engagement password.</p>
    <div class="adpwn-lbl">Your Name / Callsign</div>
    <input class="adpwn-inp" id="adpwn-name" type="text"
           placeholder="e.g. alice, bob, op3" maxlength="32"
           autocomplete="off" spellcheck="false">
    <div id="adpwn-pw-wrap">
      <div class="adpwn-lbl">Engagement Password</div>
      <input class="adpwn-inp" id="adpwn-pw" type="password"
             placeholder="engagement password" autocomplete="off">
    </div>
    <div class="adpwn-err" id="adpwn-err">&#10007; Wrong password — try again</div>
    <button id="adpwn-join-btn" onclick="adpwnJoin()">Join &#8594;</button>
  </div>
</div>
<div id="collab-ops-bar"></div>

<script>
(function(){
'use strict';
var WS_URL  = 'ws://' + location.hostname + ':__WS_PORT__';
var HAS_PW  = __HAS_PASSWORD__;
var NAME_KEY = 'adpwn_op_name';

var myName  = localStorage.getItem(NAME_KEY) || '';
var ws      = null, authed = false, retryT = null;
var pendingNonce = null;

// ── Modal setup ─────────────────────────────────────────────────────────────
var modal   = document.getElementById('adpwn-modal-bg');
var nameInp = document.getElementById('adpwn-name');
var pwInp   = document.getElementById('adpwn-pw');
var pwWrap  = document.getElementById('adpwn-pw-wrap');
var errDiv  = document.getElementById('adpwn-err');
var desc    = document.getElementById('adpwn-modal-desc');

if (myName) nameInp.value = myName;

// Hide password field if server has no password set
if (!HAS_PW) {
  pwWrap.style.display = 'none';
  desc.textContent = 'Enter your callsign to join this engagement.';
}

[nameInp, pwInp].forEach(function(el){
  el.addEventListener('keydown', function(e){ if(e.key==='Enter') adpwnJoin(); });
});

window.adpwnJoin = function() {
  var n = (nameInp.value||'').trim();
  if (!n) { nameInp.classList.add('err'); nameInp.focus(); return; }
  nameInp.classList.remove('err');
  myName = n;
  localStorage.setItem(NAME_KEY, myName);
  modal.style.display = 'none';
  connect();
};

// Auto-join if name saved and no password required
if (myName && !HAS_PW) {
  setTimeout(function(){ modal.style.display='none'; connect(); }, 80);
} else {
  setTimeout(function(){ nameInp.focus(); }, 300);
}

// Pure-JS SHA-256 — works on HTTP (no HTTPS required)
// Based on the public domain implementation by Angel Marin / Paul Johnston
var _sha256 = (function(){
  function safe_add(x,y){var lsw=(x&0xFFFF)+(y&0xFFFF),msw=(x>>16)+(y>>16)+(lsw>>16);return(msw<<16)|(lsw&0xFFFF);}
  function S(X,n){return(X>>>n)|(X<<(32-n));}
  function R(X,n){return(X>>>n);}
  function Ch(x,y,z){return((x&y)^((~x)&z));}
  function Maj(x,y,z){return((x&y)^(x&z)^(y&z));}
  function Sigma0(x){return(S(x,2)^S(x,13)^S(x,22));}
  function Sigma1(x){return(S(x,6)^S(x,11)^S(x,25));}
  function Gamma0(x){return(S(x,7)^S(x,18)^R(x,3));}
  function Gamma1(x){return(S(x,17)^S(x,19)^R(x,10));}
  var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
         0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
         0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
         0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
         0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
         0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
         0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
         0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function core(m,l){
    var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    m[l>>5]|=0x80<<(24-l%32); m[((l+64>>9)<<4)+15]=l;
    for(var i=0;i<m.length;i+=16){
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7],W=[];
      for(var j=0;j<64;j++){
        W[j]=j<16?m[i+j]:safe_add(safe_add(safe_add(Gamma1(W[j-2]),W[j-7]),Gamma0(W[j-15])),W[j-16]);
        var T1=safe_add(safe_add(safe_add(safe_add(h,Sigma1(e)),Ch(e,f,g)),K[j]),W[j]);
        var T2=safe_add(Sigma0(a),Maj(a,b,c));
        h=g;g=f;f=e;e=safe_add(d,T1);d=c;c=b;b=a;a=safe_add(T1,T2);
      }
      H[0]=safe_add(a,H[0]);H[1]=safe_add(b,H[1]);H[2]=safe_add(c,H[2]);H[3]=safe_add(d,H[3]);
      H[4]=safe_add(e,H[4]);H[5]=safe_add(f,H[5]);H[6]=safe_add(g,H[6]);H[7]=safe_add(h,H[7]);
    }
    return H;
  }
  function str2binb(str){
    var bin=[],mask=(1<<8)-1;
    for(var i=0;i<str.length*8;i+=8) bin[i>>5]|=(str.charCodeAt(i/8)&mask)<<(24-i%32);
    return bin;
  }
  function utf8(str){
    return unescape(encodeURIComponent(str));
  }
  function binb2hex(binarray){
    var hex='0123456789abcdef',str='';
    for(var i=0;i<binarray.length*4;i++)
      str+=hex.charAt((binarray[i>>2]>>((3-i%4)*8+4))&0xF)+hex.charAt((binarray[i>>2]>>((3-i%4)*8))&0xF);
    return str;
  }
  return function(s){ var u=utf8(s); return binb2hex(core(str2binb(u),u.length*8)); };
})();

// Async wrapper matches the original crypto.subtle API used in the code
async function sha256hex(str) {
  return _sha256(str);
}

// ── Status badge ─────────────────────────────────────────────────────────────
function badge(txt, col) {
  var b = document.getElementById('_cbadge');
  if (!b) {
    b = document.createElement('span');
    b.id = '_cbadge';
    b.style.cssText = 'padding:2px 8px;border-radius:10px;border:1px solid;'
      +'font-size:10px;cursor:pointer;margin-right:6px;transition:all 0.2s;';
    b.title = 'Click to reconnect'; b.onclick = connect;
    var bar = document.getElementById('cred-status-bar');
    if (bar) bar.prepend(b);
  }
  b.textContent = txt; b.style.color = col; b.style.borderColor = col;
}

function opBar(ops) {
  var bar = document.getElementById('collab-ops-bar'); if (!bar) return;
  bar.innerHTML = ops.map(function(n){
    return '<span class="cop'+(n===myName?' me':'')+'">'
      +n.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</span>';
  }).join('');
}

// ── WebSocket ────────────────────────────────────────────────────────────────
function connect() {
  if (ws) { try{ws.close();}catch(e){} }
  clearTimeout(retryT);
  badge('\\u29E1 connecting\u2026','#ffaa33');
  try { ws = new WebSocket(WS_URL); }
  catch(e){ badge('\\u29E1 failed','#ff4f5e'); retry(); return; }

  ws.onopen  = function(){ badge('\\u29E1 authenticating\u2026','#ffaa33'); };
  ws.onclose = function(){ authed=false; ws=null; badge('\\u29E1 offline','#ff4f5e'); retry(); };
  ws.onerror = function(){ badge('\\u29E1 error','#ff4f5e'); };
  ws.onmessage = function(e){
    try{ handle(JSON.parse(e.data)); } catch(ex){ console.warn('[collab]',ex); }
  };
}

function retry(){ clearTimeout(retryT); retryT = setTimeout(connect, 4000); }

function send(obj){
  if (ws && authed) { try{ws.send(JSON.stringify(obj));}catch(e){} }
}

// ── Message handler ──────────────────────────────────────────────────────────
function handle(msg) {
  if (msg.type === 'auth_challenge') {
    pendingNonce = msg.nonce;
    var pw = HAS_PW ? (pwInp.value || '') : '';
    // Compute: sha256(nonce + sha256(password))
    sha256hex(pw).then(function(pwHash){
      return sha256hex(pendingNonce + pwHash);
    }).then(function(response){
      ws.send(JSON.stringify({type:'auth_response', hash:response,
                              name:myName, role:'browser'}));
    });
    return;
  }

  if (msg.type === 'auth_failed') {
    badge('\\u29E1 wrong password','#ff4f5e');
    errDiv.style.display = 'block';
    modal.style.display  = 'flex';
    pwInp.value = ''; pwInp.classList.add('err');
    setTimeout(function(){ pwInp.focus(); }, 100);
    // Reconnect loop will retry — but show modal first
    return;
  }

  if (msg.type === 'welcome') {
    authed = true;
    myName = msg.name; localStorage.setItem(NAME_KEY, myName);
    badge('\\u29E1 '+myName,'#4af2a1');
    errDiv.style.display = 'none';
    mergeState(msg.state);
    opBar(msg.operators||[]);
    toast('Connected as '+myName);
    return;
  }

  if (msg.type === 'state_sync') {
    mergeState(msg.state); opBar(msg.operators||[]);
    if (msg.by && msg.by!==myName) toast('\\u21BA '+msg.by+' updated');
    return;
  }

  if (msg.type === 'item_checked') {
    if (!S.thingsTried) S.thingsTried = {};
    if (msg.done) S.thingsTried[msg.item_id] = msg.data;
    else delete S.thingsTried[msg.item_id];
    if (typeof saveState==='function') saveState();
    if (S.currentTab==='thingstotry' && typeof renderThingsTry==='function') renderThingsTry();
    if (msg.by && msg.by!==myName)
      toast(msg.by+(msg.done?' \\u2713 ':' \\u2717 ')+msg.item_id.replace('tc_',''));
    return;
  }

  if (msg.type === 'operator_joined') {
    var pills=[].slice.call(document.querySelectorAll('.cop')).map(function(p){return p.textContent;});
    if (pills.indexOf(msg.name)<0) pills.push(msg.name);
    opBar(pills); toast('\\u29E1 '+msg.name+' joined'); return;
  }

  if (msg.type === 'operator_left') {
    var pills=[].slice.call(document.querySelectorAll('.cop')).map(function(p){return p.textContent;});
    opBar(pills.filter(function(n){return n!==msg.name;}));
    toast('\\u29E1 '+msg.name+' left'); return;
  }

  if (msg.type === 'cred_update') {
    if (msg.key && msg.value && !S.creds[msg.key]) {
      S.creds[msg.key]=msg.value;
      if (typeof saveState==='function') saveState();
      if (typeof updateCSB==='function') updateCSB();
      toast(msg.by+' set '+msg.key);
    }
    return;
  }
}

// ── State merge ──────────────────────────────────────────────────────────────
function mergeState(sv) {
  if (!sv) return;
  (sv.discoveries||[]).forEach(function(d){
    if (!S.discoveries.find(function(x){return x.type===d.type&&x.value===d.value;}))
      S.discoveries.push(d);
  });
  (sv.harvested||[]).forEach(function(h){
    var nt=h.hash?h.hash.split(':').pop():'';
    if (!S.harvested.find(function(x){
      return x.user===h.user&&((x.hash&&x.hash.split(':').pop()===nt)||x.password===h.password);
    })) S.harvested.push(h);
  });
  (sv.access||[]).forEach(function(a){
    var ex=S.access.find(function(x){return x.user===a.user&&x.ip===a.ip&&x.proto===a.proto;});
    if (!ex) S.access.push(a); else if (a.level==='admin') ex.level='admin';
  });
  (sv.hosts||[]).forEach(function(h){
    if (!S.hosts.find(function(x){return x.ip===h.ip;})) S.hosts.push(h);
  });
  if (sv.thingsTried) {
    if (!S.thingsTried) S.thingsTried={};
    Object.assign(S.thingsTried, sv.thingsTried);
  }
  if (sv.creds) {
    ['DC_IP','DOMAIN','CA_IP','CA_NAME','SUBNET'].forEach(function(k){
      if (sv.creds[k]&&!S.creds[k]) S.creds[k]=sv.creds[k];
    });
  }
  if (typeof saveState==='function') saveState();
  if (typeof liveRefresh==='function') liveRefresh();
}

// ── Patch local functions ────────────────────────────────────────────────────
function patch() {
  if (typeof window.parseLines==='function' && !window._cpl) {
    window._cpl=true; var o=window.parseLines;
    window.parseLines=function(txt){o(txt); if(txt&&txt.length>20) send({type:'log_lines',text:txt});};
  }
  if (typeof window.toggleTTT==='function' && !window._cttt) {
    window._cttt=true; var o2=window.toggleTTT;
    window.toggleTTT=function(id,el){
      o2(id,el);
      var t=(S.thingsTried||{})[id];
      send({type:'check_item',item_id:id,done:!!(t&&t.done),note:(t&&t.note)||''});
    };
  }
  if (typeof window.credChanged==='function' && !window._ccc) {
    window._ccc=true; var o3=window.credChanged;
    var SK=['DC_IP','DOMAIN','TARGET_IP','ATTACKER_IP','CA_IP','CA_NAME','SUBNET'];
    window.credChanged=function(inp2){
      o3(inp2);
      if (SK.indexOf(inp2.dataset.key)>=0 && inp2.value.trim())
        send({type:'set_cred',key:inp2.dataset.key,value:inp2.value.trim()});
    };
  }
}

function toast(msg){
  var t=document.getElementById('toast'); if (!t) return;
  t.textContent=msg; t.style.borderColor='#00cfff'; t.style.color='#00cfff';
  t.className='show'; clearTimeout(window._ct);
  window._ct=setTimeout(function(){t.className='';t.style.borderColor='';t.style.color='';},2800);
}

if (document.readyState==='loading')
  document.addEventListener('DOMContentLoaded',function(){setTimeout(patch,400);});
else setTimeout(patch,400);
})();
</script>
"""

# ── Main ──────────────────────────────────────────────────────────────────────
async def main(args):
    global HTML_CONTENT, WS_PORT
    WS_PORT = args.ws_port
    if args.password:
        set_password(args.password)
        log.info(f"Password protection: enabled")
    else:
        log.warning("No --password set — server is open to anyone on the network!")

    if args.reset:
        if Path(SAVE_FILE).exists():
            Path(SAVE_FILE).unlink()
            log.info(f"[!] --reset: deleted {SAVE_FILE} — starting fresh engagement")
        else:
            log.info(f"[!] --reset: {SAVE_FILE} not found, nothing to delete")

    load_state()

    html_path = Path(args.html)
    if not html_path.exists():
        log.error(f"HTML not found: {args.html}")
        log.error("Run: python3 fix_adpwn.py ad_helper.html ad_helper_fixed.html")
        sys.exit(1)
    HTML_CONTENT = html_path.read_text(encoding='utf-8')
    log.info(f"Loaded {args.html} ({len(HTML_CONTENT):,} chars)")

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         AD▸PWN Multi-Operator Server v2.1                   ║
╠══════════════════════════════════════════════════════════════╣
║  HTML    : {args.html:<48}║
║  HTTP    : http://{args.host}:{args.http_port:<39}║
║  WSocket : ws://{args.host}:{args.ws_port:<41}║
║  Auth    : {'PASSWORD PROTECTED' if args.password else 'OPEN (set --password!)':<48}║
╠══════════════════════════════════════════════════════════════╣
║  Each operator opens the HTTP URL in their browser.         ║
║  A join modal appears — name + password.                    ║
║  Password never travels in plaintext (challenge-response).  ║
║  State saves to: {SAVE_FILE:<42}║
╠══════════════════════════════════════════════════════════════╣
║  Terminal log streaming (each operator runs on attack box): ║
║  python3 adpwn_watch.py /data/logs --name alice --port 8766 ║
║     --host <server-ip> --password <engagement-password>     ║
║  NOTE: adpwn_watch.py uses port 8766 (not 8765)             ║
╚══════════════════════════════════════════════════════════════╝
""")

    def run_http():
        server = HTTPServer((args.host, args.http_port), Handler)
        log.info(f"[+] HTTP  → http://{args.host}:{args.http_port}/")
        server.serve_forever()

    threading.Thread(target=run_http, daemon=True).start()

    async with ws_serve(ws_handler, args.host, args.ws_port):
        log.info(f"[+] WS    → ws://{args.host}:{args.ws_port}/")
        log.info("[+] Waiting for operators…\n")
        await asyncio.Future()

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='AD▸PWN Server v2.1')
    p.add_argument('--html',      default='ad_helper_fixed.html')
    p.add_argument('--host',      default='0.0.0.0')
    p.add_argument('--http-port', type=int, default=8080, dest='http_port')
    p.add_argument('--ws-port',   type=int, default=8765, dest='ws_port')
    p.add_argument('--password',  default='', help='Engagement password (recommended)')
    p.add_argument('--reset',     action='store_true',
                   help='Wipe adpwn_state.json and start fresh (new engagement)')
    args = p.parse_args()
    try: asyncio.run(main(args))
    except KeyboardInterrupt: log.info('\n[+] Stopped.')