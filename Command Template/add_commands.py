#!/usr/bin/env python3
"""
add_commands.py — Add custom attack commands to AD▸PWN Helper v3

Reads a YAML or JSON file of custom commands and injects them into the
ATTACKS object in the HTML. Existing attacks are preserved; new ones are added.
Custom attacks appear in whichever tab you specify.

Usage:
    python3 add_commands.py commands.yaml ad_helper_fixed.html
    python3 add_commands.py commands.json ad_helper_fixed.html --output custom_fixed.html

YAML format:
-----------
- id: nxc_mssql_enum           # unique key (no spaces)
  tab: Enumeration              # tab: Enumeration | Credential Attacks | Lateral Movement |
                                #       Privilege Escalation | ADCS | Domain Dominance | Custom
  name: NXC MSSQL Enumeration  # display name
  desc: Enumerate MSSQL instances and databases via NetExec.
  requires_priv: null           # null | local_admin | da
  requires: [DC_IP, USERNAME, PASSWORD]  # cred fields needed
  tags: [mssql, enum, nxc]
  commands:
    - label: MSSQL Scan
      cmd: "nxc mssql {SUBNET} -u {USERNAME} -p '{PASSWORD}'"
    - label: MSSQL Enum DBs
      cmd: "nxc mssql {DC_IP} -u {USERNAME} -p '{PASSWORD}' -q 'SELECT name FROM sys.databases'"
    - label: MSSQL xp_cmdshell
      cmd: "nxc mssql {TARGET_IP} -u {USERNAME} -p '{PASSWORD}' -x 'whoami' --no-output"
  next:
    - Check for SA account or sysadmin role
    - Try xp_cmdshell for RCE
    - Enumerate linked servers
  opsec: MSSQL queries are logged. xp_cmdshell execution is very loud.
  cleanup:
    - label: Disable xp_cmdshell
      cmd: "nxc mssql {TARGET_IP} -u {USERNAME} -p '{PASSWORD}' -q \"EXEC sp_configure 'xp_cmdshell',0\""

- id: custom_kerb_spray
  tab: Credential Attacks
  ...

JSON format:
-----------
Same structure as YAML but as a JSON array.

Available cred field placeholders:
    {DC_IP} {DOMAIN} {SUBNET} {TARGET_IP} {ATTACKER_IP}
    {USERNAME} {PASSWORD} {NTLM_HASH} {TICKET_PATH}
    {KRBTGT_HASH} {SERVICE_HASH} {DOMAIN_SID}
    {CA_NAME} {CA_IP} {TEMPLATE}
    {TARGET_USER} {TARGET_COMPUTER} {TARGET_SPN}
"""

import sys, json, re, argparse
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

VALID_TABS = {
    'Enumeration', 'Credential Attacks', 'Lateral Movement',
    'Privilege Escalation', 'ADCS', 'Domain Dominance', 'Custom'
}

VALID_PRIVS = {None, 'null', 'local_admin', 'da', 'da_or_target_admin'}


def load_commands(path: str) -> list:
    """Load commands from YAML or JSON file."""
    p = Path(path)
    if not p.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    text = p.read_text(encoding='utf-8')

    if p.suffix.lower() in ('.yaml', '.yml'):
        if not HAS_YAML:
            print("[!] pip install pyyaml  (needed for YAML input)", file=sys.stderr)
            sys.exit(1)
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    if not isinstance(data, list):
        data = [data]
    return data


def validate(entry: dict) -> list:
    """Return list of error strings, empty = valid."""
    errors = []
    if not entry.get('id') or not re.match(r'^[a-z0-9_]+$', entry['id']):
        errors.append(f"  'id' must be lowercase alphanumeric/underscore, got: {entry.get('id')!r}")
    if entry.get('tab') not in VALID_TABS:
        errors.append(f"  'tab' must be one of {sorted(VALID_TABS)}, got: {entry.get('tab')!r}")
    if not entry.get('name'):
        errors.append("  'name' is required")
    if not (entry.get('commands') or []) or not isinstance(entry.get('commands') or [], list):
        errors.append("  'commands' must be a non-empty list")
    else:
        for i, cmd in enumerate(entry['commands']):
            if not cmd.get('label'):
                errors.append(f"  commands[{i}] missing 'label'")
            if not cmd.get('cmd') and not cmd.get('command'):
                errors.append(f"  commands[{i}] missing 'cmd'")
    priv = entry.get('requires_priv')
    priv_str = str(priv) if priv is not None else 'null'
    if priv_str not in {str(v) for v in VALID_PRIVS}:
        errors.append(f"  'requires_priv' must be null/local_admin/da, got: {priv!r}")
    return errors


def entry_to_js(entry: dict) -> str:
    """Convert a command entry dict to its JavaScript object literal."""
    eid        = entry['id']
    tab        = entry['tab']
    name       = entry.get('name', eid.replace('_', ' ').title())
    desc       = entry.get('desc', '')
    req_priv   = entry.get('requires_priv') or entry.get('requires_priv') == 'null'
    req_priv   = None if req_priv in (None, 'null', '') else req_priv
    requires   = entry.get('requires') or []
    tags       = entry.get('tags') or []
    commands   = entry.get('commands') or []
    next_steps = entry.get('next') or []
    opsec      = entry.get('opsec') or ''
    cleanup    = entry.get('cleanup') or []

    def js_str(s):
        return json.dumps(str(s))

    def js_arr(lst):
        return '[' + ','.join(js_str(i) for i in lst) + ']'

    cmds_js = '[' + ','.join(
        '[{},{}'.format(
            js_str(c.get('label', f'Command {i+1}')),
            ',' + js_str(c.get('cmd') or c.get('command','')) + ']'
        )
        for i, c in enumerate(commands)
    ) + ']'

    cleanup_js = '[' + ','.join(
        '[{},{}]'.format(
            js_str(c.get('label', 'Cleanup')),
            js_str(c.get('cmd') or c.get('command',''))
        )
        for c in (cleanup or [])
    ) + ']'

    priv_js = 'null' if not req_priv else js_str(req_priv)

    parts = [
        f'tab:{js_str(tab)}',
        f'requires:{js_arr(requires)}',
        f'requires_priv:{priv_js}',
        f'tags:{js_arr(tags)}',
        f'desc:{js_str(desc)}',
        f'commands:{cmds_js}',
        f'next:{js_arr(next_steps)}',
        f'opsec:{js_str(opsec)}',
        f'cleanup:{cleanup_js}',
    ]

    return f'  {eid}:{{{",".join(parts)}}}'


def inject(html: str, entries: list) -> tuple:
    """Inject entries into the ATTACKS object in the HTML (single-pass, string-aware)."""
    import re as _re
    report = []

    atk_start = html.find('const ATTACKS = {')
    if atk_start == -1:
        return html, ['[!] Could not find ATTACKS object in HTML']

    # String-aware depth scan to find the real closing brace
    depth  = 0
    in_str = False
    esc    = False
    atk_end = atk_start
    for i, ch in enumerate(html[atk_start:], atk_start):
        if esc:
            esc = False; continue
        if in_str:
            if ch == '\\': esc = True
            elif ch == '"':  in_str = False
            continue
        if ch == '"':  in_str = True; continue
        if ch == '{':  depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0: atk_end = i; break

    atk_block = html[atk_start:atk_end + 1]

    new_entries_js = []
    added   = []
    skipped = []

    for entry in entries:
        eid = entry.get('id', '')
        if not eid:
            skipped.append(('?', 'missing id')); continue
        if _re.search(r'\b' + _re.escape(eid) + r'\s*:', atk_block):
            skipped.append((eid, 'already exists — skipped')); continue
        new_entries_js.append(entry_to_js(entry))
        added.append(eid)

    if new_entries_js:
        # Single insertion: strip closing } and add all new entries at once
        base = atk_block[:-1].rstrip()  # removes the final }
        base = base.rstrip(',')          # remove any trailing comma from last entry
        sep  = '' if base.rstrip().endswith('{') else ','
        new_atk_block = base + sep + '\n' + ',\n'.join(new_entries_js) + '\n}'
        html = html[:atk_start] + new_atk_block + html[atk_end + 1:]

    for eid in added:
        tab = next(e['tab'] for e in entries if e.get('id') == eid)
        report.append(f"  ✓ Added: {eid} → {tab}")
    for eid, reason in skipped:
        report.append(f"  - Skipped {eid}: {reason}")

    # Custom tab support
    custom_entries = [e for e in entries if e.get('tab') == 'Custom' and e.get('id') in added]
    if custom_entries:
        old_tabs = "const ATK_TABS = ['Enumeration','Credential Attacks','Lateral Movement','Privilege Escalation','ADCS','Domain Dominance'];"
        new_tabs = "const ATK_TABS = ['Enumeration','Credential Attacks','Lateral Movement','Privilege Escalation','ADCS','Domain Dominance','Custom'];"
        if old_tabs in html:
            html = html.replace(old_tabs, new_tabs, 1)
            old_dom_btn = '<button class="top-tab atk-tab" data-tab="Domain Dominance" onclick="switchTab(\'Domain Dominance\',this)">Dominance</button>'
            new_dom_btn = (old_dom_btn +
                '\n  <button class="top-tab atk-tab" data-tab="Custom" onclick="switchTab(\'Custom\',this)">Custom</button>')
            if old_dom_btn in html:
                html = html.replace(old_dom_btn, new_dom_btn, 1)
                report.append("  ✓ Added 'Custom' tab to topbar")

    return html, report



def write_template(path: str):
    """Write a YAML template file the user can fill in."""
    template = """\
# AD▸PWN Custom Commands Template
# Run: python3 add_commands.py this_file.yaml ad_helper_fixed.html

- id: example_nxc_module          # unique key, lowercase, underscores only
  tab: Enumeration                 # Enumeration | Credential Attacks | Lateral Movement |
                                   # Privilege Escalation | ADCS | Domain Dominance | Custom
  name: Example NXC Module
  desc: Brief description of what this attack does.
  requires_priv: null              # null | local_admin | da
  requires:                        # which cred fields are needed
    - DC_IP
    - USERNAME
    - PASSWORD
  tags:
    - nxc
    - enum
  commands:
    - label: Run module
      cmd: "nxc smb {DC_IP} -u {USERNAME} -p '{PASSWORD}' -M example_module"
    - label: With options
      cmd: "nxc smb {DC_IP} -u {USERNAME} -p '{PASSWORD}' -M example_module -o OPTION=value"
  next:
    - Review module output for interesting findings
    - Follow up with targeted enumeration
  opsec: Describe any detection/noise considerations here.
  cleanup:
    - label: Remove artifacts
      cmd: "del /f C:\\\\Windows\\\\Temp\\\\artifact"

- id: gitlab_custom_tool
  tab: Custom
  name: Custom GitLab Tool
  desc: Our internal tool from GitLab for X.
  requires_priv: local_admin
  requires:
    - TARGET_IP
    - USERNAME
    - PASSWORD
  tags:
    - custom
    - internal
  commands:
    - label: Run internal tool
      cmd: "python3 /opt/tools/internal_tool.py -t {TARGET_IP} -u {USERNAME} -p '{PASSWORD}'"
  next:
    - Review output
  opsec: Internal tool — verify before use on production systems.
  cleanup: []
"""
    Path(path).write_text(template)
    print(f"Template written to: {path}")


if __name__ == '__main__':
    p = argparse.ArgumentParser(
        description='Add custom attack commands to AD▸PWN Helper v3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    p.add_argument('commands',    nargs='?', help='YAML or JSON commands file')
    p.add_argument('html',        nargs='?', help='ad_helper_fixed.html to patch')
    p.add_argument('--output',    default='', help='Output file (default: overwrite input)')
    p.add_argument('--template',  metavar='FILE', help='Write a YAML template and exit')
    p.add_argument('--validate',  action='store_true', help='Validate commands file only')
    args = p.parse_args()

    if args.template:
        write_template(args.template)
        sys.exit(0)

    if not args.commands or not args.html:
        p.print_help()
        sys.exit(1)

    # Load
    entries = load_commands(args.commands)
    print(f"Loaded {len(entries)} command set(s) from {args.commands}")

    # Validate
    all_valid = True
    for entry in entries:
        errors = validate(entry)
        if errors:
            print(f"\n[!] Validation errors in entry {entry.get('id', '?')}:")
            for e in errors:
                print(e)
            all_valid = False

    if not all_valid:
        print("\n[!] Fix validation errors before injecting.")
        sys.exit(1)

    if args.validate:
        print("✓ All entries valid")
        sys.exit(0)

    # Load HTML
    html_path = Path(args.html)
    if not html_path.exists():
        print(f"[!] HTML not found: {args.html}", file=sys.stderr)
        sys.exit(1)

    html = html_path.read_text(encoding='utf-8')
    print(f"Loaded {args.html} ({len(html):,} chars)")

    # Inject
    fixed, report = inject(html, entries)
    print("\nInjection results:")
    for line in report:
        print(line)

    # Write
    out_path = args.output or args.html
    Path(out_path).write_text(fixed, encoding='utf-8')
    print(f"\nOutput: {out_path} ({len(fixed):,} chars)")