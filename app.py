# Splunk UF Deployer - run: pip install -r requirements.txt ; python app.py [port] [--no-browser] ; open http://localhost:5000
import fnmatch, ipaddress, re, shlex, subprocess, socket, sqlite3, csv, io, html, json, time, uuid, os, sys, threading, webbrowser
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from urllib.parse import quote as urlq, urlsplit, urlunsplit
from flask import Flask, request, jsonify, send_from_directory, abort
import winrm, paramiko

FROZEN = getattr(sys, "frozen", False)
HERE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))   # bundled files (index.html)
ROOT = os.path.dirname(sys.executable) if FROZEN else HERE                    # data/ must not live in the exe's temp dir
app = Flask(__name__)
DATA = os.path.join(ROOT, "data"); os.makedirs(DATA, exist_ok=True)
POOL = ThreadPoolExecutor(20); JOBS = {}; LOCK = threading.Lock(); MAX_HOSTS = 4096
DB = os.path.join(DATA, "history.db"); TPL = os.path.join(DATA, "templates.json")
dbc = lambda: closing(sqlite3.connect(DB, timeout=30))
with dbc() as _d, _d: _d.execute("create table if not exists h(ts text,client text,os text,host text,task text,status text,output text)")
BRAND = os.path.join(DATA, "branding.json"); GRP = os.path.join(DATA, "groups.json")
EXCL = {"history.db", "templates.json", "branding.json", "groups.json"}
visible = lambda n: n not in EXCL and not n.startswith(("logo.", ".")) and not n.endswith(".tmp")
WUF = r"C:\Program Files\SplunkUniversalForwarder"; LUF = "/opt/splunkforwarder"
WLOCAL = WUF + r"\etc\system\local"; WAPPS = WUF + r"\etc\apps"
FAIL = re.compile(r"^(ERROR|CANCELLED)", re.M)
OPS = ("status", "start", "stop", "restart")

def jload(p):
    try:
        with open(p, encoding="utf-8") as fh: return json.load(fh)
    except (OSError, ValueError): return {}
def jsave(p, o):
    with open(p + ".tmp", "w", encoding="utf-8") as fh: json.dump(o, fh)
    os.replace(p + ".tmp", p); return o

# ---------- target parsing ----------
# Line formats:  host | CIDR | a.b.c.1-a.b.c.20 | host,user,password | host @profile | win:host... | lin:host...
def expand(spec):
    spec = spec.strip()
    try:
        if "/" in spec:
            n = ipaddress.ip_network(spec, strict=False)
            if n.num_addresses > MAX_HOSTS: raise OverflowError
            return [str(h) for h in n.hosts()]
        if "-" in spec and spec.count(".") >= 6:
            a, b = sorted(int(ipaddress.ip_address(x.strip())) for x in spec.split("-", 1))
            if b - a >= MAX_HOSTS: raise OverflowError
            return [str(ipaddress.ip_address(i)) for i in range(a, b + 1)]
    except ValueError: pass
    except OverflowError: raise Exception(f"{spec}: too many addresses (max {MAX_HOSTS} per run)")
    return [spec]

def parse_targets(text, user, pw, default_os, profiles):
    prof = {}
    for l in profiles.splitlines():
        p = l.split(",", 2)
        if len(p) == 3: prof[p[0].strip()] = (p[1].strip(), p[2])
    out, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        o, u, w = default_os, user, pw
        m = re.match(r"(win|lin)\w*:(.*)", line, re.I)
        if m: o = "windows" if m[1].lower() == "win" else "linux"; line = m[2].strip()
        if " @" in line:
            line, pn = line.rsplit(" @", 1)
            if pn.strip() not in prof: raise Exception(f"Unknown credential profile: @{pn.strip()}")
            u, w = prof[pn.strip()]
        elif line.count(",") >= 2:
            line, u, w = line.split(",", 2); line, u = line.strip(), u.strip()
        for h in expand(line):
            if h and h not in seen: seen.add(h); out.append((h, u, w, o))  # duplicates would make the job never finish
        if len(out) > MAX_HOSTS: raise Exception(f"Too many targets (max {MAX_HOSTS} per run)")
    return out

def tool_url(base, host):
    """Base URL a Windows target downloads library files from. A loopback address (UI opened as localhost)
    is useless to the target, so it is replaced by this machine's IP on the route towards that target."""
    base = (base or "").strip().rstrip("/")
    if "://" not in base: base = "http://" + base
    p = urlsplit(base); hn = p.hostname or ""
    if hn in ("localhost", "::1") or hn.startswith("127."):
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s: s.connect((host, 9)); ip = s.getsockname()[0]
            p = p._replace(netloc=ip + (f":{p.port}" if p.port else ""))
        except OSError: pass
    return urlunsplit(p) + "/files/"

# ---------- Windows: WinRM first, SMB + scheduled task as fallback ----------
def smb_ps(host, u, pw, script):
    if os.name != "nt": raise Exception("SMB fallback needs the tool to run on Windows")
    unc = f"\\\\{host}\\C$"; tid = uuid.uuid4().hex[:8]; tn = "ufd_" + tid
    loc = f"C:\\Windows\\Temp\\{tn}"; rem = f"{unc}\\Windows\\Temp\\{tn}"
    run = lambda c: subprocess.run(c, capture_output=True, text=True, timeout=120)
    r = run(["net", "use", unc, pw, f"/user:{u}"])
    if r.returncode: raise Exception("SMB connect failed: " + (r.stderr or r.stdout).strip()[:200])
    try:
        with open(rem + ".ps1", "w", encoding="utf-8-sig") as fh: fh.write(script)
        tr = f'cmd /c powershell -NoProfile -ExecutionPolicy Bypass -File {loc}.ps1 > {loc}.out 2>&1 & echo x > {loc}.done'
        r = run(["schtasks", "/create", "/s", host, "/u", u, "/p", pw, "/tn", tn, "/tr", tr, "/sc", "once", "/st", "00:00", "/ru", "SYSTEM", "/f"])
        if r.returncode: raise Exception("schtasks create failed: " + (r.stderr or r.stdout).strip()[:200])
        r = run(["schtasks", "/run", "/s", host, "/u", u, "/p", pw, "/tn", tn])
        if r.returncode: raise Exception("schtasks run failed: " + (r.stderr or r.stdout).strip()[:200])
        for _ in range(450):
            if os.path.exists(rem + ".done"): break
            time.sleep(2)
        else: return "ERROR: timed out waiting for remote script"
        with open(rem + ".out", encoding="utf-8", errors="ignore") as fh: return fh.read().strip()
    finally:
        run(["schtasks", "/delete", "/s", host, "/u", u, "/p", pw, "/tn", tn, "/f"])
        for e in (".ps1", ".out", ".done"):
            try: os.remove(rem + e)
            except OSError: pass
        run(["net", "use", unc, "/delete", "/y"])

def clean(r): return re.sub(r"<Objs.*?</Objs>", "", re.sub(r"#< CLIXML", "", r), flags=re.S).strip()
def psq(s): return "'" + str(s).replace("'", "''") + "'"   # PowerShell literal string

def lockfix(kill):
    n = '"apt|apt-get|dpkg|unattended-upgr|yum|dnf|rpm|zypper|packagekitd"'
    s = f'for i in $(seq 1 15); do pgrep -x {n} >/dev/null || break; sleep 2; done; '
    if kill: s += (f'if pgrep -x {n} >/dev/null; then echo "Package manager busy - killing holders"; pkill -9 -x {n}; sleep 2; '
                   'rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/run/yum.pid; command -v dpkg >/dev/null && dpkg --configure -a; fi; ')
    return s

def win(host, u, pw, a):
    base = tool_url(a.get("base"), host); method = a.get("method", "auto"); note = []
    url = lambda n: psq(base + urlq(n))
    def ps(c):
        # Stop on the first cmdlet error and report it as one ERROR line instead of a red CLIXML dump
        c = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';try{" + c + "}catch{'ERROR: '+$_.Exception.Message}"
        return clean(ps0(c))
    def ps0(c):
        if method in ("auto", "winrm"):
            try:
                s = winrm.Session(host, auth=(u, pw), transport="ntlm", read_timeout_sec=900, operation_timeout_sec=800)
                r = s.run_ps(c); return (r.std_out + r.std_err).decode(errors="ignore").strip()
            except Exception as e:
                if method == "winrm" or not re.search(r"refused|timed out|Max retries|Connection|unreachable", str(e), re.I): raise
                note.append("(WinRM unavailable -> used SMB + scheduled task)")
        return smb_ps(host, u, pw, c)
    act, f, f2 = a["action"], a.get("file", ""), a.get("file2", "")
    need_uf = f'if(!(Test-Path {psq(WUF)})){{"ERROR: Splunk UF is not installed";return}};'
    if act == "check":
        r = ps('$u=Get-Service SplunkForwarder -EA 0;$s=Get-Service Sysmon64,Sysmon -EA 0|select -f 1;'
               '"Splunk UF: "+$(if($u){$u.Status}else{"NOT INSTALLED"});"Sysmon: "+$(if($s){$s.Name+" "+$s.Status}else{"NOT INSTALLED"})')
    elif act == "install_uf":
        msi = ' AGREETOLICENSE=Yes SPLUNKUSERNAME=admin SPLUNKPASSWORD="' + a["apass"].replace('"', '""') + '" LAUNCHSPLUNK=1 /quiet /norestart'
        if a.get("idx"): msi += f' RECEIVING_INDEXER="{a["idx"]}"'
        conf = (f';$c=Join-Path {psq(WLOCAL)} {psq(f2)};Invoke-WebRequest {url(f2)} -OutFile $c -UseBasicParsing;'
                f'Restart-Service SplunkForwarder -Force;"Initial conf applied: "+$c') if f2 else ""
        r = ps('if(Get-Service SplunkForwarder -EA 0){"UF already installed - skipped";return}'
               f'$m="$env:TEMP\\ufd_uf.msi";Invoke-WebRequest {url(f)} -OutFile $m -UseBasicParsing;'
               f'$p=Start-Process msiexec -Wait -PassThru -ArgumentList (\'/i "\'+$m+\'"\'+{psq(msi)});Remove-Item $m -EA 0;'
               'if($p.ExitCode -notin 0,3010){"ERROR: msiexec exit code "+$p.ExitCode+" (1603 = install failed, 1618 = another install is running)";return}'
               '"msiexec exit code: "+$p.ExitCode' + conf)
    elif act == "sysmon":
        inst = (f'else{{Invoke-WebRequest {url(f2)} -OutFile "$d\\sysmon.exe" -UseBasicParsing;$x="$d\\sysmon.exe";$g="-accepteula","-i";$t="INSTALLED"}}' if f2
                else 'else{"ERROR: Sysmon is not installed and no Sysmon.exe was selected";return}')
        r = ps(f'$d="$env:TEMP\\ufd_sm";mkdir $d -Force|Out-Null;Invoke-WebRequest {url(f)} -OutFile "$d\\cfg.xml" -UseBasicParsing;'
               '$sv=Get-Service Sysmon64,Sysmon -EA 0|select -f 1;'
               'if($sv){$x=if($sv.Name -eq "Sysmon64"){"$env:windir\\Sysmon64.exe"}else{"$env:windir\\Sysmon.exe"};$g=,"-c";$t="config UPDATED"}' + inst +
               ';$ErrorActionPreference="Continue";$o=& $x @g "$d\\cfg.xml" 2>&1|Out-String;$e=$LASTEXITCODE;Remove-Item $d -Recurse -Force -EA 0;'
               '$o.Trim();if($e){"ERROR: sysmon exit code "+$e}else{"Sysmon "+$t}')
    elif act == "push_conf":
        r = ps(need_uf + f'mkdir {psq(WLOCAL)} -Force|Out-Null;$o=Join-Path {psq(WLOCAL)} {psq(f)};Invoke-WebRequest {url(f)} -OutFile $o -UseBasicParsing;'
               '"Copied to $o";"Restart the SplunkForwarder service to apply it"')
    elif act == "detect":
        r = ps('$o=Get-CimInstance Win32_OperatingSystem;$c=Get-CimInstance Win32_ComputerSystem;"OS: "+$o.Caption+" build "+$o.BuildNumber+" ("+$o.OSArchitecture+")";'
               '"Host: "+$env:COMPUTERNAME+"  Domain/Workgroup: "+$c.Domain;"PowerShell: "+$PSVersionTable.PSVersion;"Last boot: "+$o.LastBootUpTime')
    elif act == "deploy_app":
        r = ps(need_uf + f'$d={psq(WAPPS)};$z=Join-Path $env:TEMP {psq("ufd_" + f)};Invoke-WebRequest {url(f)} -OutFile $z -UseBasicParsing;'
               'if($z -like "*.zip"){Expand-Archive $z $d -Force}else{$ErrorActionPreference="Continue";$o=tar -xf $z -C $d 2>&1|Out-String;'
               'if($LASTEXITCODE){Remove-Item $z -EA 0;"ERROR: tar exit code "+$LASTEXITCODE+" "+$o.Trim();return}};Remove-Item $z -EA 0;'
               '"Extracted into $d";"Apps: "+((Get-ChildItem $d -Directory).Name -join ", ");"Restart the SplunkForwarder service to load it"')
    elif act == "svc":
        v = {"start": "Start-Service $n", "stop": "Stop-Service $n -Force", "restart": "Restart-Service $n -Force", "status": "$null"}[a["op"]]
        r = ps(f'$n=if({psq(a["svc"])} -eq "sysmon"){{(Get-Service Sysmon64,Sysmon -EA 0|select -f 1).Name}}else{{"SplunkForwarder"}};'
               f'if(!$n -or !(Get-Service $n -EA 0)){{"Service not installed";return}}; {v}; "$n : "+(Get-Service $n).Status')
    else: r = "ERROR: unknown action"
    return "\n".join([r] + note)

# ---------- Linux (SSH, non-root sudo user) ----------
def lin(host, u, pw, a):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    a["_job"]["clients"].append(c)
    c.connect(host, username=u, password=pw, timeout=20, look_for_keys=False, allow_agent=False)
    sudo = "" if u == "root" else "sudo -S -p '' "
    def sh(cmd, t=300):
        # password goes through stdin (not the command line, where `ps` would show it); stderr merged in order
        ch = c.get_transport().open_session(); ch.settimeout(t); ch.set_combine_stderr(True)
        ch.exec_command(sudo + "bash -c " + shlex.quote("exec </dev/null; " + cmd))
        ch.sendall((pw + "\n").encode()); ch.shutdown_write(); b = b""
        while d := ch.recv(65536): b += d
        rc, o = ch.recv_exit_status(), b.decode(errors="ignore").strip(); ch.close()
        if sudo and rc and re.search(r"incorrect password|not in the sudoers|not allowed to execute|password is required|must have a tty", o, re.I):
            raise Exception("sudo failed: " + o[-300:])
        return rc, o
    res = lambda r: r[1] if r[0] == 0 else "ERROR: command failed (exit code %d)\n%s" % r
    def put(name, data=None):
        dst = f"/tmp/ufd_{uuid.uuid4().hex[:8]}_" + re.sub(r"[^\w.-]", "_", name)
        with closing(c.open_sftp()) as sf:
            if data is None: sf.put(os.path.join(DATA, name), dst)
            else:
                with sf.open(dst, "w") as fh: fh.write(data)
        return dst
    act, f = a["action"], a.get("file", ""); S = f"{LUF}/bin/splunk"; q = shlex.quote
    try:
        if act == "check":
            return sh(f'. /etc/os-release; echo "OS: $PRETTY_NAME";'
                      f'if [ -x {S} ]; then echo "Splunk UF: installed ($(grep -h ^VERSION {LUF}/etc/splunk.version 2>/dev/null))";'
                      f'[ -f {LUF}/etc/passwd ] && echo "Initialized: yes (admin user exists)" || echo "Initialized: NO - first start / admin user not done (run Install UF to finish)";'
                      f'echo "Service: $({S} status 2>&1 </dev/null| head -1)"; else echo "Splunk UF: NOT INSTALLED"; fi;'
                      f'if command -v auditctl >/dev/null; then echo "auditd: installed, $(systemctl is-active auditd 2>&1)"; else echo "auditd: NOT INSTALLED"; fi')[1]
        if act == "install_uf":
            p = q(put(f)); fl = f.lower(); LK = lockfix(a.get("kill"))
            i = f"{LK} rpm -U {p}" if fl.endswith(".rpm") else f"{LK} dpkg -i {p}" if fl.endswith(".deb") else f"tar xzf {p} -C /opt"
            cp = q(put(a["file2"])) if a.get("file2") else ""
            conf = f'install -m 644 {cp} {LUF}/etc/system/local/{q(a["file2"])}; rm -f {cp};' if cp else ""
            SD = '$( [ -d /run/systemd/system ] && echo "-systemd-managed 1" )'
            return res(sh(f'if [ -x {S} ]; then echo "UF binaries already present - finishing setup/start"; else {i} || {{ echo "ERROR: package install FAILED"; rm -f {p}; exit 1; }}; fi; rm -f {p};'
                      f'mkdir -p {LUF}/etc/system/local;' + conf +
                      f'[ -f {LUF}/etc/passwd ] || {{ printf "[user_info]\\nUSERNAME = admin\\nPASSWORD = %s\\n" {q(a["apass"])} > {LUF}/etc/system/local/user-seed.conf; echo "admin user seeded"; }};'
                      # first start initializes as root; then hand the tree to the package's service user (splunkfwd) and enable boot-start for it
                      f'OWN=$(stat -c %U {LUF}); id "$OWN" >/dev/null 2>&1 || OWN=root;'
                      f'timeout 240 {S} start --accept-license --answer-yes --no-prompt 2>&1 | tail -5;'
                      f'timeout 120 {S} stop >/dev/null 2>&1; chown -R "$OWN": {LUF};'
                      f'timeout 120 {S} enable boot-start {SD} -user "$OWN" --accept-license --answer-yes --no-prompt 2>&1 | tail -2;'
                      f'timeout 240 {S} start --accept-license --answer-yes --no-prompt 2>&1 | tail -3;'
                      + (f'{S} add forward-server {q(a["idx"])} -auth admin:{q(a["apass"])} 2>&1 | tail -2;' if a.get("idx") else "")
                      + f'echo "Service: $({S} status 2>&1 | head -1)"', 900))
        if act == "auditd":
            rc, o = sh('command -v auditctl >/dev/null && { echo "auditd already installed"; exit 0; }; ' + lockfix(a.get("kill")) +
                      'if command -v apt-get >/dev/null; then echo "[apt]"; DEBIAN_FRONTEND=noninteractive apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins || DEBIAN_FRONTEND=noninteractive apt-get install -y auditd;'
                      'elif command -v dnf >/dev/null; then echo "[dnf]"; dnf install -y audit;elif command -v yum >/dev/null; then echo "[yum]"; yum install -y audit;'
                      'elif command -v zypper >/dev/null; then zypper -n install audit;elif command -v pacman >/dev/null; then pacman -S --noconfirm audit;'
                      'elif command -v apk >/dev/null; then apk add audit; else echo "ERROR: no supported package manager"; exit 1; fi;'
                      'command -v auditctl >/dev/null || { echo "ERROR: auditd install failed"; exit 1; };'
                      '(systemctl enable --now auditd || service auditd start) 2>&1', 900); return res((rc, o[-1500:]))
        if act == "audit_rules":
            with open(os.path.join(DATA, f), encoding="utf-8-sig", errors="ignore") as fh: lines = fh.read().splitlines()
            log = []; total = sum(1 for l in lines if re.match(r"\s*-(a|A|w)\b", l))
            wp = lambda l: (re.match(r"\s*-w\s+(\S+)", l) or [None, None])[1]
            paths = sorted({wp(l) for l in lines if wp(l)})
            if paths:  # 1) drop watch rules whose path does not exist (fast, avoids hundreds of retries)
                _, o = sh('for p in ' + " ".join(map(q, paths)) + '; do [ -e "$p" ] || echo "$p"; done'); miss = set(o.splitlines())
                for l in [l for l in lines if wp(l) in miss]: log.append("Removed (path not on this host): " + l.strip())
                lines = [l for l in lines if wp(l) not in miss]
            for _ in range(300):  # 2) load via augenrules; remove whichever rule the kernel rejects, retry
                p = q(put("splunk.rules", "\n".join(lines) + "\n")); sh(f"mkdir -p /etc/audit/rules.d; install -m 640 {p} /etc/audit/rules.d/splunk.rules; rm -f {p}")
                rc, o = sh("augenrules --load 2>&1 || auditctl -R /etc/audit/rules.d/splunk.rules 2>&1")
                if rc == 0 and not re.search(r"error|faulty", o, re.I): log.append("Rules loaded OK"); break
                m = re.search(r"faulty line \d+ \('(.*?)'\)", o); bad = m[1] if m else None
                if not bad and (m2 := re.search(r"error in line (\d+) of (\S+)", o)):
                    bad = sh(f"sed -n {int(m2[1])}p {q(m2[2])}")[1]
                idx = next((k for k, l in enumerate(lines) if bad and l.strip() == bad.strip()), None)
                if idx is None: log.append("ERROR: stopped - rejected rule is not in your file: " + (bad or o[-300:])); break
                log.append(f"Removed (rejected): {lines[idx].strip()}"); del lines[idx]
            rem = sum(x.startswith("Removed") for x in log); ok = "Rules loaded OK" in log
            return "\n".join(log) + "\nActive rules: " + sh("auditctl -l | grep -vc '^No rules'")[1] + f"\nSUMMARY rules_total={total} applied={total - rem if ok else 0} removed={rem}"
        if act == "push_conf":
            p = q(put(f)); d = f"{LUF}/etc/system/local"
            return res(sh(f'[ -x {S} ] || {{ echo "ERROR: Splunk UF is not installed"; rm -f {p}; exit 1; }}; mkdir -p {d} && install -m 644 {p} {d}/{q(f)} && rm -f {p} && '
                          f'chown $(stat -c %U:%G {LUF}) {d}/{q(f)} && echo "Copied to {d}/{f}" && echo "Restart Splunk to apply it"'))
        if act == "detect":
            return sh('. /etc/os-release; echo "OS: $PRETTY_NAME"; echo "Kernel: $(uname -sr) $(uname -m)"; echo "Hostname: $(hostname)";'
                      'echo "Package manager: $(for m in apt-get dnf yum zypper pacman apk; do command -v $m >/dev/null && echo $m; done | tr "\\n" " ")";'
                      '[ -d /run/systemd/system ] && echo "Init: systemd" || echo "Init: non-systemd"')[1]
        if act == "deploy_app":
            p = q(put(f)); A = f"{LUF}/etc/apps"
            return res(sh(f'[ -x {S} ] || {{ echo "ERROR: Splunk UF is not installed"; rm -f {p}; exit 1; }}; mkdir -p {A}; '
                          f'case {q(f.lower())} in *.zip) unzip -oq {p} -d {A};; *) tar xzf {p} -C {A};; esac; r=$?; rm -f {p}; [ $r -eq 0 ] || exit $r; '
                          f'chown -R $(stat -c %U:%G {LUF}) {A} 2>/dev/null; echo "Extracted into {A}"; echo "Apps: $(ls {A} | tr "\\n" " ")"; echo "Restart Splunk to load it"'))
        if act == "svc":
            op, sv = a["op"], a["svc"]
            if sv == "splunk":
                if op == "status": return sh(f"{S} status 2>&1")[1]
                return res(sh(f"[ -x {S} ] || {{ echo 'Splunk UF: NOT INSTALLED'; exit 0; }}; timeout 240 {S} {op} --accept-license --answer-yes --no-prompt 2>&1 | tail -5"))
            n = "auditd" if sv == "auditd" else "sysmon"
            cmd = (f"systemctl is-active {n}; systemctl status {n} --no-pager 2>&1 | head -6" if op == "status" else
                   f"(service {n} {op} || systemctl {op} {n}) 2>&1; echo \"{n}: $(systemctl is-active {n})\"")
            return sh(cmd)[1]
        return "ERROR: unknown action"
    finally: c.close()

# ---------- Cisco (SSH or Telnet) ----------
try: from telnetlib import Telnet   # removed from the standard library in Python 3.13
except ImportError:
    class Telnet:
        """Minimal telnet client (declines every option) - enough for a Cisco CLI session."""
        def __init__(s, host, port, timeout): s.k = socket.create_connection((host, port), timeout); s.buf = b""
        def _fill(s, wait):  # True = got data, False = nothing yet, None = closed
            s.k.settimeout(wait)
            try: d = s.k.recv(65536)
            except OSError: return False
            if not d: return None
            i = 0
            while i < len(d):
                if d[i] != 255: j = d.find(b"\xff", i); j = len(d) if j < 0 else j; s.buf += d[i:j]; i = j; continue
                cmd = d[i + 1:i + 2]
                if cmd in (b"\xfd", b"\xfb"): s.k.sendall(b"\xff" + (b"\xfc" if cmd == b"\xfd" else b"\xfe") + d[i + 2:i + 3]); i += 3
                elif cmd == b"\xfa": j = d.find(b"\xff\xf0", i); i = len(d) if j < 0 else j + 2
                elif cmd == b"\xff": s.buf += b"\xff"; i += 2
                else: i += 3 if cmd in (b"\xfc", b"\xfe") else 2
            return True
        def read_until(s, m, timeout):
            end = time.time() + timeout
            while m not in s.buf and time.time() < end and s._fill(max(.05, end - time.time())) is not None: pass
            i = s.buf.find(m); n = i + len(m) if i >= 0 else len(s.buf); r, s.buf = s.buf[:n], s.buf[n:]; return r
        def read_very_eager(s):
            while s._fill(0): pass
            r, s.buf = s.buf, b""; return r
        def write(s, b): s.k.sendall(b.replace(b"\xff", b"\xff\xff"))
        def close(s): s.k.close()

def cisco(host, u, pw, a):
    proto = a.get("cproto", "ssh"); port = int(a.get("cport") or (23 if proto == "telnet" else 22)); en = a.get("cenable", "")
    socket.create_connection((host, port), 6).close()  # connectivity test
    if a["action"] == "c_test": cmds = ["show clock", "show logging | include Logging to|Trap logging"]
    else:
        if not a.get("syslog"): raise Exception("Syslog server IP is required")
        body = [l.replace("{syslog_ip}", a["syslog"]).rstrip() for l in a.get("ctext", "").splitlines() if l.strip()]
        cmds = ["configure terminal"] + body + ["end", "write memory"]
    out = ""
    if proto == "telnet":
        t = Telnet(host, port, 10)
        try:
            t.read_until(b"sername:", 10); t.write(u.encode() + b"\n"); t.read_until(b"assword:", 10); t.write(pw.encode() + b"\n")
            time.sleep(1); out += t.read_very_eager().decode(errors="ignore")
            if en: t.write(b"enable\n"); time.sleep(.5); t.write(en.encode() + b"\n")
            for x in ["terminal length 0"] + cmds: t.write(x.encode() + b"\n"); time.sleep(.6); out += t.read_very_eager().decode(errors="ignore")
        finally: t.close()
    else:
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy()); a["_job"]["clients"].append(c)
        try:
            c.connect(host, port=port, username=u, password=pw, timeout=15, look_for_keys=False, allow_agent=False)
            sh = c.invoke_shell()
            def rd(w):
                time.sleep(w); b = ""
                while sh.recv_ready(): b += sh.recv(65535).decode(errors="ignore"); time.sleep(.1)
                return b
            out += rd(1.5)
            if en: sh.send("enable\n"); rd(.5); sh.send(en + "\n"); out += rd(.8)
            for x in ["terminal length 0"] + cmds: sh.send(x + "\n"); out += rd(.7)
        finally: c.close()
    out = out.strip()
    if re.search(r"^\s*% ?(Invalid|Incomplete|Ambiguous|Authorization failed|Login invalid|Bad passwords|Access denied)", out, re.M | re.I):
        out += "\nERROR: the device rejected some commands or the login (see output above)"
    return out

def probe(h):
    # WinRM first: a Windows host may also run OpenSSH, and a Linux host may run Samba
    for port, o in ((5985, "windows"), (22, "linux"), (445, "windows"), (3389, "windows")):
        try: socket.create_connection((h, port), 3).close(); return o
        except OSError: pass
    raise Exception("Host unreachable (no SSH / WinRM / SMB / RDP port open)")

# ---------- jobs ----------
def log(client, o, h, task, r):
    st = "fail" if FAIL.search(r) else "ok"
    with dbc() as d, d: d.execute("insert into h values(?,?,?,?,?,?,?)", (time.strftime("%Y-%m-%d %H:%M:%S"), client, o, h, task, st, r))

def bad_req(m): return jsonify(error=m), 400

@app.post("/api/run")
def api_run():
    a = request.get_json(silent=True) or {}; act = a.get("action", "")
    try: ts = parse_targets(a.get("targets", ""), a.get("user", ""), a.get("pass", ""), a.get("os", "windows"), a.get("profiles", ""))
    except Exception as e: return bad_req(str(e))
    if not ts: return bad_req("Enter at least one target (IP / hostname / CIDR)")
    for k in ("file", "file2"):
        n = a[k] = os.path.basename(a.get(k) or "")
        if n and not (visible(n) and os.path.isfile(os.path.join(DATA, n))): return bad_req(f"File not found in the library: {n}")
    if act in ("install_uf", "sysmon", "push_conf", "deploy_app", "audit_rules") and not a["file"]: return bad_req("Select a file for this task (upload it to the Files library first)")
    if act == "install_uf" and len(a.get("apass") or "") < 8: return bad_req("UF admin password must be at least 8 characters (Options)")
    if act == "svc" and a.get("op") not in OPS: return bad_req("Invalid service action")
    for k in ("idx", "syslog"):
        a[k] = (a.get(k) or "").strip()
        if not re.fullmatch(r"[\w.:\-\[\]]*", a[k]): return bad_req(f"Invalid address: {a[k]}")
    if not a.get("base"): a["base"] = request.host_url
    with LOCK:  # forget finished jobs older than 6 hours
        for k in [k for k, j in JOBS.items() if time.time() - j["t"] > 21600]: JOBS.pop(k, None)
        jid = uuid.uuid4().hex; job = JOBS[jid] = {"results": {}, "hosts": [t[0] for t in ts], "total": len(ts), "clients": [], "cancel": False, "t": time.time()}
    task = act + (":" + a.get("svc", "") + "/" + a["op"] if act == "svc" else ""); client = request.remote_addr
    def one(t):
        h, u, w, o = t
        if job["cancel"]: return
        try:
            if o == "auto": o = probe(h)
            if not u: raise Exception("No username (set default credentials, a profile or host,user,pass)")
            r = {"windows": win, "linux": lin, "cisco": cisco}[o](h, u, w, {**a, "_job": job})
        except Exception as e: r = "ERROR: " + (str(e) or type(e).__name__)[:500]
        if not job["cancel"]: job["results"][h] = r; log(client, o, h, task, r)
    for t in ts: POOL.submit(one, t)
    return jsonify(id=jid, total=len(ts))

@app.post("/api/cancel/<jid>")
def api_cancel(jid):
    j = JOBS.get(jid)
    if j:
        j["cancel"] = True
        for c in j["clients"]:
            try: c.close()
            except Exception: pass
        for h in j["hosts"]: j["results"].setdefault(h, "CANCELLED")
    return jsonify(ok=True)

@app.get("/api/job/<jid>")
def api_job(jid):
    j = JOBS.get(jid, {}); return jsonify({k: v for k, v in j.items() if k != "clients"})
@app.post("/api/upload")
def api_upload():
    for f in request.files.getlist("f"):
        n = os.path.basename((f.filename or "").replace("\\", "/"))
        if n and visible(n): f.save(os.path.join(DATA, n))
    return api_files()
def host_match(spec):
    nets, names = [], []
    for x in [x.strip() for x in re.split(r"[,\n;]+", spec) if x.strip()]:
        try:
            if "/" in x: nets.append(ipaddress.ip_network(x, strict=False)); continue
            if "-" in x and x.count(".") >= 6:
                nets.append(tuple(sorted(int(ipaddress.ip_address(y.strip())) for y in x.split("-", 1)))); continue
        except ValueError: pass
        names.append(x.lower())
    def m(h):
        if any(fnmatch.fnmatch(h.lower(), n) for n in names): return True
        try: ip = ipaddress.ip_address(h)
        except ValueError: return False
        return any((ip in n) if hasattr(n, "network_address") else n[0] <= int(ip) <= n[1] for n in nets)
    return m

def hist(args):
    w, p = ["1=1"], []
    for k, col in (("os", "os"), ("status", "status")):
        if args.get(k): w.append(f"{col}=?"); p.append(args[k])
    if args.get("task"): w.append("task like ?"); p.append(args["task"] + "%")
    if args.get("q"): w.append("(host like ? or output like ?)"); p += [f"%{args['q']}%"] * 2
    if args.get("frm"): w.append("ts>=?"); p.append(args["frm"])
    if args.get("to"): w.append("ts<=?"); p.append(args["to"] + " 23:59:59")
    with dbc() as d: rows = d.execute(f"select ts,client,os,host,task,status,output from h where {' and '.join(w)} order by ts desc limit 5000", p).fetchall()
    spec = args.get("hosts", "") + "\n" + jload(GRP).get(args.get("group", ""), "")
    if spec.strip():
        m = host_match(spec); rows = [r for r in rows if m(r[3])]
    return rows
@app.get("/api/history")
def api_hist(): return jsonify(hist(request.args))
@app.get("/api/history.csv")
def api_csv():
    b = io.StringIO(); w = csv.writer(b); w.writerow(["time", "client", "os", "host", "task", "status", "output"]); w.writerows(hist(request.args))
    return b.getvalue().encode("utf-8-sig"), 200, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=uf-deployer-history.csv"}
@app.get("/report")
def report():
    rows = hist(request.args); ok = sum(r[5] == "ok" for r in rows); E = html.escape
    tr = "".join(f"<tr class={r[5]}><td>{E(r[0])}</td><td>{E(r[2])}</td><td>{E(r[3])}</td><td>{E(r[4])}</td><td>{E(r[5])}</td></tr><tr><td colspan=5><pre>{E(r[6])}</pre></td></tr>" for r in rows)
    return (f"<meta charset=utf-8><title>UF Deployer report</title><style>body{{font:12px Segoe UI,sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:4px 6px;text-align:left}}"
            f".fail td:nth-child(5){{color:#c00;font-weight:bold}}.ok td:nth-child(5){{color:#080}}pre{{white-space:pre-wrap;margin:0;font-size:11px}}@media print{{button{{display:none}}}}</style>"
            f"<h2>Splunk UF Deployer - Report</h2><p>Generated {time.strftime('%Y-%m-%d %H:%M')} - {len(rows)} records, {ok} ok, {len(rows)-ok} failed "
            f"<button onclick=print()>Print / Save as PDF</button></p><table><tr><th>Time</th><th>OS</th><th>Host</th><th>Task</th><th>Status</th></tr>{tr}</table>")

def facts(rows):
    H = {}
    def st_of(t):
        if re.search(r"not installed", t, re.I): return "Not installed"
        if re.search(r"not running|stopped|inactive|failed", t, re.I): return "Stopped"
        if re.search(r"running|active", t, re.I): return "Running"
        return "Installed"
    for ts, cl, o, host, task, st, out in reversed(rows):
        d = H.setdefault(host, dict(os=o, uf="-", sysmon="-", auditd="-", rules=None, apps=0, confs=0, tasks={}, err={}, last=ts))
        d["tasks"][task] = st; d["last"] = ts; d["os"] = o
        if st == "fail":
            d["err"][task] = "auth" if re.search(r"auth|credential|denied|logon|password", out, re.I) else "net" if re.search(r"refused|timed out|unreachable|Max retries|Connection|SMB connect", out, re.I) else "other"; continue
        d["err"].pop(task, None); low = out.lower()
        if task == "check":
            for key, pat in (("uf", r"Splunk UF: (.*)"), ("sysmon", r"Sysmon: (.*)"), ("auditd", r"auditd: (.*)")):
                m = re.search(pat, out)
                if m: d[key] = st_of(m[1])
            m = re.search(r"Service: (.*)", out)
            if m and d["uf"] != "Not installed": d["uf"] = st_of(m[1])
        elif task.startswith("svc:"):
            k = {"splunk": "uf", "sysmon": "sysmon", "auditd": "auditd"}.get(task.split(":")[1].split("/")[0])
            v = st_of(out)
            if k and (v != "Installed" or d[k] == "-"): d[k] = v
        elif task == "install_uf" and re.search(r"exit code: (0|3010)|already installed|running|started", low): d["uf"] = "Running" if "running" in low or "exit code: 0" in low else "Installed"
        elif task == "sysmon" and ("installed" in low or "updated" in low): d["sysmon"] = "Installed"
        elif task == "auditd" and "no supported package" not in low: d["auditd"] = "Installed"
        elif task == "audit_rules":
            m = re.search(r"rules_total=(\d+) applied=(\d+) removed=(\d+)", out)
            if m: d["rules"] = tuple(map(int, m.groups()))
        elif task == "push_conf": d["confs"] += 1
        elif task == "deploy_app": d["apps"] += 1
    return H

def g2j(gy, gm, gd):
    gdm = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]; gy2 = gy + 1 if gm > 2 else gy
    days = 355666 + 365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100 + (gy2 + 399) // 400 + gd + gdm[gm - 1]
    jy = -1595 + 33 * (days // 12053); days %= 12053; jy += 4 * (days // 1461); days %= 1461
    if days > 365: jy += (days - 1) // 365; days = (days - 1) % 365
    jm, jd = (1 + days // 31, 1 + days % 31) if days < 186 else (7 + (days - 186) // 30, 1 + (days - 186) % 30)
    return jy, jm, jd
def fdate(ts, lang):
    if lang != "fa": return ts
    jy, jm, jd = g2j(int(ts[:4]), int(ts[5:7]), int(ts[8:10])); return f"{jy}/{jm:02d}/{jd:02d} {ts[11:16]}"

LBL = {"fa": dict(title="گزارش مدیریتی استقرار Splunk", gen="تاریخ گزارش", prn="چاپ / ذخیره PDF", by="تهیه‌کننده",
        sum="{nh} سرور پردازش شد. {hy} سرور ({p}٪) کاملاً سالم هستند و {bad} سرور نیاز به بررسی دارند. Splunk Forwarder روی {uf} سرور، Sysmon روی {sm} سرور و auditd روی {ad} سرور فعال است. {ra} قانون از {rt} قانون auditd با موفقیت اعمال شد.",
        k1="سرور", k2="کار انجام‌شده", k3="درصد موفقیت", k4="قانون auditd اعمال‌شده", c1="وضعیت اجرای کارها", c2="پوشش در سرورها", c3="قوانین auditd", c4="وضعیت هر سرور", c5="مشکلات باز",
        uf="Splunk Forwarder فعال", sm="Sysmon فعال", ad="auditd فعال", hos="سرورهای سالم", okf="{ok} موفق، {bad} ناموفق",
        lg="اعمال‌شده {ra} ■ حذف‌شده (روی سرور معتبر نبود) {rr} ■ مجموع {rt}", th=["سرور", "سیستم‌عامل", "Splunk UF", "Sysmon", "auditd", "قوانین auditd", "نصب‌شده‌ها", "وضعیت کلی", "آخرین فعالیت"],
        dep="{a} اپ، {c} کانفیگ", skip="{n} ردشده", tk="{n} کار", none="مشکل بازی وجود ندارد.",
        st={"Running": "در حال اجرا", "Installed": "نصب شده", "Stopped": "متوقف", "Not installed": "نصب نشده", "Healthy": "سالم", "Attention": "نیاز به بررسی", "Failed": "ناموفق", "-": "—"},
        os={"windows": "ویندوز", "linux": "لینوکس", "cisco": "سیسکو"},
        msg={"auth": "ورود پذیرفته نشد؛ نام کاربری و رمز عبور را بررسی کنید", "net": "در دسترس نبود؛ مدیریت از راه دور مسدود یا سرور خاموش است", "other": "یک کار کامل نشد"}),
       "en": dict(title="Splunk Deployment - Management Report", gen="Generated", prn="Print / Save as PDF", by="Prepared by",
        sum="{nh} server(s) were processed. {hy} ({p}%) are fully healthy; {bad} need attention. Splunk Forwarder is active on {uf}, Sysmon on {sm} and auditd on {ad} servers. {ra} of {rt} audit rules were applied successfully.",
        k1="Servers", k2="Tasks executed", k3="Success rate", k4="Audit rules applied", c1="Task outcome", c2="Coverage across servers", c3="Audit rules", c4="Per-server status", c5="Open issues",
        uf="Splunk Forwarder active", sm="Sysmon active", ad="auditd active", hos="Healthy servers", okf="{ok} succeeded - {bad} failed",
        lg="applied {ra} ■ removed (not valid on host) {rr} ■ total {rt}", th=["Server", "OS", "Splunk UF", "Sysmon", "auditd", "Audit rules", "Deployed", "Overall", "Last activity"],
        dep="{a} apps, {c} configs", skip="{n} skipped", tk="{n} task(s)", none="No open issues.",
        st={}, os={}, msg={"auth": "login was rejected - check the username and password", "net": "could not be reached - remote management is blocked or the host is offline", "other": "a task did not complete"})}

@app.get("/report/exec")
def report_exec():
    lang = "en" if request.args.get("lang") == "en" else "fa"; L = LBL[lang]; E = html.escape
    br = jload(BRAND)
    rows = hist(request.args); H = facts(rows); n = len(rows); ok = sum(r[5] == "ok" for r in rows)
    tr = lambda v: L["st"].get(v, v)
    badge = lambda v: f"<span class='bd {'g' if v in ('Running','Installed','Healthy') else 'r' if v in ('Failed','Stopped','Not installed') else 'a' if v=='Attention' else 'n'}'>{tr(v)}</span>"
    status = {}
    for h, d in H.items():
        okc = sum(1 for v in d["tasks"].values() if v == "ok"); status[h] = "Failed" if d["err"] and not okc else "Attention" if d["err"] else "Healthy"
    cnt = lambda k: sum(d[k] in ("Running", "Installed") for d in H.values())
    nh = len(H); hy = sum(v == "Healthy" for v in status.values())
    R = [d["rules"] for d in H.values() if d["rules"]]; rt, ra, rr = (sum(x[i] for x in R) for i in (0, 1, 2))
    bar = lambda l, v, t, c: f"<div class=b><span>{l}</span><div class=t><i style='width:{(100*v/t if t else 0):.0f}%;background:{c}'></i></div><b>{v}/{t}</b></div>"
    pct = (100 * ok / n) if n else 0; circ = 251.3
    donut = (f"<svg width=130 height=130 viewBox='0 0 100 100'><circle cx=50 cy=50 r=40 fill=none stroke='#fca5a5' stroke-width=14 />"
             f"<circle cx=50 cy=50 r=40 fill=none stroke='#16a34a' stroke-width=14 stroke-dasharray='{circ*pct/100:.1f} {circ}' transform='rotate(-90 50 50)' />"
             f"<text x=50 y=55 text-anchor=middle font-size=16 font-weight=700>{pct:.0f}%</text></svg>")
    byos = "".join(bar(f"{L['hos']} ({L['os'].get(o, o.title())})", sum(1 for h, d in H.items() if d["os"] == o and status[h] == "Healthy"), sum(1 for d in H.values() if d["os"] == o), "#2f6bff") for o in sorted({d["os"] for d in H.values()}))
    stack = (f"<div class=t style='height:22px;display:flex'><i style='width:{(100*ra/rt if rt else 0):.0f}%;background:#16a34a'></i><i style='width:{(100*rr/rt if rt else 0):.0f}%;background:#f59e0b'></i></div>"
             f"<div class=hint>{L['lg'].format(ra=ra, rr=rr, rt=rt)}</div>")
    ip = lambda h: f"<bdi class=ip dir=ltr>{E(h)}</bdi>"
    issues = "".join(f"<li>{ip(h)}: {L['msg'][sorted(d['err'].values())[0]]} ({L['tk'].format(n=len(d['err']))})</li>" for h, d in H.items() if d["err"]) or f"<li>{L['none']}</li>"
    trs = "".join(f"<tr><td><b>{ip(h)}</b></td><td>{L['os'].get(d['os'], d['os'].title())}</td><td>{badge(d['uf'])}</td><td>{badge(d['sysmon'])}</td><td>{badge(d['auditd'])}</td>"
                  f"<td>{(str(d['rules'][1]) + ' / ' + str(d['rules'][0]) + (' (' + L['skip'].format(n=d['rules'][2]) + ')' if d['rules'][2] else '')) if d['rules'] else '—'}</td>"
                  f"<td>{L['dep'].format(a=d['apps'], c=d['confs'])}</td><td>{badge(status[h])}</td><td>{fdate(d['last'], lang)}</td></tr>" for h, d in sorted(H.items()))
    css = ("body{font:14px Vazirmatn,Tahoma,'Segoe UI',system-ui,sans-serif;margin:0;background:#f4f6fa;color:#1c2434}.w{max-width:1100px;margin:auto;padding:24px}h1{margin:0;font-size:24px}.sub{color:#6a7590;margin-top:2px}"
           ".hd{display:flex;align-items:center;gap:16px;margin-bottom:16px}.hd img{max-height:70px;max-width:180px}.k{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px}"
           ".c{background:#fff;border:1px solid #dfe4ee;border-radius:10px;padding:14px;margin-bottom:14px}.k .c{margin:0;text-align:center}.k b{display:block;font-size:30px;color:#2f6bff}"
           ".g2{display:grid;grid-template-columns:1fr 2fr;gap:14px}h3{margin:0 0 10px;font-size:14px;color:#6a7590}.b{display:flex;align-items:center;gap:8px;margin:7px 0}.b span{width:210px}.b b{width:60px;text-align:end}"
           ".t{flex:1;background:#e5e9f2;border-radius:6px;overflow:hidden;height:14px}.t i{display:block;height:100%}table{border-collapse:collapse;width:100%}td,th{padding:8px;border-bottom:1px solid #e5e9f2;text-align:start}"
           "th{color:#6a7590;font-size:12px}.bd{padding:2px 10px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;background:#94a3b8;white-space:nowrap}.bd.g{background:#16a34a}.bd.r{background:#dc2626}.bd.a{background:#d97706}"
           ".hint{color:#6a7590;font-size:12px;margin-top:6px}@media(max-width:700px){.k,.g2{grid-template-columns:1fr 1fr}.g2{grid-template-columns:1fr}.c{overflow-x:auto}}"
           "@media print{button{display:none}body{background:#fff}.c{break-inside:avoid}}")
    logo = f"<img src='/logo?v={E(br['logo'])}' alt=logo>" if br.get("logo") else ""
    sub = " | ".join(x for x in (E(br.get("company", "")), f"{L['by']}: {E(br['by'])}" if br.get("by") else "", f"{L['gen']}: {fdate(time.strftime('%Y-%m-%d %H:%M'), lang)}") if x)
    digits = ("<script>const D='۰۱۲۳۴۵۶۷۸۹',w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);let x;while(x=w.nextNode())if(!x.parentElement.closest('.ip,script,style'))x.nodeValue=x.nodeValue.replace(/[0-9]/g,d=>D[d])</script>" if lang == "fa" else "")
    return (f"<!doctype html><html dir={'rtl' if lang == 'fa' else 'ltr'} lang={lang}><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{E(br.get('title') or L['title'])}</title><style>{css}</style><div class=w>"
            f"<div class=hd>{logo}<div><h1>{E(br.get('title') or L['title'])}</h1><div class=sub>{sub}</div></div><button style='margin-inline-start:auto;padding:8px 16px' onclick=print()>{L['prn']}</button></div>"
            f"<div class=c>{L['sum'].format(nh=nh, hy=hy, p=round(100*hy/nh) if nh else 0, bad=nh-hy, uf=cnt('uf'), sm=cnt('sysmon'), ad=cnt('auditd'), ra=ra, rt=rt)}</div>"
            f"<div class=k><div class=c><b>{nh}</b>{L['k1']}</div><div class=c><b>{n}</b>{L['k2']}</div><div class=c><b>{pct:.0f}%</b>{L['k3']}</div><div class=c><b>{ra}</b>{L['k4']}</div></div>"
            f"<div class=g2><div class=c><h3>{L['c1']}</h3><div style='text-align:center'>{donut}</div><div class=hint style='text-align:center'>{L['okf'].format(ok=ok, bad=n-ok)}</div></div>"
            f"<div class=c><h3>{L['c2']}</h3>{bar(L['uf'], cnt('uf'), nh, '#16a34a')}{bar(L['sm'], cnt('sysmon'), nh, '#2f6bff')}{bar(L['ad'], cnt('auditd'), nh, '#7c3aed')}{byos}"
            f"<h3 style='margin-top:14px'>{L['c3']}</h3>{stack}</div></div>"
            f"<div class=c><h3>{L['c4']}</h3><table><tr>{''.join('<th>' + x + '</th>' for x in L['th'])}</tr>{trs}</table></div>"
            f"<div class=c><h3>{L['c5']}</h3><ul>{issues}</ul></div></div>{digits}")

@app.get("/api/branding")
def api_brand_get(): return jsonify(jload(BRAND))
@app.post("/api/branding")
def api_brand_set():
    with LOCK:
        b = jload(BRAND); b.update({k: str(v) for k, v in (request.get_json(silent=True) or {}).items() if k in ("company", "title", "by", "logo")})
        return jsonify(jsave(BRAND, b))
@app.post("/api/logo")
def api_logo():
    f = request.files.get("f")
    ext = os.path.splitext(f.filename or "")[1].lower() if f else ""
    if ext not in (".png", ".jpg", ".jpeg", ".svg", ".gif", ".webp"): return bad_req("Use png/jpg/svg/gif/webp")
    with LOCK:
        for o in os.listdir(DATA):
            if o.startswith("logo."): os.remove(os.path.join(DATA, o))
        f.save(os.path.join(DATA, "logo" + ext)); b = jload(BRAND)
        b["logo"] = str(int(time.time())) + ext; return jsonify(jsave(BRAND, b))
@app.get("/logo")
def logo():
    for o in os.listdir(DATA):
        if o.startswith("logo."): return send_from_directory(DATA, o)
    return "", 404
def named_store(path):
    d = request.get_json(silent=True) or {}; name = str(d.get("name", "")).strip()
    with LOCK:
        g = jload(path)
        if name:
            if str(d.get("text", "")).strip(): g[name] = d["text"]
            else: g.pop(name, None)
            jsave(path, g)
    return jsonify(g)
@app.get("/api/groups")
def api_grp_get(): return jsonify(jload(GRP))
@app.post("/api/groups")
def api_grp_set(): return named_store(GRP)
@app.get("/api/templates")
def api_tpl_get(): return jsonify(jload(TPL))
@app.post("/api/templates")
def api_tpl_set(): return named_store(TPL)
@app.get("/api/filelist")
def api_filelist(): return jsonify([[n, os.path.getsize(os.path.join(DATA, n))] for n in sorted(os.listdir(DATA)) if visible(n) and os.path.isfile(os.path.join(DATA, n))])
@app.post("/api/delete")
def api_delete():
    n = os.path.basename(str((request.get_json(silent=True) or {}).get("name", ""))); p = os.path.join(DATA, n)
    if n and visible(n) and os.path.isfile(p): os.remove(p)
    return api_filelist()
@app.get("/api/files")
def api_files(): return jsonify(sorted(n for n in os.listdir(DATA) if visible(n) and os.path.isfile(os.path.join(DATA, n))))
@app.get("/files/<path:n>")
def files(n):  # targets download from here: never expose history / groups / branding
    if n != os.path.basename(n) or not visible(n): abort(404)
    return send_from_directory(DATA, n)
@app.get("/")
def index():
    with open(os.path.join(HERE, "index.html"), encoding="utf-8") as fh: return fh.read()

if __name__ == "__main__":
    args = sys.argv[1:]; port = next((int(x) for x in args if x.isdigit()), int(os.environ.get("PORT", 5000)))
    if "--no-browser" not in args: threading.Timer(1.5, webbrowser.open, [f"http://127.0.0.1:{port}"]).start()
    app.run(host="0.0.0.0", port=port, threaded=True)
