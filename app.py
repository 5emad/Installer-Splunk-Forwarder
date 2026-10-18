"""UF Deployer - web UI + FastAPI backend to deploy Splunk UF / Sysmon / auditd.
Run:  python app.py   ->  http://127.0.0.1:8000
"""
import csv, io, ipaddress, json, os, re, secrets, shlex, shutil, socket, sqlite3
import subprocess, tempfile, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

import sys, base64, getpass, hashlib
FROZEN = getattr(sys, "frozen", False)
BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))  # bundled resources
DATA = (os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "UFDeployer")
        if FROZEN else BASE)  # writable folder (installed exe may live in Program Files)
os.makedirs(DATA, exist_ok=True)
DB = os.path.join(DATA, "history.db")
MAX_HOSTS, WORKERS = 1024, 10
PORT = 8000
app = FastAPI(title="UF Deployer")


# ───────────────────────── request guard (CSRF / DNS rebinding) ─────────────────────────
# Any web page open in the browser can send simple POSTs to 127.0.0.1, so every API call must
# carry a per-run secret: a SameSite=Strict cookie (all /api requests) plus a custom header
# (state-changing requests; a cross-site page cannot add it without a CORS preflight we never allow).
TOKEN = secrets.token_urlsafe(32)
HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ORIGINS = {f"http://{h}" for h in HOSTS}


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.headers.get("host", "") not in HOSTS:
        return JSONResponse({"detail": "invalid Host header"}, 400)
    if request.url.path.startswith("/api/"):
        if not secrets.compare_digest(request.cookies.get("ufd", ""), TOKEN):
            return JSONResponse({"detail": "session expired - reload the page"}, 403)
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if (origin and origin not in ORIGINS) or \
                    not secrets.compare_digest(request.headers.get("x-ufd-token", ""), TOKEN):
                return JSONResponse({"detail": "request rejected (missing or invalid token)"}, 403)
    return await call_next(request)


# ───────────────────────── history (SQLite) ─────────────────────────
def db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, ts TEXT, ip TEXT,
                 os TEXT, service TEXT, operation TEXT, ok INTEGER, message TEXT)""")
    try:
        c.execute("ALTER TABLE history ADD COLUMN operator TEXT")
    except sqlite3.OperationalError:
        pass
    return c


def db_add(ip, os_, svc, op, ok, msg, operator=""):
    with db() as c:
        c.execute("INSERT INTO history(ts,ip,os,service,operation,ok,message,operator) VALUES(?,?,?,?,?,?,?,?)",
                  (time.strftime("%Y-%m-%d %H:%M:%S"), ip, os_, svc, op, int(ok), (msg or "")[:4000], operator))


def query_history(df="", dt="", os_="", svc="", status="", q=""):
    sql, p = "SELECT ts,ip,os,service,operation,ok,message,operator FROM history WHERE 1=1", []
    if df: sql += " AND ts>=?"; p.append(df)
    if dt: sql += " AND ts<=?"; p.append(dt + " 23:59:59")
    if os_: sql += " AND os=?"; p.append(os_)
    if svc: sql += " AND service=?"; p.append(svc)
    if status == "ok": sql += " AND ok=1"
    if status == "fail": sql += " AND ok=0"
    if q:
        sql += " AND (ip LIKE ? OR operation LIKE ? OR message LIKE ?)"; p += [f"%{q}%"] * 3
    with db() as c:
        return c.execute(sql + " ORDER BY id DESC LIMIT 5000", p).fetchall()


# ───────────────────────── jobs ─────────────────────────
class Cancelled(Exception):
    pass


class Job:
    def __init__(self):
        self.id = uuid.uuid4().hex[:10]
        self.lines, self.done = [], False
        self.cancel = threading.Event()
        self.dir = tempfile.mkdtemp(prefix="ufd_")

    def log(self, ip, lvl, msg):
        for l in (str(msg).splitlines() or [""]):
            self.lines.append({"t": time.strftime("%H:%M:%S"), "ip": ip, "lvl": lvl, "msg": l})

    def check(self):
        if self.cancel.is_set():
            raise Cancelled()


OPERATOR = getpass.getuser()
JOBS: dict = {}
ACTIONS: dict = {}


def action(os_, name, svc):
    def deco(f):
        ACTIONS[(os_, name)] = (f, svc)
        return f
    return deco


# ───────────────────────── helpers ─────────────────────────
def ping(ip):
    nt = os.name == "nt"
    cmd = ["ping", "-n", "1", "-w", "1000", ip] if nt else ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


def port_open(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def parse_targets(mode, text, csv_bytes, d):
    rows = []
    text = (text or "").strip()
    if mode == "single":
        rows = [{"ip": text}]
    elif mode == "range":
        if "/" in text:
            rows = [{"ip": str(i)} for i in ipaddress.ip_network(text, strict=False).hosts()]
        elif "-" in text:
            a, b = [x.strip() for x in text.split("-", 1)]
            end = b if "." in b else a.rsplit(".", 1)[0] + "." + b
            rows = [{"ip": str(ipaddress.ip_address(i))}
                    for i in range(int(ipaddress.ip_address(a)), int(ipaddress.ip_address(end)) + 1)]
        else:
            raise ValueError("range must be CIDR (10.0.0.0/24) or 10.0.0.1-10.0.0.20")
    elif mode == "csv":
        rd = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig")))
        for r in rd:
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
            if r.get("ip"):
                rows.append({"ip": r["ip"], "port": r.get("port"), "user": r.get("username"),
                             "pass": r.get("password"), "auth": r.get("auth_type") or r.get("auth")})
    if not rows or not rows[0]["ip"]:
        raise ValueError("no targets")
    if len(rows) > MAX_HOSTS:
        raise ValueError(f"max {MAX_HOSTS} hosts")
    return [{"ip": r["ip"], "port": r.get("port") or d["port"], "user": r.get("user") or d["user"],
             "pass": r.get("pass") or d["pass"], "auth": (r.get("auth") or d["auth"]).lower(),
             "key": d["key"], "sudo_pass": d["sudo_pass"], "enable": d.get("enable", ""),
             "verify": d.get("verify", False)} for r in rows]


PATHFIX = "export PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin; "


# ---- SSH host keys: trust on first use, refuse a changed key ----
KNOWN_HOSTS = os.path.join(DATA, "known_hosts")
_kh_lock = threading.Lock()


def _load_known():
    import paramiko
    hk = paramiko.HostKeys()
    with _kh_lock:
        if os.path.isfile(KNOWN_HOSTS):
            hk.load(KNOWN_HOSTS)
    return hk


def trust_host_key(name, key, log):
    """Remember the key of a host seen for the first time; raise if a known host shows another key."""
    import paramiko
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    with _kh_lock:
        hk = paramiko.HostKeys()
        if os.path.isfile(KNOWN_HOSTS):
            hk.load(KNOWN_HOSTS)
        known = hk.lookup(name)
        if known:
            if known.get(key.get_name()) != key:
                raise RuntimeError(f"SSH HOST KEY CHANGED for {name} (now {key.get_name()} {fp}) - possible "
                                   f"man-in-the-middle. If the host was really reinstalled, delete its line from "
                                   f"{KNOWN_HOSTS}")
            return
        hk.add(name, key.get_name(), key)
        hk.save(KNOWN_HOSTS)
    log(f"new SSH host key saved: {key.get_name()} {fp}")


def ssh_precheck(ip, port, log):
    """Fetch and verify the host key before any password is sent (used for netmiko connections)."""
    import paramiko
    name = ip if port == 22 else f"[{ip}]:{port}"
    known = list(_load_known().lookup(name) or {})
    t = paramiko.Transport(socket.create_connection((ip, port), timeout=15))
    try:
        if known:
            o = t.get_security_options()
            o.key_types = tuple(known + [k for k in o.key_types if k not in known])
        t.start_client(timeout=15)
        key = t.get_remote_server_key()
    finally:
        t.close()
    trust_host_key(name, key, log)


# ---- SMB admin share without putting the password on a command line ----
_smb_lock = threading.Lock()
_smb_refs: dict = {}
_smb_host_locks: dict = {}


def _smb_api():
    import ctypes
    from ctypes import wintypes

    class NETRESOURCE(ctypes.Structure):
        _fields_ = [("dwScope", wintypes.DWORD), ("dwType", wintypes.DWORD), ("dwDisplayType", wintypes.DWORD),
                    ("dwUsage", wintypes.DWORD), ("lpLocalName", wintypes.LPWSTR),
                    ("lpRemoteName", wintypes.LPWSTR), ("lpComment", wintypes.LPWSTR),
                    ("lpProvider", wintypes.LPWSTR)]
    return ctypes, NETRESOURCE


def smb_open(unc, user, pw):
    """Connect to \\\\host\\C$ (ref-counted so parallel jobs on one host don't drop each other's session)."""
    with _smb_lock:
        hl = _smb_host_locks.setdefault(unc, threading.Lock())
    with hl:
        if _smb_refs.get(unc):
            _smb_refs[unc] += 1
            return
        ctypes, NETRESOURCE = _smb_api()
        nr = NETRESOURCE(dwType=1, lpRemoteName=unc)  # RESOURCETYPE_DISK
        rc = ctypes.windll.mpr.WNetAddConnection2W(ctypes.byref(nr), pw or None, user or None, 0)
        if rc:
            hint = (" - this PC already has a connection to that host with other credentials (see 'net use')"
                    if rc == 1219 else "")
            raise RuntimeError(f"SMB connect to {unc} failed: {ctypes.FormatError(rc).strip()} ({rc}){hint}")
        _smb_refs[unc] = 1


def smb_close(unc):
    with _smb_lock:
        hl = _smb_host_locks.setdefault(unc, threading.Lock())
    with hl:
        _smb_refs[unc] = _smb_refs.get(unc, 1) - 1
        if _smb_refs[unc] <= 0:
            _smb_refs.pop(unc, None)
            ctypes, _ = _smb_api()
            ctypes.windll.mpr.WNetCancelConnection2W(unc, 0, True)


class Ctx:
    def __init__(self, job, t, p, files, os_):
        self.job, self.t, self.p, self.files, self.os = job, t, p, files, os_
        self._ws = self._ssh = self._net = None

    def log(self, m): self.job.log(self.t["ip"], "INFO", m)
    def step(self, m): self.job.check(); self.log(m)

    def close(self):
        if self._ssh:
            self._ssh.close()
        if self._net:
            try:
                self._net.disconnect()
            except Exception:
                pass

    # ---- Windows (WinRM for exec, SMB admin share for file copy) ----
    def ws(self):
        if not self._ws:
            import winrm
            port = int(self.t["port"] or 5985)
            tr = {"ntlm": "ntlm", "basic": "basic", "kerberos": "kerberos", "credssp": "credssp",
                  "domain": "ntlm", "workgroup": "ntlm"}.get(self.t["auth"], "ntlm")
            https = port == 5986
            if tr == "basic" and not https:
                raise RuntimeError("Basic auth over HTTP (5985) sends the password in clear text - use port 5986 "
                                   "(HTTPS) or NTLM/Kerberos")
            self._ws = winrm.Session(f"{'https' if https else 'http'}://{self.t['ip']}:{port}/wsman",
                                     auth=(self.t["user"], self.t["pass"]), transport=tr,
                                     server_cert_validation="validate" if self.t.get("verify") else "ignore",
                                     read_timeout_sec=660, operation_timeout_sec=600)
        return self._ws

    def ps(self, script):
        self.job.check()
        r = self.ws().run_ps(script)
        return r.status_code, (r.std_out + r.std_err).decode("utf-8", "ignore").strip()

    def smb_cp(self, local, rel):
        if os.name != "nt":
            raise RuntimeError("SMB copy needs this app to run on Windows")
        unc = rf"\\{self.t['ip']}\C$"
        smb_open(unc, self.t["user"], self.t["pass"])
        try:
            dst = unc + "\\" + rel
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(local, dst)
        finally:
            smb_close(unc)

    # ---- Linux (SSH + sudo -S) ----
    def ssh(self):
        if not self._ssh:
            import paramiko
            log = self.log

            class Tofu(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client, hostname, key):
                    trust_host_key(hostname, key, log)

            c = paramiko.SSHClient()
            c.get_host_keys().update(_load_known())
            c.set_missing_host_key_policy(Tofu())
            kw = dict(hostname=self.t["ip"], port=int(self.t["port"] or 22), username=self.t["user"],
                      timeout=15, allow_agent=False, look_for_keys=False)
            if self.t["auth"] == "key":
                pk = None
                for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                    try:
                        pk = cls.from_private_key(io.StringIO(self.t["key"]), password=self.t["pass"] or None)
                        break
                    except Exception:
                        continue
                if not pk:
                    raise RuntimeError("cannot load SSH private key")
                kw["pkey"] = pk
            else:
                kw["password"] = self.t["pass"]
            try:
                c.connect(**kw)
            except paramiko.BadHostKeyException as e:
                raise RuntimeError(f"SSH HOST KEY CHANGED for {self.t['ip']} - possible man-in-the-middle. If the "
                                   f"host was really reinstalled, delete its line from {KNOWN_HOSTS}") from e
            self._ssh = c
        return self._ssh

    def sudo(self, cmd, timeout=900):
        self.job.check()
        if self.t["user"] == "root":
            full = f"sh -c {shlex.quote(PATHFIX + cmd)} 2>&1"
        else:
            full = f"sudo -S -p '' sh -c {shlex.quote(PATHFIX + cmd)} 2>&1"
        stdin, out, _ = self.ssh().exec_command(full, timeout=timeout)
        stdin.write((self.t["sudo_pass"] or self.t["pass"] or "") + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()
        code = out.channel.recv_exit_status()
        return code, out.read().decode("utf-8", "ignore").strip()

    def put(self, local, dest, mode="0644"):
        tmp = f"/tmp/.ufd_{uuid.uuid4().hex[:8]}"
        sf = self.ssh().open_sftp()
        try:
            sf.put(local, tmp)
        finally:
            sf.close()
        d = shlex.quote(os.path.dirname(dest))
        return self.sudo(f"install -D -m {mode} {shlex.quote(tmp)} {shlex.quote(dest)} && "
                         f"(chown --reference={d} {shlex.quote(dest)} 2>/dev/null; true); rm -f {shlex.quote(tmp)}")

    def put_text(self, text, dest, mode="0644"):
        p = os.path.join(self.job.dir, uuid.uuid4().hex)
        with open(p, "w", newline="\n") as f:
            f.write(text)
        try:
            return self.put(p, dest, mode)
        finally:
            os.remove(p)


# ───────────────────────── Windows actions ─────────────────────────
UF_WIN = r"C:\Program Files\SplunkUniversalForwarder"
TMP_WIN = r"C:\Windows\Temp\ufdeploy"


def q(s): return str(s).replace("'", "''")


@action("windows", "connectivity", "network")
def w_conn(c):
    ip, res = c.t["ip"], []
    res.append(f"ICMP: {'reply' if ping(ip) else 'no reply'}")
    st = {p: port_open(ip, p) for p in (5985, 5986, 445)}
    res += [f"{p}: {'open' if o else 'closed'}" for p, o in st.items()]
    return (st[5985] or st[5986]), "  ".join(res)


@action("windows", "uf_check", "uf")
def w_uf_check(c):
    _, out = c.ps('$s=Get-Service SplunkForwarder -EA SilentlyContinue; '
                  'if($s){"INSTALLED status="+$s.Status}else{"NOT INSTALLED"}')
    return True, out


@action("windows", "uf_install", "uf")
def w_uf_install(c):
    p, f = c.p, c.files.get("main", [])
    for k in ("share_path", "receiver", "splunk_pass"):
        if '"' in (p.get(k) or ""):  # would break out of the quoted msiexec property
            return False, f'{k} must not contain a double quote (")'
    msi = p.get("share_path", "").strip()
    if not msi:
        if not f:
            return False, "select a UF .msi file (or give a share path)"
        name = os.path.basename(f[0])
        c.step(f"copying {name} via SMB (C$)")
        c.smb_cp(f[0], r"Windows\Temp\ufdeploy" + "\\" + name)
        msi = TMP_WIN + "\\" + name
    args = f'/i "{msi}" AGREETOLICENSE=Yes LAUNCHSPLUNK=1 SERVICESTARTTYPE=auto /quiet'
    if p.get("receiver"):
        args += f' RECEIVING_INDEXER="{p["receiver"]}"'
    args += (f' SPLUNKUSERNAME=admin SPLUNKPASSWORD="{p["splunk_pass"]}"' if p.get("splunk_pass")
             else " GENRANDOMPASSWORD=1")
    c.step("running msiexec")
    _, out = c.ps(f"$r=Start-Process msiexec.exe -ArgumentList '{q(args)}' -Wait -PassThru; \"exit=\"+$r.ExitCode")
    return ("exit=0" in out or "exit=3010" in out), out


@action("windows", "uf_cfg", "uf")
def w_uf_cfg(c):
    fs = c.files.get("cfg", [])
    if not fs:
        return False, "select config files (inputs.conf, outputs.conf, ...)"
    for f in fs:
        c.step(f"pushing {os.path.basename(f)}")
        c.smb_cp(f, UF_WIN[3:] + r"\etc\system\local" + "\\" + os.path.basename(f))
    if c.p.get("restart"):
        _, out = c.ps("Restart-Service SplunkForwarder; (Get-Service SplunkForwarder).Status")
        return True, f"{len(fs)} file(s) pushed; service {out}"
    return True, f"{len(fs)} file(s) pushed"


@action("windows", "uf_service", "uf")
def w_uf_service(c):
    op = c.p.get("op", "status")
    cmd = {"start": "Start-Service", "stop": "Stop-Service", "restart": "Restart-Service"}.get(op)
    _, out = c.ps((f"{cmd} SplunkForwarder -EA Stop; " if cmd else "") +
                  "$s=Get-Service SplunkForwarder -EA SilentlyContinue; if($s){$s.Status}else{'NOT INSTALLED'}")
    return "NOT INSTALLED" not in out and "rror" not in out, out


SYS_FIND = "$s=Get-Service Sysmon64,Sysmon -EA SilentlyContinue | Select -First 1; "


@action("windows", "sysmon_check", "sysmon")
def w_sys_check(c):
    _, out = c.ps(SYS_FIND + 'if($s){"INSTALLED "+$s.Name+" "+$s.Status}else{"NOT INSTALLED"}')
    return True, out


@action("windows", "sysmon_deploy", "sysmon")
def w_sys_deploy(c):
    exe, cfg = c.files.get("main", []), c.files.get("cfg", [])
    if not cfg:
        return False, "select a Sysmon XML config"
    cn = os.path.basename(cfg[0])
    c.step("copying files")
    c.smb_cp(cfg[0], r"Windows\Temp\ufdeploy" + "\\" + cn)
    en = ""
    if exe:
        en = os.path.basename(exe[0])
        c.smb_cp(exe[0], r"Windows\Temp\ufdeploy" + "\\" + en)
    c.step("installing/updating Sysmon")
    cfgpath = TMP_WIN + "\\" + cn
    # file names go in single quotes (no $() expansion); -accepteula on update too, because the EULA flag is
    # per user and an admin who never ran Sysmon would otherwise get a prompt that blocks the WinRM call
    if en:
        fresh = f"& '{q(TMP_WIN + chr(92) + en)}' -accepteula -i $cfg 2>&1; 'INSTALLED'"
    else:
        fresh = "'NOT INSTALLED and no Sysmon binary supplied'; exit 1"
    script = (SYS_FIND + f"$cfg='{q(cfgpath)}'; "
              'if($s){ & "$env:windir\\$($s.Name).exe" -accepteula -c $cfg 2>&1; "UPDATED" } '
              'else { ' + fresh + ' }')
    code, out = c.ps(script)
    return code == 0 and ("UPDATED" in out or "INSTALLED" in out) and "supplied" not in out, out


@action("windows", "sysmon_service", "sysmon")
def w_sys_service(c):
    op = c.p.get("op", "status")
    cmd = {"start": "Start-Service", "stop": "Stop-Service", "restart": "Restart-Service"}.get(op)
    _, out = c.ps(SYS_FIND + 'if(-not $s){"NOT INSTALLED";exit 1}; ' +
                  (f"{cmd} $s.Name -EA Stop; " if cmd else "") + "(Get-Service $s.Name).Status")
    return "NOT INSTALLED" not in out and "rror" not in out, out


AUDITPOL_LINE = re.compile(r'(?i)^auditpol(\.exe)?(\s+[\w/:\\".,{}* -]+)$')


@action("windows", "audit_apply", "auditpol")
def w_audit_apply(c):
    lines = [l.strip() for l in c.p.get("commands", "").splitlines() if l.strip() and not l.startswith("#")]
    if not lines:
        return False, "enter at least one auditpol command"
    # the line runs through PowerShell, so no ; | & $ ( ) ` @ ' < > % - nothing that could chain another command
    bad = [l for l in lines if not AUDITPOL_LINE.match(l) or l.count('"') % 2]
    if bad:
        return False, "only plain auditpol commands are allowed (no ; | & $ ( ) etc.): " + bad[0]
    fails = 0
    for l in lines:
        c.step(l)
        code, out = c.ps(l)
        if code:
            fails += 1; c.log("ERROR: " + out)
    return fails == 0, f"{len(lines) - fails}/{len(lines)} commands applied"


@action("windows", "audit_report", "auditpol")
def w_audit_report(c):
    _, out = c.ps("auditpol /get /category:*")
    return True, out


# ───────────────────────── Linux actions ─────────────────────────
UF_LIN = "/opt/splunkforwarder"
SPL = f"{UF_LIN}/bin/splunk"
# Any splunk CLI call on a never-started (or freshly upgraded) UF shows the license / migration prompt and
# waits for input. Always answer non-interactively, give it no stdin and cap the run time.
SPL_FLAGS = "--accept-license --answer-yes --no-prompt"
# Read-only state check that never runs the splunk CLI (so it can't trigger license, first-run or migration).
UF_STATE = (f'if [ ! -x {SPL} ]; then echo NOT INSTALLED; exit 0; fi; '
            f'sed -n "s/^VERSION=/version /p;s/^BUILD=/build /p" {UF_LIN}/etc/splunk.version 2>/dev/null '
            f'| tr "\\n" " "; echo; '
            f'[ -e {UF_LIN}/ftr ] && echo "first start pending (license not accepted yet / UF never started)"; '
            f'if pgrep -x splunkd >/dev/null 2>&1; then echo "splunkd is running"; '
            f'else echo "splunkd is not running"; fi')


def spl(cmd, limit=600):
    return f"timeout {limit} {SPL} {cmd} {SPL_FLAGS} </dev/null 2>&1"


@action("linux", "connectivity", "network")
def l_conn(c):
    port = int(c.t["port"] or 22)
    up = port_open(c.t["ip"], port)
    msg = f"ICMP: {'reply' if ping(c.t['ip']) else 'no reply'}  tcp/{port}: {'open' if up else 'closed'}"
    if up:
        try:
            code, out = c.sudo("id -un")
            msg += f"  login OK, sudo {'OK' if code == 0 else 'FAILED'} ({out})"
            up = code == 0
        except Exception as e:
            msg += f"  login FAILED: {e}"; up = False
    return up, msg


@action("linux", "uf_check", "uf")
def l_uf_check(c):
    _, out = c.sudo(UF_STATE)
    return True, out


@action("linux", "os_detect", "network")
def l_os_detect(c):
    d = detect_distro(c)  # defined below, in "Linux distro detection"
    return True, (f"{d['name']}\n"
                  f"family: {d['family']} | id: {d['id'] or '?'} | version: {d['version'] or '?'}\n"
                  f"arch: {d['arch'] or '?'} | kernel: {d['kernel'] or '?'} | init: {d['init'] or '?'}\n"
                  f"package manager: {d['pm'] or 'none found'} | recommended UF package: "
                  f"{d['pkg'] or '.tgz'} (.tgz works everywhere)")


@action("linux", "uf_install", "uf")
def l_uf_install(c):
    f = c.files.get("main", [])
    if not f:
        return False, "select a UF package (.deb, .rpm or .tgz)"
    name = os.path.basename(f[0]).lower()
    d = detect_distro(c)
    c.log(f"detected: {d['summary']}")
    ext = ".deb" if name.endswith(".deb") else ".rpm" if name.endswith(".rpm") else ""
    if ext and d["pkg"] and ext != d["pkg"]:
        return False, (f"package type {ext} does not match this distro ({d['name']}); "
                       f"use a {d['pkg']} package or a .tgz")
    tmp = f"/tmp/ufpkg_{uuid.uuid4().hex[:6]}_{os.path.basename(f[0])}"
    arch = d["arch"]
    if (arch == "x86_64" and re.search(r"arm|aarch64", name)) or \
       (arch in ("aarch64", "arm64") and re.search(r"x86_64|amd64", name)):
        return False, f"package architecture does not match host ({arch})"
    inst = (f"DEBIAN_FRONTEND=noninteractive dpkg --force-confold -i {shlex.quote(tmp)}" if name.endswith(".deb") else
            f"rpm -Uvh --replacepkgs {shlex.quote(tmp)}" if name.endswith(".rpm") else
            f"tar -xzf {shlex.quote(tmp)} -C /opt" if name.endswith((".tgz", ".tar.gz")) else None)
    if not inst:
        return False, "unsupported package type"
    pw = c.p.get("splunk_pass") or ""
    if "\n" in pw or "\r" in pw:
        return False, "UF admin password must not contain line breaks"
    c.step("uploading package")
    sf = c.ssh().open_sftp(); sf.put(f[0], tmp); sf.close()
    c.step("installing")
    code, out = c.sudo(f"({inst}) </dev/null; rc=$?; rm -f {shlex.quote(tmp)}; exit $rc")
    if code:
        return False, out
    # Seed the admin user through user-seed.conf (consumed and deleted by splunk on first start) instead of
    # --seed-passwd, which would show the password in the target's process list. Only on a fresh install:
    # if etc/passwd exists splunk ignores the seed and would leave the clear-text file behind.
    seed = f"{UF_LIN}/etc/system/local/user-seed.conf"
    _, has_users = c.sudo(f"[ -f {UF_LIN}/etc/passwd ] && echo yes || echo no")
    if has_users.strip() == "yes":
        if pw:
            c.log("admin user already exists (upgrade/reinstall) - the supplied password was NOT applied")
    else:
        if not pw:
            pw = secrets.token_urlsafe(12)
            c.log(f"generated UF admin password (shown once): {pw}")
        c.step("seeding admin user")
        code, out = c.put_text(f"[user_info]\nUSERNAME = admin\nPASSWORD = {pw}\n", seed, mode="0600")
        if code:
            return False, out
    c.step("first start (license accepted non-interactively)")
    code, out = c.sudo(spl("start"))
    if code:
        c.sudo(f"rm -f {seed}")
        return False, out[-1500:]
    c.step("boot-start")
    code, out2 = c.sudo("if [ -f /etc/init.d/splunk ] || [ -f /etc/systemd/system/SplunkForwarder.service ]; "
                        "then echo 'boot-start already enabled'; "
                        f"else timeout 120 {SPL} enable boot-start </dev/null 2>&1; fi")
    return code == 0, (out + "\n" + out2)[-1500:]


@action("linux", "uf_cfg", "uf")
def l_uf_cfg(c):
    fs = c.files.get("cfg", [])
    if not fs:
        return False, "select config files"
    for f in fs:
        c.step(f"pushing {os.path.basename(f)}")
        code, out = c.put(f, f"{UF_LIN}/etc/system/local/{os.path.basename(f)}")
        if code:
            return False, out
    if c.p.get("restart"):
        _, out = c.sudo(spl("restart") + " | tail -3")
        return True, f"{len(fs)} file(s) pushed; {out}"
    return True, f"{len(fs)} file(s) pushed"


@action("linux", "uf_service", "uf")
def l_uf_service(c):
    op = c.p.get("op", "status")
    if op == "status":
        _, out = c.sudo(UF_STATE)
        return "NOT INSTALLED" not in out, out
    if op not in ("start", "stop", "restart"):  # op ends up in a shell command - whitelist it
        return False, f"unknown operation: {op}"
    code, out = c.sudo(f"[ -x {SPL} ] || {{ echo NOT INSTALLED; exit 1; }}; " + spl(op))
    return code == 0, out[-1500:]


PM = "for p in apt-get dnf yum zypper; do command -v $p >/dev/null 2>&1 && echo $p && break; done"
AUD_INSTALL = {
    "apt-get": "export DEBIAN_FRONTEND=noninteractive; "
               "apt-get update -qq; apt-get install -y -o Dpkg::Options::=--force-confold auditd",
    "dnf": "dnf install -y audit", "yum": "yum install -y audit",
    "zypper": "zypper --non-interactive install audit"}


@action("linux", "auditd_check", "auditd")
def l_aud_check(c):
    _, out = c.sudo("if command -v auditctl >/dev/null 2>&1; then echo INSTALLED; "
                    "systemctl is-active auditd 2>/dev/null || service auditd status 2>&1 | head -1; "
                    "else echo NOT INSTALLED; fi")
    return True, out


def normalize_rules(c, rules):
    """Expand /home/*/ per real home dir, drop unwatchable /proc/*/ paths, remove exact duplicates."""
    _, hs = c.sudo('for h in /home/*/; do [ -d "$h" ] && echo "${h%/}"; done')
    homes = [h for h in hs.splitlines() if h.startswith("/home/")]
    out, seen, dropped, expanded = [], set(), [], 0
    for l in rules:
        t = l.strip()
        if not t or t.startswith("#"):
            out.append(l); continue
        if "/proc/*/" in t:
            dropped.append(t); continue
        if "/home/*/" in t:
            if not homes:
                dropped.append(t)
            for h in homes:
                n = t.replace("/home/*/", h + "/")
                if n not in seen:
                    seen.add(n); out.append(n); expanded += 1
            continue
        if t not in seen:
            seen.add(t); out.append(l)
    return out, expanded, dropped


def apply_rules(c, text):
    rules, removed = [l.rstrip() for l in text.splitlines()], []
    rules, expanded, dropped = normalize_rules(c, rules)
    if expanded or dropped:
        c.log(f"normalized: {expanded} wildcard rule(s) expanded per user, {len(dropped)} unsupported rule(s) skipped")
    is_rule = lambda l: bool(l.strip()) and not l.strip().startswith("#")
    total = sum(1 for l in rules if is_rule(l))
    norm = lambda s: " ".join(s.split())
    c.sudo("cp -a /etc/audit/audit.rules /etc/audit/audit.rules.bak-$(date +%s) 2>/dev/null; true")
    for _ in range(len(rules) + 3):
        c.job.check()
        c.put_text("\n".join(rules) + "\n", "/etc/audit/rules.d/99-deployer.rules")
        code, out = c.sudo("augenrules --load 2>&1")
        m = re.search(r"error in line (\d+) of (\S+)", out)
        if code == 0 and not m:
            ok_n = total - len(removed)
            return True, (f"SUMMARY: total {total} rules | applied {ok_n} | failed {len(removed)}"
                          + f" | skipped {len(dropped)} | expanded {expanded}"
                          + ("\nFailed rules (removed):" + "".join(f"\n  - {r}" for r in removed)
                             if removed else ""))
        if not m:
            return False, out
        _, bad = c.sudo(f"sed -n '{int(m.group(1))}p' {shlex.quote(m.group(2))}")
        idx = next((i for i, r in enumerate(rules) if norm(r) == norm(bad)), None)
        if idx is None or not bad.strip():
            return False, f"cannot map faulty line {m.group(1)} ({bad!r}):\n{out}"
        c.log(f"ERROR rule removed: {bad.strip()}")
        removed.append(bad.strip())
        rules.pop(idx)
    return False, "too many retries"


PM_PROCS = {"apt-get": "apt|apt-get|aptitude|dpkg|unattended-upgr|packagekitd",
            "dnf": "dnf|yum|rpm|packagekitd", "yum": "yum|dnf|rpm|packagekitd",
            "zypper": "zypper|rpm|packagekitd"}


def free_pm_lock(c, pm):
    """Kill processes holding the package-manager lock (opt-in; can interrupt a running upgrade)."""
    script = (f'PIDS=$(pgrep -x "{PM_PROCS[pm]}" | tr "\\n" " "); '
              'if [ -z "$PIDS" ]; then echo "no package-manager process running"; exit 0; fi; '
              'echo "killing:"; ps -o pid,etime,args -p $(echo $PIDS | tr " " ",") 2>&1; '
              'kill $PIDS 2>/dev/null; sleep 5; kill -9 $PIDS 2>/dev/null; sleep 1; '
              + ("dpkg --configure -a 2>&1 | tail -3; " if pm == "apt-get" else "") + "exit 0")
    return c.sudo(script)[1]


@action("linux", "auditd_deploy", "auditd")
def l_aud_deploy(c):
    rf = c.files.get("cfg", [])
    _, inst = c.sudo("command -v auditctl >/dev/null 2>&1 && echo yes || echo no")
    if inst != "yes":
        if not c.p.get("install", True):
            return False, "auditd not installed (install option disabled)"
        _, pm = c.sudo(PM)
        if pm not in AUD_INSTALL:
            return False, "no supported package manager found"
        if c.p.get("kill_lock"):
            c.step("freeing package-manager lock")
            c.log(free_pm_lock(c, pm))
        c.step(f"installing auditd with {pm} (may take a while)")
        # mktemp, not a fixed /tmp name: root writing to a predictable path can be redirected by a symlink
        code, out = c.sudo(f'L=$(mktemp); ({AUD_INSTALL[pm]}) </dev/null >"$L" 2>&1; rc=$?; '
                           'tail -15 "$L"; rm -f "$L"; exit $rc')
        if code:
            return False, f"auditd install failed (exit {code}) - check repo/internet access on the target:\n{out}"
        c.sudo("systemctl enable --now auditd 2>&1 || service auditd start 2>&1")
        _, chk = c.sudo("command -v auditctl >/dev/null 2>&1 && echo yes || echo no")
        if chk != "yes":
            return False, f"package manager reported success but auditctl is missing:\n{out}"
    if not rf:
        return True, "auditd present; no rules file supplied"
    c.step("applying rules")
    with open(rf[0], encoding="utf-8", errors="ignore") as f:
        return apply_rules(c, f.read())


@action("linux", "auditd_service", "auditd")
def l_aud_service(c):
    op = c.p.get("op", "status")
    cmd = {"restart": "service auditd restart || systemctl restart auditd",
           "start": "systemctl start auditd || service auditd start",
           "stop": "service auditd stop || systemctl stop auditd",
           "status": "systemctl is-active auditd; auditctl -s 2>&1 | head -3"}[op]
    code, out = c.sudo(cmd + " 2>&1")
    return (code == 0 or op == "status"), out


# ───────────────────────── Linux distro detection ─────────────────────────
FAMILIES = {"debian": ("debian", "ubuntu", "linuxmint", "kali", "raspbian", "pop"),
            "rhel": ("rhel", "centos", "rocky", "almalinux", "fedora", "ol", "amzn", "scientific"),
            "suse": ("suse", "sles", "sled", "opensuse", "opensuse-leap", "opensuse-tumbleweed")}


def detect_distro(c):
    _, out = c.sudo(
        '. /etc/os-release 2>/dev/null; echo "ID=$ID"; echo "LIKE=$ID_LIKE"; echo "VER=$VERSION_ID"; '
        'echo "NAME=$PRETTY_NAME"; echo "ARCH=$(uname -m)"; echo "KERNEL=$(uname -r)"; '
        'echo "INIT=$(ps -p 1 -o comm= 2>/dev/null)"; '
        'for p in apt-get dnf yum zypper; do command -v $p >/dev/null 2>&1 && echo "PM=$p" && break; done; '
        '[ -f /etc/redhat-release ] && echo "RH=$(cat /etc/redhat-release)"')
    kv = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    ids = [kv.get("ID", "").lower()] + kv.get("LIKE", "").lower().split()
    fam = next((f for f, names in FAMILIES.items() if any(i in names for i in ids if i)), "")
    if not fam and kv.get("PM"):
        fam = {"apt-get": "debian", "dnf": "rhel", "yum": "rhel", "zypper": "suse"}.get(kv["PM"], "")
    pkg = {"debian": ".deb", "rhel": ".rpm", "suse": ".rpm"}.get(fam, "")
    name = kv.get("NAME") or kv.get("RH") or kv.get("ID") or "unknown"
    d = {"name": name, "id": kv.get("ID", ""), "version": kv.get("VER", ""), "family": fam or "unknown",
         "arch": kv.get("ARCH", ""), "kernel": kv.get("KERNEL", ""), "init": kv.get("INIT", ""),
         "pm": kv.get("PM", ""), "pkg": pkg}
    d["summary"] = (f"{name} | family={d['family']} | arch={d['arch']} | kernel={d['kernel']} | "
                    f"init={d['init'] or '?'} | pkg manager={d['pm'] or '?'} | "
                    f"recommended package: {pkg or '.tgz'}")
    return d


@action("linux", "distro", "system")
def l_distro(c):
    d = detect_distro(c)
    return d["family"] != "unknown", d["summary"]


# ───────────────────────── UF apps / add-ons ─────────────────────────
ARCH = (".zip", ".spl", ".tgz", ".tar.gz")


@action("windows", "uf_apps", "uf")
def w_uf_apps(c):
    fs = c.files.get("main", [])
    if not fs:
        return False, "select at least one file / add-on package"
    apps = UF_WIN + r"\etc\apps"
    _, out = c.ps(f"if(Test-Path -LiteralPath '{q(apps)}'){{'yes'}}else{{'no'}}")
    if out.strip() != "yes":
        return False, "UF apps directory not found (is UF installed?)"
    for f in fs:
        name = os.path.basename(f)
        if c.p.get("extract", True) and name.lower().endswith(ARCH):
            c.step(f"uploading and extracting {name}")
            c.smb_cp(f, r"Windows\Temp\ufdeploy" + "\\" + name)
            tmp = TMP_WIN + "\\" + name
            if name.lower().endswith(".zip"):
                ex = f"Expand-Archive -LiteralPath '{q(tmp)}' -DestinationPath '{q(apps)}' -Force"
            else:
                ex = f"& tar.exe -xzf '{q(tmp)}' -C '{q(apps)}'; if($LASTEXITCODE -ne 0){{ exit 1 }}"
            code, out = c.ps(ex + f"; Remove-Item -LiteralPath '{q(tmp)}' -Force -EA SilentlyContinue")
            if code:
                return False, f"extract failed for {name}: {out}"
        else:
            c.step(f"copying {name}")
            c.smb_cp(f, UF_WIN[3:] + r"\etc\apps" + "\\" + name)
    msg = f"{len(fs)} item(s) deployed to {apps}"
    if c.p.get("restart"):
        _, out = c.ps("Restart-Service SplunkForwarder; (Get-Service SplunkForwarder).Status")
        msg += f"; service {out}"
    return True, msg


@action("linux", "uf_apps", "uf")
def l_uf_apps(c):
    fs = c.files.get("main", [])
    if not fs:
        return False, "select at least one file / add-on package"
    apps = f"{UF_LIN}/etc/apps"
    _, out = c.sudo(f"[ -d {apps} ] && echo yes || echo no")
    if out.strip() != "yes":
        return False, "UF apps directory not found (is UF installed?)"
    for f in fs:
        name = os.path.basename(f)
        low = name.lower()
        if c.p.get("extract", True) and low.endswith(ARCH):
            c.step(f"uploading and extracting {name}")
            tmp = f"/tmp/.ufd_{uuid.uuid4().hex[:8]}_{name}"
            sf = c.ssh().open_sftp()
            try:
                sf.put(f, tmp)
            finally:
                sf.close()
            if low.endswith(".zip"):
                ex = (f"(command -v unzip >/dev/null 2>&1 && unzip -oq {shlex.quote(tmp)} -d {apps} || "
                      f"python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "
                      f"{shlex.quote(tmp)} {apps})")
            else:
                ex = f"tar -xzf {shlex.quote(tmp)} -C {apps}"
            code, out = c.sudo(f"{ex}; rc=$?; rm -f {shlex.quote(tmp)}; exit $rc")
            if code:
                return False, f"extract failed for {name}: {out}"
        else:
            c.step(f"copying {name}")
            code, out = c.put(f, f"{apps}/{name}")
            if code:
                return False, out
    c.sudo(f"chown -R --reference={apps} {apps} 2>/dev/null; true")
    msg = f"{len(fs)} item(s) deployed to {apps}"
    if c.p.get("restart"):
        _, out = c.sudo(spl("restart") + " | tail -2")
        msg += f"; {out}"
    return True, msg


# ───────────────────────── Cisco IOS / IOS-XE syslog ─────────────────────────
SAFE = re.compile(r"^[A-Za-z0-9_.:/+-]+$")
# IOS accepts abbreviations and "do <exec cmd>", so a blocklist is easy to get around; extra lines must
# instead start with one of these logging-related keywords (written out in full).
EXTRA_OK = re.compile(r"^(no\s+)?(logging|service\s+(timestamps|sequence-numbers)|login\s+on-(success|failure)|"
                      r"archive|log\s+config|notify\s+syslog|hidekeys|ntp\s+server|"
                      r"clock\s+(timezone|summer-time))(\s|$)|^exit$", re.I)
LEVELS = ["emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging"]


def build_cisco_cmds(p):
    host = (p.get("syslog_ip") or "").strip()
    if not SAFE.match(host):
        raise ValueError("invalid syslog server address")
    proto = (p.get("syslog_proto") or "udp").lower()
    port = str(p.get("syslog_port") or "514").strip()
    level = p.get("level") or "informational"
    if proto not in ("udp", "tcp"):
        raise ValueError("syslog protocol must be udp or tcp")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("invalid syslog port")
    if level not in LEVELS:
        raise ValueError("invalid log level")
    cmds = ["service timestamps log datetime msec localtime show-timezone", "logging on"]
    cmds.append(f"logging host {host}" if (proto, port) == ("udp", "514")
                else f"logging host {host} transport {proto} port {port}")
    cmds.append(f"logging trap {level}")
    for key, fmt in (("facility", "logging facility {}"), ("source_if", "logging source-interface {}")):
        v = (p.get(key) or "").strip()
        if v:
            if not SAFE.match(v):
                raise ValueError(f"invalid value for {key}")
            cmds.append(fmt.format(v))
    if p.get("origin_id"):
        cmds.append("logging origin-id hostname")
    if p.get("userinfo"):
        cmds.append("logging userinfo")
    if p.get("config_log"):
        cmds += ["archive", "log config", "logging enable", "notify syslog contenttype plaintext", "hidekeys",
                 "exit", "exit"]
    if p.get("login_log"):
        cmds += ["login on-success log", "login on-failure log"]
    if p.get("aaa_cmd"):
        g = (p.get("aaa_group") or "tacacs+").strip()
        if not SAFE.match(g):
            raise ValueError("invalid AAA group name")
        cmds += [f"aaa accounting commands 1 default start-stop group {g}",
                 f"aaa accounting commands 15 default start-stop group {g}"]
    for line in (p.get("extra") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        if not EXTRA_OK.match(line):
            raise ValueError(f"command not allowed (only logging / timestamps / archive log config / login / "
                             f"ntp / clock commands, keywords in full): {line}")
        cmds.append(line)
    return cmds


def cisco_net(c):
    if not c._net:
        from netmiko import ConnectHandler
        tel = c.p.get("conn") == "telnet"
        port = int(c.t["port"] or (23 if tel else 22))
        kw = {}
        if tel:
            c.log("WARNING: telnet sends the username and passwords in clear text")
        else:
            ssh_precheck(c.t["ip"], port, c.log)  # host key verified/saved before credentials are sent
            kw = dict(ssh_strict=True, system_host_keys=False, alt_host_keys=True, alt_key_file=KNOWN_HOSTS)
        c._net = ConnectHandler(device_type="cisco_ios_telnet" if tel else "cisco_ios", host=c.t["ip"],
                                port=port, username=c.t["user"],
                                password=c.t["pass"], secret=c.t.get("enable") or c.t["pass"],
                                timeout=30, conn_timeout=20, **kw)
        if not c._net.check_enable_mode():
            c._net.enable()
    return c._net


@action("cisco", "connectivity", "cisco")
def cs_conn(c):
    port = int(c.t["port"] or 22)
    if not port_open(c.t["ip"], port):
        return False, f"ICMP: {'reply' if ping(c.t['ip']) else 'no reply'}  tcp/{port}: closed"
    n = cisco_net(c)
    return True, f"tcp/{port} open, login OK, prompt {n.find_prompt()}\n{n.send_command('show clock')}"


@action("cisco", "preview", "cisco")
def cs_preview(c):
    cmds = build_cisco_cmds(c.p)
    return True, "configure terminal\n" + "\n".join("  " + x for x in cmds) + "\nend"


@action("cisco", "apply", "cisco")
def cs_apply(c):
    cmds = build_cisco_cmds(c.p)
    n = cisco_net(c)
    n.config_mode()
    errs = 0
    for cmd in cmds:
        c.job.check()
        out = n.send_command_timing(cmd, strip_prompt=False, strip_command=True, last_read=0.6, read_timeout=30)
        c.log(f"> {cmd}")
        bad = [l for l in out.splitlines() if l.strip().startswith("%")]
        if bad:
            errs += 1
            c.job.log(c.t["ip"], "FAIL", "  " + " / ".join(b.strip() for b in bad))
    n.exit_config_mode()
    msg = f"{len(cmds)} commands sent, {errs} error(s)"
    if c.p.get("save"):
        out = n.send_command_timing("write memory", read_timeout=60)
        if "confirm" in out.lower() or out.rstrip().endswith("?"):  # some images ask before overwriting NVRAM
            out += n.send_command_timing("\n", read_timeout=60)
        if "[OK]" in out or "Building configuration" in out:
            msg += "; configuration saved"
        else:
            c.job.log(c.t["ip"], "FAIL", "write memory: " + out.strip())
            msg += "; SAVE NOT CONFIRMED"
            errs += 1
    return errs == 0, msg


@action("cisco", "verify", "cisco")
def cs_verify(c):
    n = cisco_net(c)
    parts = []
    for cmd in ("show running-config | include ^logging|^archive|log config|^login on|^aaa accounting",
                "show logging | include Trap|Logging to|logging to"):
        parts.append(f"# {cmd}\n" + n.send_command(cmd))
    return True, "\n".join(parts)


# ───────────────────────── API ─────────────────────────
@app.post("/api/run")
async def run(os_name: str = Form(..., alias="os"), action_name: str = Form(..., alias="action"),
              params: str = Form("{}"), mode: str = Form("single"), targets: str = Form(""),
              port: str = Form(""), username: str = Form(""), password: str = Form(""),
              auth: str = Form("ntlm"), key: str = Form(""), sudo_pass: str = Form(""), enable: str = Form(""), cred: str = Form(""),
              winrm_verify: str = Form(""),
              csv_file: Optional[UploadFile] = File(None),
              main: List[UploadFile] = File(default=[]), cfg: List[UploadFile] = File(default=[])):
    if (os_name, action_name) not in ACTIONS:
        raise HTTPException(400, "unknown action")
    if cred:
        v = vault_get(cred)
        username = v.get("username") or username
        password = v.get("password") or password
        enable = v.get("enable") or enable
        key = v.get("key") or key
        sudo_pass = v.get("sudo_pass") or sudo_pass
    job = Job()
    try:
        csv_bytes = await csv_file.read() if csv_file and csv_file.filename else b""
        tl = parse_targets(mode, targets, csv_bytes, dict(port=port, user=username, **{"pass": password},
                                                         auth=auth, key=key, sudo_pass=sudo_pass, enable=enable,
                                                         verify=bool(winrm_verify)))
    except Exception as e:
        raise HTTPException(400, str(e))
    files = {}
    for grp, ups in (("main", main), ("cfg", cfg)):
        for u in ups:
            if u.filename:
                p = os.path.join(job.dir, grp + "_" + os.path.basename(u.filename))
                with open(p, "wb") as f:
                    shutil.copyfileobj(u.file, f)
                files.setdefault(grp, []).append(p)
                # keep the original name for remote files
                final = os.path.join(job.dir, grp, os.path.basename(u.filename))
                os.makedirs(os.path.dirname(final), exist_ok=True)
                shutil.move(p, final)
                files[grp][-1] = final
    JOBS[job.id] = job
    fn, svc = ACTIONS[(os_name, action_name)]
    p = json.loads(params or "{}")
    op = action_name + (":" + p["op"] if p.get("op") else "")

    def one(t):
        c = Ctx(job, t, p, files, os_name)
        try:
            job.check()
            ok, msg = fn(c)
        except Cancelled:
            ok, msg = False, "cancelled"
        except Exception as e:
            ok, msg = False, f"{type(e).__name__}: {e}"
        finally:
            c.close()
        job.log(t["ip"], "OK" if ok else "FAIL", msg)
        db_add(t["ip"], os_name, svc, op, ok, msg, OPERATOR)

    def runner():
        with ThreadPoolExecutor(WORKERS) as ex:
            list(ex.map(one, tl))
        job.done = True
        shutil.rmtree(job.dir, ignore_errors=True)

    threading.Thread(target=runner, daemon=True).start()
    return {"job": job.id, "hosts": len(tl)}


@app.get("/api/jobs/{jid}/stream")
def stream(jid: str):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404)

    def gen():
        i = 0
        while True:
            while i < len(job.lines):
                yield f"data: {json.dumps(job.lines[i])}\n\n"; i += 1
            if job.done and i >= len(job.lines):
                yield "event: end\ndata: {}\n\n"; return
            time.sleep(0.25)
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/api/jobs/{jid}/cancel")
def cancel(jid: str):
    if jid in JOBS:
        JOBS[jid].cancel.set()
    return {"ok": True}


# ───────────────────────── credential vault (encrypted) ─────────────────────────
VAULT = os.path.join(DATA, "vault.json")
TPL = os.path.join(DATA, "templates.json")
_vk = {"f": None}


def _jload(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _jsave(path, obj):
    tmp = path + ".tmp"  # write then rename, so a crash mid-write can't leave a truncated file
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _vload():
    """Vault file or None if it doesn't exist. A file that exists but can't be read is an error, never
    'no vault' - otherwise the next unlock would create a new empty vault over the old credentials."""
    if not os.path.exists(VAULT):
        return None
    try:
        with open(VAULT, encoding="utf-8") as f:
            v = json.load(f)
        v["salt"], v["check"], v["items"]
        return v
    except Exception:
        raise HTTPException(500, f"vault file is unreadable ({VAULT}); restore it from a backup or move it away")


def _fernet(pw, salt):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(pw.encode())))


def vault_get(name):
    v = _vload()
    if not _vk["f"] or not v:
        raise HTTPException(403, "vault is locked - unlock it first")
    tok = v["items"].get(name)
    if not tok:
        raise HTTPException(404, "credential not found")
    return json.loads(_vk["f"].decrypt(tok.encode()))


@app.get("/api/vault")
def vault_status():
    v = _vload()
    return {"exists": bool(v), "unlocked": _vk["f"] is not None,
            "names": sorted(v["items"]) if v and _vk["f"] else []}


@app.post("/api/vault/unlock")
def vault_unlock(body: dict = Body(...)):
    pw, v = body.get("password", ""), _vload()
    if not v:
        if len(pw) < 8:
            raise HTTPException(400, "master password must be at least 8 characters")
        salt = os.urandom(16)
        f = _fernet(pw, salt)
        v = {"salt": base64.b64encode(salt).decode(), "check": f.encrypt(b"ok").decode(), "items": {}}
        _jsave(VAULT, v)
    else:
        f = _fernet(pw, base64.b64decode(v["salt"]))
        try:
            f.decrypt(v["check"].encode())
        except Exception:
            raise HTTPException(403, "wrong master password")
    _vk["f"] = f
    return {"ok": True}


@app.post("/api/vault/lock")
def vault_lock():
    _vk["f"] = None
    return {"ok": True}


@app.post("/api/vault")
def vault_save(body: dict = Body(...)):
    v = _vload()
    name = (body.get("name") or "").strip()
    if not _vk["f"] or not v:
        raise HTTPException(403, "vault is locked")
    if not name:
        raise HTTPException(400, "name required")
    data = {k: body.get(k, "") for k in ("username", "password", "enable", "key", "sudo_pass")}
    v["items"][name] = _vk["f"].encrypt(json.dumps(data).encode()).decode()
    _jsave(VAULT, v)
    return {"ok": True}


@app.delete("/api/vault/{name}")
def vault_delete(name: str):
    v = _vload()
    if not _vk["f"] or not v:
        raise HTTPException(403, "vault is locked")
    v["items"].pop(name, None)
    _jsave(VAULT, v)
    return {"ok": True}


# ───────────────────────── Cisco syslog templates ─────────────────────────
@app.get("/api/templates")
def tpl_list():
    return _jload(TPL, {})


@app.post("/api/templates")
def tpl_save(body: dict = Body(...)):
    t = _jload(TPL, {})
    if not (body.get("name") or "").strip():
        raise HTTPException(400, "name required")
    t[body["name"].strip()] = body.get("params", {})
    _jsave(TPL, t)
    return {"ok": True}


@app.delete("/api/templates/{name}")
def tpl_delete(name: str):
    t = _jload(TPL, {})
    t.pop(name, None)
    _jsave(TPL, t)
    return {"ok": True}


def _hist(df, dt, os, service, status, q_):
    return query_history(df, dt, os, service, status, q_)


@app.get("/api/history")
def history(df: str = "", dt: str = "", os: str = "", service: str = "", status: str = "", q: str = ""):
    return [dict(zip(("ts", "ip", "os", "service", "operation", "ok", "message", "operator"), r))
            for r in _hist(df, dt, os, service, status, q)]


@app.get("/api/history.csv")
def history_csv(df: str = "", dt: str = "", os: str = "", service: str = "", status: str = "", q: str = ""):
    b = io.StringIO()
    w = csv.writer(b)
    w.writerow(["time", "target", "os", "service", "operation", "status", "operator", "message"])
    for r in _hist(df, dt, os, service, status, q):
        w.writerow([*r[:5], "success" if r[5] else "failed", r[7] or "", r[6]])
    return Response("\ufeff" + b.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=history.csv"})


@app.get("/api/history.pdf")
def history_pdf(df: str = "", dt: str = "", os: str = "", service: str = "", status: str = "", q: str = ""):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    rows = _hist(df, dt, os, service, status, q)
    st = getSampleStyleSheet()
    small = st["BodyText"].clone("s", fontSize=7, leading=9)
    summ = {}
    for r in rows:
        k = (r[2], r[3]); s = summ.setdefault(k, [0, 0]); s[0 if r[5] else 1] += 1
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    ts = lambda: TableStyle([("GRID", (0, 0), (-1, -1), .4, colors.grey),
                             ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a4d")),
                             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 7),
                             ("VALIGN", (0, 0), (-1, -1), "TOP")])
    t1 = Table([["OS", "Service", "Success", "Failed"]] + [[k[0], k[1], v[0], v[1]] for k, v in sorted(summ.items())])
    t1.setStyle(ts())
    t2 = Table([["Time", "Target", "OS", "Service", "Operation", "Status", "User", "Message"]] +
               [[r[0], r[1], r[2], r[3], r[4], "OK" if r[5] else "FAIL", r[7] or "",
                 Paragraph((r[6] or "")[:300].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), small)] for r in rows],
              colWidths=[80, 80, 45, 55, 100, 40, 55, 320], repeatRows=1)
    t2.setStyle(ts())
    doc.build([Paragraph("Deployment report", st["Title"]),
               Paragraph(time.strftime("Generated %Y-%m-%d %H:%M:%S") + f" - {len(rows)} records", st["BodyText"]),
               Spacer(1, 8), Paragraph("Summary", st["Heading2"]), t1, Spacer(1, 12),
               Paragraph("Details", st["Heading2"]), t2])
    return Response(buf.getvalue(), media_type="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=report.pdf"})


def _find_index():
    for p in (os.path.join(BASE, "static", "index.html"), os.path.join(BASE, "index.html")):
        if os.path.isfile(p):
            return p
    raise SystemExit("index.html not found: put it next to app.py or inside a 'static' folder")


with open(_find_index(), encoding="utf-8") as _f:
    INDEX_HTML = _f.read().replace("</head>", f'<meta name="ufd-token" content="{TOKEN}">\n</head>', 1)


@app.get("/")
def index():
    r = HTMLResponse(INDEX_HTML, headers={"Cache-Control": "no-store"})
    r.set_cookie("ufd", TOKEN, httponly=True, samesite="strict")
    return r

if __name__ == "__main__":
    import sys, threading as _t, uvicorn, webbrowser
    if "--no-browser" not in sys.argv:
        _t.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}")).start()
    uvicorn.run(app, host="127.0.0.1", port=PORT)
