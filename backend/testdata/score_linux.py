#!/usr/bin/env python3
"""
MEASURED OCSF-quality scorer for the LINUX family (score_win_android.py sibling).

A seeded generator emits typed records across every Linux log FORMAT
(RFC3164 / RFC5424 / journald-JSON / auditd / dmesg) and every EVENT TYPE
(auth, account, process, network, http, system). Each record carries an
*expected* OCSF spec (class, severity, whether a real event-time must exist, and
the concrete fields that must be promoted). Every sample is run through the REAL
pipeline.process() and graded on 8 independent correctness criteria. Nothing is
asserted — the "very-proper %" is the mean of per-sample scores.

Scale it toward a million:
  N_PER_TYPE=40000 python3 testdata/score_linux.py     # ~40k * 25 types = 1,000,000
Default is a fast, representative sweep.

Run:
  PARSERS_DIR=<repo>/parsers/registry python3 testdata/score_linux.py
"""
import os
import random
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
os.environ.setdefault("PARSERS_DIR", str(REPO / "parsers" / "registry"))
sys.path.insert(0, str(BACKEND))

from pipeline import process  # noqa: E402

SEED = int(os.getenv("SEED", "1337"))
random.seed(SEED)
N_PER_TYPE = int(os.getenv("N_PER_TYPE", "400"))

CANONICAL_KEYS = {
    "class_uid", "class_name", "category_uid", "category_name", "activity_id",
    "activity_name", "type_uid", "time", "timezone_offset", "severity_id",
    "severity", "status", "status_id", "message", "device", "actor",
    "src_endpoint", "dst_endpoint", "connection_info", "auth_protocol",
    "metadata", "observables", "unmapped", "raw_data", "confidence",
    "confidence_breakdown", "parse_path", "parse_stages", "parse_status",
    "ocsf_mapping_status", "needs_review",
}
# HTTP Activity (4002) legitimately carries these OCSF objects above the skeleton.
ALLOWED_CLASS_ATTRS = {4002: {"http_request", "http_response"}}

# ── entropy helpers ───────────────────────────────────────────────────────────
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
HOSTS = ["web01", "db02", "gateway", "app-node-3", "fw01", "cache-1", "mail", "k8s-worker-7"]
USERS = ["root", "admin", "deploy", "svc_backup", "jdoe", "postgres", "www-data", "ubuntu"]


def rip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))


def rport():
    return random.randint(1024, 65535)


def rts():
    return "%s %2d %02d:%02d:%02d" % (random.choice(MONTHS), random.randint(1, 28),
                                      random.randint(0, 23), random.randint(0, 59),
                                      random.randint(0, 59))


def _f(path, val, mode="eq"):
    return (path, val, mode)


# ── typed generators: each returns (raw, spec) ────────────────────────────────
# spec = dict(cls, sev, orig, fields=[(path,val,mode)...])

def t_auth_ssh_ok():
    u, ip, pt, h = random.choice(USERS), rip(), rport(), random.choice(HOSTS)
    raw = "%s %s sshd[%d]: Accepted %s for %s from %s port %d ssh2" % (
        rts(), h, random.randint(1000, 30000),
        random.choice(["password", "publickey"]), u, ip, pt)
    return raw, dict(cls=3002, sev="Informational", orig=True, fields=[
        _f("actor.user.name", u), _f("src_endpoint.ip", ip),
        _f("src_endpoint.port", pt), _f("device.hostname", h)])


def t_auth_ssh_fail():
    u, ip, pt = random.choice(USERS), rip(), rport()
    raw = "%s %s sshd[%d]: Failed password for %s%s from %s port %d ssh2" % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000),
        random.choice(["", "invalid user "]), u, ip, pt)
    return raw, dict(cls=3002, sev="Medium", orig=True, fields=[
        _f("actor.user.name", u), _f("src_endpoint.ip", ip)])


def t_auth_invalid_user():
    u, ip, pt = random.choice(USERS), rip(), rport()
    raw = "%s %s sshd[%d]: Invalid user %s from %s port %d" % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000), u, ip, pt)
    return raw, dict(cls=3002, sev="Medium", orig=True, fields=[
        _f("actor.user.name", u), _f("src_endpoint.ip", ip)])


def t_auth_pam_sshd():
    u = random.choice(USERS)
    raw = "%s %s sshd[%d]: pam_unix(sshd:session): session opened for user %s by (uid=0)" % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000), u)
    return raw, dict(cls=3002, sev="Informational", orig=True, fields=[
        _f("actor.user.name", u)])


def t_auth_pg_ok():
    u, ip = random.choice(USERS), rip()
    raw = "%s %s postgres[%d]: connection authorized: user=%s database=appdb client=%s" % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000), u, ip)
    return raw, dict(cls=3002, sev="Informational", orig=True, fields=[
        _f("actor.user.name", u), _f("src_endpoint.ip", ip)])


def t_auth_pg_fail():
    u = random.choice(USERS)
    raw = '%s %s postgres[%d]: FATAL: password authentication failed for user "%s"' % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000), u)
    return raw, dict(cls=3002, sev="Medium", orig=True, fields=[
        _f("actor.user.name", u)])


def t_account_useradd():
    u = random.choice(USERS)
    verb = random.choice([
        "new user: name=%s, UID=1001, GID=1001, home=/home/%s" % (u, u),
        "new group: name=%s, GID=1002" % u,
        "password changed for %s" % u])
    raw = "%s %s %s[%d]: %s" % (rts(), random.choice(HOSTS),
                                random.choice(["useradd", "groupadd", "passwd"]),
                                random.randint(1000, 30000), verb)
    return raw, dict(cls=3005, sev="Informational", orig=True, fields=[])


def t_proc_sudo():
    u, cmd = random.choice(USERS), random.choice(
        ["/bin/ls -la /root", "/usr/bin/apt update", "/bin/systemctl restart nginx"])
    raw = "%s %s sudo[%d]:   %s : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=%s" % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000), u, cmd)
    return raw, dict(cls=1007, sev="Informational", orig=True, fields=[
        _f("actor.process.cmd_line", cmd)])


def t_proc_cron():
    cmd = random.choice(["/usr/local/bin/backup.sh", "run-parts /etc/cron.hourly"])
    raw = "%s %s CRON[%d]: (root) CMD (%s)" % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000), cmd)
    return raw, dict(cls=1007, sev="Informational", orig=True, fields=[
        _f("actor.process.cmd_line", cmd)])


def t_proc_oom():
    proc = random.choice(["java", "python3", "node", "chrome"])
    raw = ("%s %s kernel: Out of memory: Killed process %d (%s) total-vm:%dkB, "
           "anon-rss:%dkB" % (rts(), random.choice(HOSTS), random.randint(100, 9999),
                              proc, random.randint(10 ** 5, 10 ** 7), random.randint(10 ** 4, 10 ** 6)))
    return raw, dict(cls=1007, sev="High", orig=True, fields=[
        _f("actor.process.name", proc)])


def t_net_ufw():
    src, dst, proto = rip(), rip(), random.choice(["TCP", "UDP"])
    spt, dpt = rport(), random.choice([22, 80, 443, 445, 3389])
    action = random.choice(["BLOCK", "DROP", "REJECT"])
    raw = ("%s %s kernel: [%d.%06d] [UFW %s] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e "
           "SRC=%s DST=%s LEN=60 TTL=64 PROTO=%s SPT=%d DPT=%d WINDOW=64240 SYN" % (
               rts(), random.choice(HOSTS), random.randint(1, 999999),
               random.randint(0, 999999), action, src, dst, proto, spt, dpt))
    return raw, dict(cls=4001, sev="Medium", orig=True, fields=[
        _f("src_endpoint.ip", src), _f("dst_endpoint.ip", dst),
        _f("dst_endpoint.port", dpt), _f("connection_info.protocol_name", proto)])


def t_net_synflood():
    raw = "%s %s kernel: TCP: Possible SYN flooding on port %d. Sending cookies." % (
        rts(), random.choice(HOSTS), random.choice([80, 443, 22]))
    return raw, dict(cls=4001, sev="High", orig=True, fields=[])


def t_net_fail2ban():
    ip = rip()
    raw = "%s %s fail2ban.actions[%d]: NOTICE [sshd] Ban %s" % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000), ip)
    return raw, dict(cls=4001, sev="Medium", orig=True, fields=[
        _f("src_endpoint.ip", ip)])


def t_http_access():
    ip, method, code = rip(), random.choice(["GET", "POST", "PUT"]), random.choice([200, 301, 404, 500])
    uri = random.choice(["/", "/api/v1/users", "/login", "/static/app.js"])
    raw = '%s %s nginx: %s - - [28/Aug/2026:10:00:00 +0000] "%s %s HTTP/1.1" %d 512 "-" "curl/8"' % (
        rts(), random.choice(HOSTS), ip, method, uri, code)
    sev = "Medium" if code >= 400 else "Informational"
    return raw, dict(cls=4002, sev=sev, orig=True, fields=[
        _f("src_endpoint.ip", ip), _f("http_request.http_method", method),
        _f("http_request.url.path", uri), _f("http_response.code", code)])


def t_sys_systemd():
    msg = random.choice([
        "Started Session %d of user %s." % (random.randint(1, 999), random.choice(USERS)),
        "Reached target Multi-User System.",
        "Stopped Daily apt download activities.",
        "Starting Cleanup of Temporary Directories..."])
    raw = "%s %s systemd[1]: %s" % (rts(), random.choice(HOSTS), msg)
    return raw, dict(cls=1001, sev="Informational", orig=True, fields=[
        _f("actor.process.name", "systemd")])


def t_sys_pam_cron():
    raw = "%s %s CRON[%d]: pam_unix(cron:session): session opened for user %s" % (
        rts(), random.choice(HOSTS), random.randint(1000, 30000), random.choice(USERS))
    return raw, dict(cls=1001, sev="Informational", orig=True, fields=[])


def t_sys_kernel_misc():
    msg = random.choice([
        "device eth0 entered promiscuous mode",
        "EXT4-fs (sda1): mounted filesystem with ordered data mode",
        "usb 1-1: new high-speed USB device number 4 using xhci_hcd"])
    raw = "%s %s kernel: %s" % (rts(), random.choice(HOSTS), msg)
    return raw, dict(cls=1001, sev="Informational", orig=True, fields=[])


def t_sys_apparmor():
    raw = ('%s %s kernel: audit: type=1400 apparmor="DENIED" operation="open" '
           'profile="/usr/sbin/nginx" name="/etc/shadow" pid=%d' % (
               rts(), random.choice(HOSTS), random.randint(100, 9999)))
    return raw, dict(cls=1001, sev="High", orig=True, fields=[])


def t_auditd_login():
    u, ip = random.choice(USERS), rip()
    raw = ('type=USER_LOGIN msg=audit(%d.%03d:%d): pid=%d uid=0 '
           'msg=\'op=login id=%s exe="/usr/sbin/sshd" hostname=%s addr=%s res=success\'' % (
               random.randint(1600000000, 1700000000), random.randint(0, 999),
               random.randint(1, 9999), random.randint(1, 9999), u,
               random.choice(HOSTS), ip))
    return raw, dict(cls=3002, sev="Informational", orig=True, fields=[])


def t_auditd_execve():
    cmd = random.choice(["/bin/bash", "/usr/bin/wget", "/bin/nc"])
    raw = ('type=EXECVE msg=audit(%d.%03d:%d): argc=1 a0="%s"' % (
        random.randint(1600000000, 1700000000), random.randint(0, 999),
        random.randint(1, 9999), cmd))
    return raw, dict(cls=1007, sev="Informational", orig=True, fields=[])


def t_journald_sys():
    h, u = random.choice(HOSTS), random.choice(USERS)
    raw = ('{"MESSAGE":"Started Session of user %s","PRIORITY":"6",'
           '"SYSLOG_IDENTIFIER":"systemd","_PID":"1","_HOSTNAME":"%s","_SYSTEMD_UNIT":"init.scope"}' % (u, h))
    return raw, dict(cls=1001, sev="Informational", orig=False, fields=[
        _f("device.hostname", h), _f("actor.process.name", "systemd")])


def t_journald_ssh():
    h, u, ip, pt = random.choice(HOSTS), random.choice(USERS), rip(), rport()
    raw = ('{"MESSAGE":"Accepted password for %s from %s port %d ssh2","PRIORITY":"6",'
           '"SYSLOG_IDENTIFIER":"sshd","_PID":"%d","_HOSTNAME":"%s"}' % (
               u, ip, pt, random.randint(1000, 30000), h))
    return raw, dict(cls=3002, sev="Informational", orig=False, fields=[
        _f("actor.user.name", u), _f("src_endpoint.ip", ip), _f("device.hostname", h)])


def t_rfc5424_sys():
    h, u = random.choice(HOSTS), random.choice(USERS)
    raw = ("<38>1 2026-08-28T10:00:00.000Z %s sshd %d ID47 "
           "- Accepted password for %s from %s port %d ssh2" % (
               h, random.randint(1000, 30000), u, rip(), rport()))
    return raw, dict(cls=3002, sev=None, orig=False, fields=[
        _f("actor.user.name", u)])


def t_dmesg():
    raw = "[%d.%06d] EXT4-fs (sda1): re-mounted. Opts: (null)" % (
        random.randint(1, 999999), random.randint(0, 999999))
    return raw, dict(cls=1001, sev=None, orig=False, fields=[])


GENERATORS = {
    "auth.ssh.accept": t_auth_ssh_ok,
    "auth.ssh.fail": t_auth_ssh_fail,
    "auth.ssh.invalid": t_auth_invalid_user,
    "auth.pam.sshd": t_auth_pam_sshd,
    "auth.pg.ok": t_auth_pg_ok,
    "auth.pg.fail": t_auth_pg_fail,
    "account.mgmt": t_account_useradd,
    "proc.sudo": t_proc_sudo,
    "proc.cron": t_proc_cron,
    "proc.oom": t_proc_oom,
    "net.ufw": t_net_ufw,
    "net.synflood": t_net_synflood,
    "net.fail2ban": t_net_fail2ban,
    "http.access": t_http_access,
    "sys.systemd": t_sys_systemd,
    "sys.pam.cron": t_sys_pam_cron,
    "sys.kernel.misc": t_sys_kernel_misc,
    "sys.apparmor": t_sys_apparmor,
    "auditd.login": t_auditd_login,
    "auditd.execve": t_auditd_execve,
    "journald.sys": t_journald_sys,
    "journald.ssh": t_journald_ssh,
    "rfc5424.sys": t_rfc5424_sys,
    "dmesg.kernel": t_dmesg,
}


def _get(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _match(actual, expected, mode):
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if isinstance(expected, int) and not isinstance(expected, bool):
        try:
            return int(actual) == expected
        except (TypeError, ValueError):
            return False
    a, e = str(actual), str(expected)
    if mode == "end":
        return a.endswith(e)
    if mode == "in":
        return e in a
    return a == e


def score_one(raw, spec):
    r = process(raw)
    n = r["normalized"]
    keys = set(n.keys())
    allowed = CANONICAL_KEYS | ALLOWED_CLASS_ATTRS.get(n.get("class_uid"), set())
    fields_ok = all(_match(_get(n, p), v, m) for (p, v, m) in spec["fields"])
    crit = {
        "deterministic_parse": r["path"] == "ngre",
        "canonical_complete": CANONICAL_KEYS.issubset(keys),
        "no_pollution": not (keys - allowed),
        "correct_ocsf_class": n.get("class_uid") == spec["cls"],
        "correct_severity": (spec["sev"] is None) or (n.get("severity") == spec["sev"]),
        "event_time_ok": bool(n.get("time")) and (not spec["orig"] or bool(n["metadata"].get("original_time"))),
        "lossless_raw_and_native": ((n.get("raw_data") or "").strip() == raw.strip()
                                    and "linux" in n.get("unmapped", {})),
        "correct_field_promotion": fields_ok,
    }
    return crit, sum(crit.values()), len(crit)


def main():
    print("#" * 96)
    print("# LINUX FAMILY — measured OCSF very-proper score")
    print("#   seed=%d  N_PER_TYPE=%d  types=%d  total=%d samples"
          % (SEED, N_PER_TYPE, len(GENERATORS), N_PER_TYPE * len(GENERATORS)))
    print("#" * 96)
    grand_pass = grand_crit = grand_perfect = grand_n = 0
    crit_tally = {}
    rows = []
    for name, gen in GENERATORS.items():
        tp = tc = perfect = 0
        fail_c = {}
        for _ in range(N_PER_TYPE):
            crit, passed, ncrit = score_one(*gen())
            tp += passed
            tc += ncrit
            perfect += 1 if passed == ncrit else 0
            for k, v in crit.items():
                crit_tally[k] = crit_tally.get(k, 0) + (1 if v else 0)
                if not v:
                    fail_c[k] = fail_c.get(k, 0) + 1
        pct = 100.0 * tp / tc if tc else 0.0
        ppct = 100.0 * perfect / N_PER_TYPE
        worst = ",".join("%s×%d" % (k, c) for k, c in sorted(fail_c.items(), key=lambda x: -x[1])[:2])
        rows.append((name, pct, ppct, worst))
        grand_pass += tp
        grand_crit += tc
        grand_perfect += perfect
        grand_n += N_PER_TYPE
    print("%-22s %10s %12s   %s" % ("event-type", "criteria%", "perfect%", "top misses"))
    print("-" * 96)
    for name, pct, ppct, worst in rows:
        print("%-22s %9.2f%% %11.2f%%   %s" % (name, pct, ppct, worst))
    print("-" * 96)
    gpct = 100.0 * grand_pass / grand_crit if grand_crit else 0.0
    gperf = 100.0 * grand_perfect / grand_n if grand_n else 0.0
    print("per-criterion pass (out of %d): " % grand_n)
    for k, v in crit_tally.items():
        print("   %-26s %d  (%.2f%%)" % (k, v, 100.0 * v / grand_n))
    print("=" * 96)
    print("LINUX very-proper (mean criteria) : %.3f%%   over %d samples" % (gpct, grand_n))
    print("LINUX flawless samples            : %.3f%%   (%d/%d)" % (gperf, grand_perfect, grand_n))
    print("=" * 96)
    return 0


if __name__ == "__main__":
    sys.exit(main())
