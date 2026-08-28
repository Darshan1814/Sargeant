#!/usr/bin/env python3
"""
ULPF synthetic log generator (seeded / reproducible).

For each covered parser it writes four categories into
    <out>/generated/<parser_id>/{wellformed,variant,malformed,adversarial}.{jsonl,log}

  * wellformed  (500) — lines that match the parser's ngre_pattern exactly
  * variant     ( 50) — extra whitespace / optional field missing / alt spacing,
                        still expected to match
  * malformed   ( 20) — truncated / key-token removed / garbage; must NOT match this
                        parser -> should fall through to Drain3 (never crash)
  * adversarial ( 10) — one source's header wrapping another source's payload; used
                        to probe fingerprint header/payload mismatch handling

The canonical artifact for ingestion is the `.jsonl` file: one JSON-encoded raw
string per physical line, so multi-line records (e.g. Windows 4625 blocks) survive
line-based ingestion intact. The `.log` file is a human-readable companion.

Coverage spans all four source families:
  Windows  -> WIN-SEC-4625        (multi-line auth block, class 3002)
  macOS    -> MAC-APPFW-001       (socketfilterfw,        class 4001)
  Firewall -> FW-GENERIC-001      (iptables/UFW,          class 4001)
  Firewall -> FW-W3C-001          (pfSense filterlog,     class 4001)
  Linux    -> LINUX-SYSLOG-001    (RFC3164 syslog,        class 1001)
  Linux    -> LINUX-AUTH-001      (sshd auth,             class 3002)

Run:  python3 generate_logs.py            (host or in-container)
      SEED=1337 ULPF_TESTDATA_OUT=/app/testdata python3 generate_logs.py
"""
import json
import os
import random
import re
import sys
from pathlib import Path

# ── reproducibility ──────────────────────────────────────────────────────────
SEED = int(os.getenv("SEED", "1337"))
random.seed(SEED)

N_WELLFORMED = int(os.getenv("N_WELLFORMED", "500"))
N_VARIANT = int(os.getenv("N_VARIANT", "50"))
N_MALFORMED = int(os.getenv("N_MALFORMED", "20"))
N_ADVERSARIAL = int(os.getenv("N_ADVERSARIAL", "10"))

# ── locate registry (host: <repo>/parsers/registry ; container: /app/parsers/registry)
_HERE = Path(__file__).resolve()


def _find_registry():
    candidates = [
        Path(os.getenv("PARSERS_DIR", "")) if os.getenv("PARSERS_DIR") else None,
        _HERE.parents[2] / "parsers" / "registry",  # <repo>/parsers/registry
        Path("/app/parsers/registry"),
    ]
    for c in candidates:
        if c and c.exists():
            return c
    raise FileNotFoundError("could not locate parsers/registry")


REGISTRY = _find_registry()
OUT_ROOT = Path(os.getenv("ULPF_TESTDATA_OUT", str(_HERE.parent))) / "generated"

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
HOSTS = ["web01", "db02", "gateway", "app-node-3", "MacBook", "DC01.corp.local", "pfsense"]
USERS = ["root", "admin", "deploy", "svc_backup", "jdoe", "postgres"]
PROCS = ["sshd", "sudo", "systemd", "cron", "NetworkManager", "dbus-daemon"]


def rip():
    return "%d.%d.%d.%d" % (
        random.randint(1, 223), random.randint(0, 255),
        random.randint(0, 255), random.randint(1, 254),
    )


def rport():
    return random.randint(1024, 65535)


def rts():
    return "%s %2d %02d:%02d:%02d" % (
        random.choice(MONTHS), random.randint(1, 28),
        random.randint(0, 23), random.randint(0, 59), random.randint(0, 59),
    )


# ── well-formed generators (one raw record each) ─────────────────────────────
def g_win_sec_4625():
    return "\n".join([
        "Log Name:      Security",
        "Source:        Microsoft-Windows-Security-Auditing",
        "Event ID:      4625",
        "Level:         Information",
        "Computer:      %s" % random.choice(["DC01.corp.local", "WS-%d" % random.randint(1, 99)]),
        "An account failed to log on.",
        "  Account Name:  %s" % random.choice(USERS),
        "  Account Domain:  %s" % random.choice(["CORP", "WORKGROUP", "CONTOSO"]),
        "  Logon Type:  %d" % random.choice([2, 3, 10]),
        "  Failure Reason:  %s" % random.choice(
            ["Unknown user name or bad password", "Account locked out", "Account currently disabled"]),
        "  Source Network Address:  %s" % rip(),
    ])


def g_mac_appfw():
    verb = random.choice(["Deny", "Allow"])
    proc = random.choice(["screensharingd", "sshd-keygen-wrapper", "ARDAgent", "java", "python3"])
    return "%s %s socketfilterfw[%d] <%s>: %s %s connecting from %s" % (
        rts(), random.choice(["MacBook", "iMac-Pro"]), random.randint(100, 999),
        random.choice(["Info", "Error"]), verb, proc, rip(),
    )


def g_fw_generic():
    proto = random.choice(["TCP", "UDP"])
    return ("%s %s kernel: [%d.%06d] [UFW %s] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e "
            "SRC=%s DST=%s LEN=60 TOS=0x00 TTL=%d ID=%d PROTO=%s SPT=%d DPT=%d WINDOW=64240 SYN") % (
        rts(), random.choice(["gateway", "fw01"]), random.randint(1, 999999),
        random.randint(0, 999999), random.choice(["BLOCK", "ALLOW", "DROP"]),
        rip(), rip(), random.randint(32, 128), random.randint(1, 65535),
        proto, rport(), random.choice([22, 80, 443, 445, 3389, rport()]),
    )


def g_fw_w3c():
    proto, protoid = random.choice([("tcp", 6), ("udp", 17)])
    return ("%s %s filterlog[%d]: %d,,,%d,em0,match,%s,%s,4,0x0,,%d,%d,0,none,%d,%s,60,"
            "%s,%s,%d,%d,0,S,%d,,,,") % (
        rts(), "pfsense", random.randint(1000, 9999), random.randint(1, 200),
        random.randint(1000000000, 1999999999), random.choice(["block", "pass"]),
        random.choice(["in", "out"]), random.randint(32, 128), random.randint(1, 65535),
        protoid, proto, rip(), rip(), rport(),
        random.choice([22, 80, 443, 445, 3389, rport()]), random.randint(1, 2 ** 31),
    )


def g_linux_syslog():
    proc = random.choice(PROCS)
    msg = random.choice([
        "Started Session %d of user %s." % (random.randint(1, 999), random.choice(USERS)),
        "Reached target Multi-User System.",
        "pam_unix(cron:session): session opened for user %s" % random.choice(USERS),
        "device eth0 entered promiscuous mode",
    ])
    return "%s %s %s[%d]: %s" % (rts(), random.choice(HOSTS[:4]), proc, random.randint(1, 30000), msg)


def g_linux_auth():
    return "%s %s sshd[%d]: %s %s for %s%s from %s port %d ssh2" % (
        rts(), random.choice(HOSTS[:4]), random.randint(1000, 30000),
        random.choice(["Accepted", "Failed"]),
        random.choice(["password", "publickey"]),
        random.choice(["", "invalid user "]),
        random.choice(USERS), rip(), rport(),
    )


PARSERS = {
    "WIN-SEC-4625": g_win_sec_4625,
    "MAC-APPFW-001": g_mac_appfw,
    "FW-GENERIC-001": g_fw_generic,
    "FW-W3C-001": g_fw_w3c,
    "LINUX-SYSLOG-001": g_linux_syslog,
    "LINUX-AUTH-001": g_linux_auth,
}


# ── transforms ───────────────────────────────────────────────────────────────
def make_variant(line):
    """Whitespace / spacing tweaks that should still match (regex uses \\s+)."""
    t = random.choice(["pad", "colon", "tab"])
    if t == "pad":
        return re.sub(r" ", "  ", line, count=random.randint(1, 3))
    if t == "colon":
        return line.replace(": ", ":   ", 1)
    return line.replace(" ", "\t", 1)


def make_malformed(line, gen_name, rx=None):
    """Corrupt so the parser's key token is gone -> must fall to Drain3.

    If a compiled regex `rx` is supplied, guarantee the result does NOT match it
    (so the '100% malformed -> Drain3' expectation holds deterministically).
    """
    t = random.choice(["truncate", "strip_key", "garbage", "reorder"])

    def _corrupt(mode):
        if mode == "truncate":
            return line[: max(8, len(line) // 4)]
        if mode == "garbage":
            return "\x00\x01� " + line[:20] + " <<CORRUPT>> \x07\x1b"
        if mode == "reorder":
            toks = line.split()
            random.shuffle(toks)
            return " ".join(toks)
        # strip_key: remove the signature token for this parser
        for key in ["SRC=", "filterlog", "sshd", "socketfilterfw", "Event ID:", "kernel:"]:
            if key in line:
                return line.replace(key, "XXX", 1)
        return line[:15]

    out = _corrupt(t)
    if rx is not None and rx.search(out):
        # last resort: strip every known signature token, then truncate
        for key in ["SRC=", "DST=", "PROTO=", "filterlog", "sshd", "socketfilterfw",
                    "Event ID:", "kernel:", "Logon Type:"]:
            out = out.replace(key, "XX")
        if rx.search(out):
            out = out[: max(6, len(out) // 5)]
    return out


ADVERSARIAL_HEADERS = {
    # header claims one source, body is another source's payload
    "syslog_wraps_windows": lambda: "%s %s app[%d]: Event ID: 4625 Account Name: %s Logon Type: 3 Source Network Address: %s" % (
        rts(), random.choice(HOSTS), random.randint(1, 9999), random.choice(USERS), rip()),
    "filterlog_wraps_sshd": lambda: "%s pfsense filterlog[%d]: Accepted password for %s from %s port %d ssh2" % (
        rts(), random.randint(1, 9999), random.choice(USERS), rip(), rport()),
    "sshd_wraps_iptables": lambda: "%s %s sshd[%d]: SRC=%s DST=%s PROTO=TCP SPT=%d DPT=%d" % (
        rts(), random.choice(HOSTS), random.randint(1, 9999), rip(), rip(), rport(), rport()),
    "win_wraps_syslog": lambda: "Event ID: 4625 Computer: %s -- %s systemd[1]: Started Session 1" % (
        random.choice(HOSTS), rts()),
}


def make_adversarial():
    return random.choice(list(ADVERSARIAL_HEADERS.values()))()


# ── write helpers ────────────────────────────────────────────────────────────
def write_batch(pdir, category, records):
    pdir.mkdir(parents=True, exist_ok=True)
    with open(pdir / ("%s.jsonl" % category), "w") as jf:
        for r in records:
            jf.write(json.dumps(r) + "\n")
    with open(pdir / ("%s.log" % category), "w") as lf:
        lf.write(("\n%s\n" % ("-" * 8)).join(records))


def main():
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    summary = []
    print("=" * 74)
    print("ULPF synthetic log generator   SEED=%d" % SEED)
    print("registry: %s" % REGISTRY)
    print("output  : %s" % OUT_ROOT)
    print("counts  : wellformed=%d variant=%d malformed=%d adversarial=%d"
          % (N_WELLFORMED, N_VARIANT, N_MALFORMED, N_ADVERSARIAL))
    print("=" * 74)

    for pid, gen in PARSERS.items():
        cfg = json.loads((REGISTRY / ("%s.json" % pid)).read_text())
        rx = re.compile(cfg["ngre_pattern"], re.MULTILINE | re.DOTALL)
        pdir = OUT_ROOT / pid

        well = [gen() for _ in range(N_WELLFORMED)]
        var = [make_variant(gen()) for _ in range(N_VARIANT)]
        mal = [make_malformed(gen(), pid, rx) for _ in range(N_MALFORMED)]
        adv = [make_adversarial() for _ in range(N_ADVERSARIAL)]

        write_batch(pdir, "wellformed", well)
        write_batch(pdir, "variant", var)
        write_batch(pdir, "malformed", mal)
        write_batch(pdir, "adversarial", adv)

        # self-verification against the REAL engine regex
        well_hit = sum(1 for r in well if rx.search(r))
        var_hit = sum(1 for r in var if rx.search(r))
        mal_hit = sum(1 for r in mal if rx.search(r))
        summary.append((pid, well_hit, var_hit, mal_hit))

    print("\n%-18s %-14s %-12s %-16s" % ("parser_id", "wellformed", "variant", "malformed"))
    print("%-18s %-14s %-12s %-16s" % ("", "(want ~100%)", "(want high)", "(want ~0%)"))
    print("-" * 74)
    ok = True
    for pid, w, v, m in summary:
        wpct = 100.0 * w / max(1, N_WELLFORMED)
        vpct = 100.0 * v / max(1, N_VARIANT)
        mpct = 100.0 * m / max(1, N_MALFORMED)
        flag = "OK" if (wpct >= 95 and mpct <= 10) else "CHECK"
        if flag != "OK":
            ok = False
        print("%-18s %5d/%-3d %5.1f%%  %3d/%-3d %4.0f%%  %3d/%-3d %5.1f%%   %s"
              % (pid, w, N_WELLFORMED, wpct, v, N_VARIANT, vpct, m, N_MALFORMED, mpct, flag))
    print("-" * 74)
    total = len(PARSERS) * (N_WELLFORMED + N_VARIANT + N_MALFORMED + N_ADVERSARIAL)
    print("total lines generated: %d across %d parsers" % (total, len(PARSERS)))
    print("SELF-CHECK: %s" % ("PASS" if ok else "REVIEW NEEDED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
