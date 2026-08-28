"""
Linux parser family — Matryoshka package (detector -> envelope -> taxonomy -> engine).

Public entry point mirrors the Windows / Android families:

    from linux import parse
    result = parse(raw_log)   # LinuxParseResult | None  (None -> pipeline falls through)

The engine converts EVERY common Linux log format (RFC3164 syslog, RFC5424,
kernel dmesg, native auditd, journald-JSON) into the shared OCSF envelope while
preserving every Linux-native field losslessly under `linux_block`.
"""
from .engine import parse, LinuxParseResult, is_linux

__all__ = ["parse", "LinuxParseResult", "is_linux"]
