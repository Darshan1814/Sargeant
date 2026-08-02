"""
Android TAXONOMY mapping.

Given an AndroidEvent, choose the OCSF class + activity based on the tag and the
Android event-log verb where present. Everything is table-driven and lossless —
fields that aren't promoted to OCSF are kept under `android.*` by the engine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .envelope import AndroidEvent

# OCSF classes reused across the framework.
CLS_SYSTEM = 1001    # System Activity
CLS_PROCESS = 1007   # Process Activity
CLS_NETWORK = 4001   # Network Activity
CLS_APP = 6005       # Application Lifecycle / Activity


@dataclass
class SemanticResult:
    ocsf_class_uid: int = CLS_APP
    activity: tuple = (0, "Unknown")
    category: str = "Application Activity"
    source_name: str = "Android logcat"
    summary: Optional[str] = None
    mapping: dict = field(default_factory=dict)


# Android activity-manager / event-log verbs → (class, activity name).
# These appear as the TAG in event logs, e.g. "am_proc_start".
_EVENT_VERBS = {
    "am_proc_start": (CLS_PROCESS, "Launch"),
    "am_proc_died":  (CLS_PROCESS, "Terminate"),
    "am_kill":       (CLS_PROCESS, "Terminate"),
    "am_create_activity": (CLS_APP, "Launch"),
    "am_finish_activity": (CLS_APP, "Terminate"),
    "am_crash":      (CLS_APP, "Crash"),
    "am_anr":        (CLS_APP, "ANR"),
    "dvm_lock_sample": (CLS_SYSTEM, "Lock"),
}

# Tag substrings that indicate a network-related event.
_NET_TAGS = ("connectivity", "netd", "wifi", "network", "dns", "socket",
             "tcp", "http", "okhttp", "volley")

# Tag substrings that indicate a process/lifecycle event.
_PROC_TAGS = ("activitymanager", "am_", "zygote", "process", "dalvikvm", "art",
              "packagemanager", "androidruntime")


def classify(ev: AndroidEvent) -> SemanticResult:
    tag = (ev.tag or "").strip()
    tag_low = tag.lower()

    # Event-log verb tags (exact match) get precise semantics.
    verb = _EVENT_VERBS.get(tag_low)
    if verb:
        cls, act = verb
        return SemanticResult(
            ocsf_class_uid=cls, activity=(1, act),
            category=("Process Activity" if cls == CLS_PROCESS else "Application Activity"),
            summary=f"{tag}: {ev.message}" if ev.message else tag,
            mapping={"tag": "actor.process.name", "pid": "actor.process.pid",
                     "tid": "windows.thread_id", "message": "message"},
        )

    if any(t in tag_low for t in _NET_TAGS):
        return SemanticResult(
            ocsf_class_uid=CLS_NETWORK, activity=(6, "Traffic"),
            category="Network Activity", summary=ev.message,
            mapping={"tag": "actor.process.name", "pid": "actor.process.pid",
                     "message": "message"},
        )

    if any(t in tag_low for t in _PROC_TAGS):
        return SemanticResult(
            ocsf_class_uid=CLS_PROCESS, activity=(0, "Process Activity"),
            category="Process Activity", summary=ev.message,
            mapping={"tag": "actor.process.name", "pid": "actor.process.pid",
                     "tid": "windows.thread_id", "message": "message"},
        )

    # Default: generic Android application activity (still fully captured).
    return SemanticResult(
        ocsf_class_uid=CLS_APP, activity=(0, "Log"),
        category="Application Activity", summary=ev.message,
        mapping={"tag": "actor.process.name", "pid": "actor.process.pid",
                 "tid": "windows.thread_id", "message": "message"},
    )
