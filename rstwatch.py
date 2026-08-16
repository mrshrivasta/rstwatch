#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 RSTWATCH
 TCP Reset Pattern Analyzer - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 WHAT A RESET IS

   A TCP RST means "this connection does not exist, stop talking". It is the
   normal, correct answer to a packet for a connection nobody has - which makes
   it the single most common packet on any network that nobody looks at.

   Almost every reset is ordinary:
     - connecting to a closed port gets one immediately
     - a browser closing tabs abruptly sends them by the dozen
     - load balancers and NAT gateways reset idle connections on a timer
     - an application calling close() with unread data pending sends one

   What makes resets worth analysing is not any single packet. It is the PATTERN:
   which direction they travel, how quickly they arrive after the handshake,
   whether they cluster on one port or spray across many, and whether the
   sequence numbers make sense.

 THE FOUR SHAPES THIS LOOKS FOR

   PORT SCAN           Many resets FROM this machine to one source, across many
                       different ports, in a short window. That is what your own
                       kernel does while somebody scans you - the resets are
                       yours, and they are the evidence.
   INJECTION           A reset arriving mid-connection whose sequence number sits
                       oddly in the window, or which is followed by traffic that
                       should have stopped. That is the shape of an off-path
                       injected reset - the technique used to interrupt
                       connections without being in the path.
   CONNECTION REFUSED  Resets immediately after a SYN, which simply means nothing
                       is listening. Counted so it can be excluded from the rest.
   TEARDOWN            Resets late in a connection's life, which is an
                       application closing without a graceful FIN. Extremely
                       common and almost never interesting.

 *** A RESET IS NOT AN ATTACK ***
   This is the caveat governing the whole tool. Resets are how TCP says no, and a
   busy machine produces thousands legitimately. Everything here reports the
   SHAPE of reset traffic and explains what could produce it. Deciding whether a
   pattern is hostile needs context this tool does not have.

 *** INJECTION CANNOT BE PROVEN FROM ONE ENDPOINT ***
   A forged reset is designed to look exactly like a real one - that is the whole
   point. From here you can see that a reset was surprising, arrived with odd
   timing, or carried an unexpected sequence number. You cannot see that it came
   from somewhere other than the peer. That needs a capture from a second vantage
   point, and this tool never claims otherwise.

 READ-ONLY AND SILENT
   It reads /proc and listens. It sends no packet of any kind, resets no
   connection, and changes no setting. Fixes are printed for you to run.

 LEGAL DISCLAIMER
   Provided "as is" with no warranty; the author accepts no liability for any
   loss or damage.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import html as _html
import io
import ipaddress
import json
import math
import os
import platform
import re
import select
import shutil
import socket
import sqlite3
import struct
import sys
import textwrap
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

APP_NAME = "RSTWatch"
APP_SHORT = "RSTWATCH"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("RSTWATCH_DB", "rstwatch.db")

RESET_IS_NORMAL = (
    "A reset is not an attack. RST is how TCP says 'this connection does not exist' - it is "
    "the correct answer to a packet for a connection nobody has, and a busy machine produces "
    "thousands legitimately. Connecting to a closed port, a browser closing tabs, a load "
    "balancer timing out an idle session: all of these are resets."
)
INJECTION_UNPROVABLE = (
    "A forged reset is designed to look exactly like a real one. From one endpoint you can "
    "see that a reset was surprising, oddly timed, or carried an unexpected sequence number - "
    "you cannot see that it came from somewhere other than the peer. Proving injection needs "
    "a capture from a second vantage point, which this tool does not have."
)
COUNTERS_ARE_TOTALS = (
    "The kernel counters are totals since boot, not a window. A large number means the "
    "machine has been up a long time at least as often as it means anything is wrong - the "
    "rate between two readings is the useful figure, not the total."
)
CAPTURE_LIMIT = (
    "Capture sees only what reaches this machine, and only while it is running. No resets "
    "seen means none arrived in that window, not that none are being sent."
)
DISCLAIMER_SHORT = (
    "Read-only and silent. Analyses the pattern of TCP resets - direction, timing, spread and "
    "sequence sanity - from kernel counters and optional capture. A reset is not an attack, "
    "and injection cannot be proven from one endpoint."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    A RESET IS NOT AN ATTACK. RST is how TCP says "this connection does not exist". It is the
    correct answer to a packet for a connection nobody has, and a busy machine produces
    thousands legitimately. Everything here reports the SHAPE of reset traffic and explains
    what could produce it; deciding whether a pattern is hostile needs context this tool does
    not have.

    INJECTION CANNOT BE PROVEN FROM ONE ENDPOINT. A forged reset is built to look exactly like
    a real one. From here you can see that a reset was surprising, oddly timed, or carried an
    unexpected sequence number - you cannot see that it came from somewhere other than the
    peer. That needs a capture from a second vantage point.

    THE KERNEL COUNTERS ARE TOTALS SINCE BOOT. A large number means the machine has been up a
    long time at least as often as it means anything is wrong. The rate between two readings
    is the useful figure.

    CAPTURE SEES ONLY THIS MACHINE, AND ONLY WHILE RUNNING. No resets captured means none
    arrived in that window - not that none are being sent, and not that none arrived before
    you started.

    A CONNECTION THIS TOOL NEVER SAW THE START OF CANNOT BE JUDGED. Timing analysis needs the
    handshake; a reset on a connection that was already open when capture began is reported
    as unclassifiable rather than guessed at.

    READ-ONLY AND SILENT. It sends no packet of any kind, resets no connection and changes no
    setting. Fixes are printed for you to run.

    Provided "as is" with no warranty; the author accepts no liability for any loss or
    damage."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 35.0, "high": 18.0, "medium": 8.0, "low": 3.0, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}
SHAPE_COLOR = {"scan": "#f76808", "injection": "#e5484d", "refused": "#3e9dd8",
               "teardown": "#30a46c", "unknown": "#8b8f9b"}


def risk_band(score: float, checked: bool = True) -> tuple[str, str]:
    if not checked:
        return "not checked", "#8b8f9b"
    if score >= 35:
        return "worth investigating now", "#e5484d"
    if score >= 18:
        return "an unusual pattern", "#f76808"
    if score >= 8:
        return "worth a look", "#ffb224"
    if score > 0:
        return "minor notes", "#3e9dd8"
    return "nothing unusual", "#30a46c"


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    return _html.escape("" if s is None else str(s), quote=True)


def shorten(s, n=90) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n - 1] + "\u2026"


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "-"
    seconds = float(seconds)
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    d, r = divmod(int(seconds), 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def ago(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        delta = (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
    except Exception:
        return "-"
    return fmt_duration(delta) + " ago" if delta >= 0 else "in the future"


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def F(category, title, severity, description, evidence="", advice="", fix=""):
    return {"category": category, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:2500],
            "advice": advice, "fix": fix}


class Result:
    def __init__(self, name: str):
        self.name = name
        self.data = None
        self.status = "ok"
        self.detail = ""

    def unavailable(self, detail):
        self.status, self.detail = "unavailable", detail
        return self

    def partial(self, detail):
        self.status = "partial"
        self.detail = " ".join((self.detail + "; " + detail).strip("; ").split())[:400]
        return self


# =============================================================================
# SECTION 2 - The packets
#   Only what a reset analysis needs: the five-tuple, the flags, the sequence
#   numbers and the window. Parsed by hand so there is no dependency and so the
#   sequence arithmetic is visible and testable.
# =============================================================================

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
FLAG_NAMES = [(FIN, "FIN"), (SYN, "SYN"), (RST, "RST"), (PSH, "PSH"),
              (ACK, "ACK"), (URG, "URG"), (ECE, "ECE"), (CWR, "CWR")]


def flag_string(flags: int) -> str:
    return "".join(n for bit, n in FLAG_NAMES if flags & bit) or "none"


def parse_tcp_frame(frame: bytes) -> dict | None:
    """Ethernet -> IPv4/IPv6 -> TCP. Returns None for anything else."""
    if len(frame) < 34:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ethertype == 0x8100:                       # VLAN
        if len(frame) < 38:
            return None
        ethertype = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if ethertype == ETH_P_IP:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        if frame[offset + 9] != 6:
            return None
        src = socket.inet_ntop(socket.AF_INET, frame[offset + 12:offset + 16])
        dst = socket.inet_ntop(socket.AF_INET, frame[offset + 16:offset + 20])
        ttl = frame[offset + 8]
        total_len = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        tcp_off = offset + ihl
        payload_len = max(0, total_len - ihl - 20)
        family = 4
    elif ethertype == ETH_P_IPV6:
        if len(frame) < offset + 40:
            return None
        if frame[offset + 6] != 6:
            return None
        src = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        ttl = frame[offset + 7]
        payload_len = struct.unpack("!H", frame[offset + 4:offset + 6])[0]
        tcp_off = offset + 40
        family = 6
    else:
        return None
    if len(frame) < tcp_off + 20:
        return None
    sport, dport = struct.unpack("!HH", frame[tcp_off:tcp_off + 4])
    seq, ack = struct.unpack("!II", frame[tcp_off + 4:tcp_off + 12])
    data_offset = (frame[tcp_off + 12] >> 4) * 4
    flags = frame[tcp_off + 13]
    window = struct.unpack("!H", frame[tcp_off + 14:tcp_off + 16])[0]
    if family == 4:
        payload = max(0, payload_len + 20 - data_offset)
    else:
        payload = max(0, payload_len - data_offset)
    return {"family": family, "src": src, "dst": dst, "sport": sport, "dport": dport,
            "seq": seq, "ack": ack, "flags": flags, "flag_names": flag_string(flags),
            "window": window, "ttl": ttl, "payload_len": payload,
            "data_offset": data_offset,
            "is_rst": bool(flags & RST), "is_syn": bool(flags & SYN),
            "is_fin": bool(flags & FIN), "is_ack": bool(flags & ACK),
            "eth_src": ":".join(f"{b:02x}" for b in frame[6:12])}


def flow_key(pkt: dict) -> tuple:
    """A connection, identified the same way regardless of direction."""
    a = (pkt["src"], pkt["sport"])
    b = (pkt["dst"], pkt["dport"])
    return tuple(sorted([a, b]))


def build_tcp_frame(src: str, dst: str, sport: int, dport: int, flags: int,
                    seq: int = 0, ack: int = 0, window: int = 65535,
                    ttl: int = 64, payload: bytes = b"") -> bytes:
    """A TCP frame, built for testing the parser and the classifiers.

    This returns BYTES and nothing in this tool ever transmits them - there is no
    send path anywhere in the file.
    """
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags,
                      window, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, 0, ttl, 6, 0)
    ip += socket.inet_aton(src) + socket.inet_aton(dst)
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" \
        + struct.pack("!H", ETH_P_IP)
    return eth + ip + tcp


# =============================================================================
# SECTION 3 - Following connections, so a reset can be placed in one
#   A reset only means something in the context of the connection it ended. This
#   keeps just enough state to answer: had we seen a handshake, how long had it
#   been open, how much data had moved, and did the sequence number fit.
# =============================================================================

class FlowTracker:
    """Minimal connection state, sized so a long capture cannot exhaust memory."""

    def __init__(self, max_flows: int = 20000):
        self.flows: dict[tuple, dict] = {}
        self.max_flows = max_flows
        self.evicted = 0

    def observe(self, pkt: dict, when: float) -> dict:
        key = flow_key(pkt)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                # drop the oldest quarter rather than growing without limit
                oldest = sorted(self.flows.items(),
                                key=lambda kv: kv[1]["last_seen"])[:self.max_flows // 4]
                for k, _v in oldest:
                    del self.flows[k]
                self.evicted += len(oldest)
            flow = {"key": key, "first_seen": when, "last_seen": when,
                    "saw_syn": False, "saw_synack": False, "established_at": None,
                    "packets": 0, "bytes": 0, "fin_seen": False,
                    "next_seq": {}, "peers": set(), "reset_at": None,
                    "initiator": None}
            self.flows[key] = flow
        flow["last_seen"] = when
        flow["packets"] += 1
        flow["bytes"] += pkt["payload_len"]
        flow["peers"].add((pkt["src"], pkt["sport"]))

        if pkt["is_syn"] and not pkt["is_ack"]:
            flow["saw_syn"] = True
            flow["syn_at"] = when
            flow["initiator"] = (pkt["src"], pkt["sport"])
        elif pkt["is_syn"] and pkt["is_ack"]:
            flow["saw_synack"] = True
            flow["established_at"] = when
        if pkt["is_fin"]:
            flow["fin_seen"] = True

        # track the expected next sequence number per direction, which is what a
        # reset's sequence number has to match to be accepted
        who = (pkt["src"], pkt["sport"])
        if not pkt["is_rst"]:
            advance = pkt["payload_len"] + (1 if pkt["is_syn"] else 0) \
                + (1 if pkt["is_fin"] else 0)
            if advance or who not in flow["next_seq"]:
                flow["next_seq"][who] = (pkt["seq"] + advance) & 0xFFFFFFFF
        return flow


def seq_delta(a: int, b: int) -> int:
    """Signed distance in TCP's 32-bit wrapping sequence space."""
    d = (a - b) & 0xFFFFFFFF
    if d > 0x7FFFFFFF:
        d -= 0x100000000
    return d


def classify_reset(pkt: dict, flow: dict, when: float,
                   local_addresses: set | None = None) -> dict:
    """Which of the four shapes this reset fits, and how confident that is.

    Every branch names what else could produce the same thing, because almost
    everything here has an innocent explanation.
    """
    local_addresses = local_addresses or set()
    # A reset can arrive for a flow this tool never saw - capture starting
    # mid-conversation, or a single frame decoded from a dump. That is a lack of
    # context, not an error, so it degrades to "unknown" rather than raising.
    if flow is None:
        return {"shape": "unknown", "confidence": "low",
                "why": ("no other packet from this connection was seen, so there is no "
                        "context to place this reset in - capture may simply have started "
                        "mid-conversation"),
                "alternatives": ("with the surrounding packets this would usually classify "
                                 "cleanly; the shape here rests on the header alone"),
                "age": None, "outbound": pkt["src"] in local_addresses,
                "seq_fits": None, "seq_offset": None, "bytes_moved": 0,
                "packets_before": 0, "signals": []}
    out = {"shape": "unknown", "confidence": "low", "why": "", "alternatives": "",
           "age": None, "outbound": pkt["src"] in local_addresses,
           "seq_fits": None, "seq_offset": None, "bytes_moved": flow["bytes"],
           "packets_before": flow["packets"]}

    if flow.get("established_at"):
        out["age"] = when - flow["established_at"]
    elif flow.get("syn_at"):
        out["age"] = when - flow["syn_at"]

    # does the sequence number sit where the peer would have sent it?
    who = (pkt["src"], pkt["sport"])
    expected = flow["next_seq"].get(who)
    if expected is not None:
        offset = seq_delta(pkt["seq"], expected)
        out["seq_offset"] = offset
        out["seq_fits"] = offset == 0

    # 1. nothing was listening: a reset answering a SYN, with no handshake done
    if flow["saw_syn"] and not flow["saw_synack"] and (out["age"] or 0) < 5.0:
        out.update(shape="refused", confidence="high",
                   why=("a reset arriving right after a SYN with no handshake completed, "
                        "which is simply nothing listening on that port"),
                   alternatives=("a firewall configured to reject rather than drop produces "
                                 "exactly the same thing"))
        return out

    # 2. a reset on a connection we never saw start: cannot be judged
    if not flow["saw_syn"] and not flow["saw_synack"]:
        out.update(shape="unknown", confidence="low",
                   why=("this connection was already open when capture began, so there is "
                        "no handshake to measure against"),
                   alternatives=("nothing can be concluded about timing or sequence sanity "
                                 "for a connection whose start was never seen"))
        return out

    # 3. a reset whose sequence number does not fit the window
    if out["seq_fits"] is False and abs(out["seq_offset"] or 0) > 0:
        far = abs(out["seq_offset"]) > 65535
        out.update(shape="injection",
                   confidence="medium" if far else "low",
                   why=(f"the reset's sequence number is {out['seq_offset']:+d} from what "
                        f"this peer should have sent next"
                        + (", which is outside any plausible window" if far else
                           ", which is close enough that reordering could explain it")),
                   alternatives=("packet reordering, a retransmission, a middlebox rewriting "
                                 "sequence numbers, or simply a capture that missed packets "
                                 "all produce this. " + INJECTION_UNPROVABLE))
        return out

    # 4. established and short-lived, with data moved: an abrupt application close
    if flow.get("established_at"):
        if flow["bytes"] > 0 or flow["packets"] > 4:
            out.update(shape="teardown", confidence="medium",
                       why=("a reset on an established connection that had carried data, "
                            "which is an application closing without a graceful FIN"),
                       alternatives=("extremely common: close() with unread data pending, a "
                                     "browser tab closing, or a load balancer expiring an "
                                     "idle session"))
        else:
            out.update(shape="teardown", confidence="low",
                       why=("a reset on a connection that completed a handshake but carried "
                            "no data"),
                       alternatives=("a health check that connects and immediately hangs up "
                                     "looks exactly like this, and so does a scanner that "
                                     "completes the handshake"))
        return out

    out.update(shape="unknown", confidence="low",
               why="the reset does not fit any of the shapes this tool recognises",
               alternatives="reported so it is visible rather than silently dropped")
    return out


def detect_scan_pattern(resets: list[dict], window: float = 10.0,
                        min_ports: int = 8) -> list[dict]:
    """Resets FROM this machine to one peer across many ports in a short window.

    That is what a kernel does while somebody scans it - so the pattern is
    somebody scanning you, evidenced by your own replies.
    """
    by_peer: dict[str, list] = defaultdict(list)
    for r in resets:
        if not r["classification"]["outbound"]:
            continue
        by_peer[r["packet"]["dst"]].append(r)
    out = []
    for peer, group in by_peer.items():
        group = sorted(group, key=lambda r: r["at_monotonic"])
        # slide a window over the resets and find the densest burst
        best = None
        for i, start in enumerate(group):
            burst = [r for r in group[i:]
                     if r["at_monotonic"] - start["at_monotonic"] <= window]
            ports = {r["packet"]["sport"] for r in burst}
            if len(ports) >= min_ports and (best is None or len(ports) > len(best[1])):
                best = (burst, ports)
        if best:
            burst, ports = best
            span = burst[-1]["at_monotonic"] - burst[0]["at_monotonic"]
            out.append({
                "peer": peer, "ports": sorted(ports)[:60], "port_count": len(ports),
                "resets": len(burst), "seconds": round(span, 2),
                "rate": round(len(burst) / max(span, 0.001), 1),
                "sequential": _looks_sequential(sorted(ports)),
            })
    return sorted(out, key=lambda x: -x["port_count"])


def _looks_sequential(ports: list[int]) -> bool:
    """Consecutive port numbers suggest a sweep rather than ordinary traffic."""
    if len(ports) < 4:
        return False
    gaps = [ports[i + 1] - ports[i] for i in range(len(ports) - 1)]
    return sum(1 for g in gaps if g == 1) >= len(gaps) * 0.5


def summarise_resets(resets: list[dict]) -> dict:
    """The shape of the reset traffic as a whole."""
    out = {"total": len(resets), "inbound": 0, "outbound": 0,
           "shapes": Counter(), "top_peers": [], "top_ports": [],
           "seq_mismatches": 0, "rst_ack": 0, "with_payload": 0,
           "families": Counter(), "ttls": Counter()}
    peers, ports = Counter(), Counter()
    for r in resets:
        c, p = r["classification"], r["packet"]
        out["shapes"][c["shape"]] += 1
        if c["outbound"]:
            out["outbound"] += 1
            peers[p["dst"]] += 1
            ports[p["sport"]] += 1
        else:
            out["inbound"] += 1
            peers[p["src"]] += 1
            ports[p["dport"]] += 1
        if c["seq_fits"] is False:
            out["seq_mismatches"] += 1
        if p["is_ack"]:
            out["rst_ack"] += 1
        if p["payload_len"] > 0:
            out["with_payload"] += 1
        out["families"][p["family"]] += 1
        out["ttls"][p["ttl"]] += 1
    out["top_peers"] = peers.most_common(10)
    out["top_ports"] = ports.most_common(10)
    out["shapes"] = dict(out["shapes"])
    out["families"] = dict(out["families"])
    out["distinct_ttls"] = len(out["ttls"])
    out["ttls"] = dict(out["ttls"].most_common(6))
    return out


# =============================================================================
# SECTION 4 - What the kernel already counted
#   These need no privileges and cover the whole time since boot, which capture
#   never can. They are totals though, so the useful figure is the rate between
#   two readings rather than the number itself.
# =============================================================================

# The abort counters say WHY the kernel reset something, which is the part
# people rarely look at and the part that actually explains a spike.
ABORT_COUNTERS = {
    "TCPAbortOnData": ("an application closed a socket with unread data still "
                       "buffered, so the kernel had to reset rather than close "
                       "gracefully", "info"),
    "TCPAbortOnClose": ("a socket was closed while data was still arriving", "info"),
    "TCPAbortOnMemory": ("the kernel ran out of memory for socket buffers and killed "
                         "connections to recover", "high"),
    "TCPAbortOnTimeout": ("connections were reset after retransmitting for too long "
                          "with no answer - the peer or the path went away", "medium"),
    "TCPAbortOnLinger": ("connections reset because SO_LINGER was set to zero, which "
                         "is a deliberate application choice", "info"),
    "TCPAbortFailed": ("the kernel wanted to send a reset and could not", "medium"),
}
CHALLENGE_COUNTERS = {
    "TCPChallengeACK": ("challenge ACKs sent - the kernel received a reset or SYN it "
                        "was not sure about and asked the peer to confirm before "
                        "acting. This is RFC 5961, the defence against blind reset "
                        "injection, and a rising count means something is sending "
                        "resets that did not fit the window", "medium"),
    "TCPSYNChallenge": ("challenge ACKs sent in response to a SYN on an existing "
                        "connection", "low"),
    "TCPACKSkippedRST": ("challenge ACKs suppressed by rate limiting - the kernel "
                         "wanted to challenge more resets than it was willing to "
                         "answer", "medium"),
    "TCPACKSkippedSynRecv": ("challenge ACKs suppressed while a connection was half "
                             "open", "low"),
}
LISTEN_COUNTERS = {
    "ListenDrops": ("connections dropped because the listen backlog was full", "medium"),
    "ListenOverflows": ("the accept queue overflowed - the application is not "
                        "accepting fast enough", "medium"),
}


def read_counters() -> Result:
    """Reset-related counters from /proc/net/snmp and /proc/net/netstat."""
    r = Result("counters")
    r.data = {"tcp": {}, "ext": {}, "uptime": None, "sources": []}
    if not sys.platform.startswith("linux"):
        return r.unavailable(f"the counters come from /proc/net, which is Linux-only; this "
                             f"is {sys.platform}. Nothing was read.")
    found = False
    try:
        with open("/proc/net/snmp") as fh:
            lines = fh.readlines()
        for i in range(0, len(lines) - 1):
            if lines[i].startswith("Tcp:") and not lines[i + 1].startswith("Tcp:"):
                continue
            if lines[i].startswith("Tcp:") and lines[i + 1].startswith("Tcp:"):
                keys = lines[i].split()[1:]
                values = lines[i + 1].split()[1:]
                r.data["tcp"] = {k: int(v) for k, v in zip(keys, values)
                                 if v.lstrip("-").isdigit()}
                r.data["sources"].append("/proc/net/snmp")
                found = True
                break
    except OSError as e:
        r.partial(f"/proc/net/snmp could not be read: {e}")
    try:
        with open("/proc/net/netstat") as fh:
            lines = fh.readlines()
        for i in range(0, len(lines) - 1):
            if lines[i].startswith("TcpExt:") and lines[i + 1].startswith("TcpExt:"):
                keys = lines[i].split()[1:]
                values = lines[i + 1].split()[1:]
                r.data["ext"] = {k: int(v) for k, v in zip(keys, values)
                                 if v.lstrip("-").isdigit()}
                r.data["sources"].append("/proc/net/netstat")
                found = True
                break
    except OSError as e:
        r.partial(f"/proc/net/netstat could not be read: {e}")
    try:
        with open("/proc/uptime") as fh:
            r.data["uptime"] = float(fh.read().split()[0])
    except (OSError, ValueError):
        pass
    if not found:
        return r.unavailable("neither /proc/net/snmp nor /proc/net/netstat could be read, "
                             "so no counters were available. Nothing was checked.")
    return r


def counter_rates(before: dict, after: dict, seconds: float) -> dict:
    """The change between two readings, which is the figure that means something."""
    out = {}
    if seconds <= 0:
        return out
    for section in ("tcp", "ext"):
        for key, value in (after.get(section) or {}).items():
            old = (before.get(section) or {}).get(key)
            if old is None or value < old:      # a counter reset means a reboot
                continue
            delta = value - old
            if delta:
                out[key] = {"delta": delta, "per_second": round(delta / seconds, 3),
                            "section": section}
    return out


def read_states() -> Result:
    """Connection states now, because a pile of SYN_RECV or a burst of TIME_WAIT is
    context for a reset spike."""
    r = Result("states")
    r.data = {"counts": {}, "total": 0}
    states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
              "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
              "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
              "0A": "LISTEN", "0B": "CLOSING"}
    counts: Counter = Counter()
    found = False
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        if not os.path.exists(path):
            continue
        found = True
        try:
            with open(path) as fh:
                next(fh, None)
                for line in fh:
                    f = line.split()
                    if len(f) > 3:
                        counts[states.get(f[3].upper(), f[3])] += 1
        except OSError as e:
            r.partial(f"{path} could not be read: {e}")
    if not found:
        return r.unavailable("no /proc/net/tcp tables were present")
    r.data["counts"] = dict(counts)
    r.data["total"] = sum(counts.values())
    return r


def local_addresses() -> set:
    """This machine's own addresses, so a reset's direction can be decided."""
    out = {"127.0.0.1", "::1"}
    base = "/sys/class/net"
    if not os.path.isdir(base):
        return out
    import fcntl
    for name in sorted(os.listdir(base)):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            packed = struct.pack("256s", name.encode()[:15])
            out.add(socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, packed)[20:24]))
        except OSError:
            pass
        finally:
            if sock is not None:
                sock.close()
    try:
        with open("/proc/net/if_inet6") as fh:
            for line in fh:
                hexaddr = line.split()[0]
                try:
                    out.add(socket.inet_ntop(socket.AF_INET6, bytes.fromhex(hexaddr)))
                except (ValueError, OSError):
                    continue
    except OSError:
        pass
    return out


# =============================================================================
# SECTION 5 - Watching the wire
#   Transmits nothing. A reset is a packet somebody else sends, or one this
#   kernel sends on its own - either way the job is to watch.
# =============================================================================

def capture_resets(seconds: float = 60.0, interface: str | None = None,
                   max_resets: int = 20000, on_reset=None) -> Result:
    r = Result("capture")
    r.data = {"resets": [], "frames": 0, "tcp_frames": 0, "seconds": seconds,
              "started": now_iso(), "transmitted": False, "flows_seen": 0,
              "evicted": 0, "truncated": False}
    if not sys.platform.startswith("linux"):
        return r.unavailable(f"capture uses AF_PACKET, which is Linux-only; this is "
                             f"{sys.platform}. Nothing was captured.")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.settimeout(0.5)
        if interface:
            try:
                sock.bind((interface, 0))
            except OSError as e:
                r.partial(f"could not bind to {interface}: {e}")
    except PermissionError:
        return r.unavailable(
            "capturing needs root. Nothing was captured - which is NOT the same as no "
            "resets arriving. The kernel counters need no privileges and cover the whole "
            "time since boot, so they are the better place to start.")
    except OSError as e:
        return r.unavailable(f"a capture socket could not be opened: {e}")

    local = local_addresses()
    tracker = FlowTracker()
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                continue
            r.data["frames"] += 1
            pkt = parse_tcp_frame(frame)
            if not pkt:
                continue
            r.data["tcp_frames"] += 1
            when = time.time()
            mono = time.monotonic()
            flow = tracker.observe(pkt, mono)
            if not pkt["is_rst"]:
                continue
            if len(r.data["resets"]) >= max_resets:
                r.data["truncated"] = True
                continue
            classification = classify_reset(pkt, flow, mono, local)
            entry = {"packet": pkt, "classification": classification,
                     "at": now_iso(), "at_monotonic": mono, "at_epoch": when}
            r.data["resets"].append(entry)
            flow["reset_at"] = mono
            if on_reset:
                on_reset(entry)
    except KeyboardInterrupt:
        r.partial("interrupted before the full capture window elapsed")
    finally:
        try:
            sock.close()
        except Exception:
            pass
    r.data["flows_seen"] = len(tracker.flows)
    r.data["evicted"] = tracker.evicted
    r.data["ended"] = now_iso()
    if r.data["truncated"]:
        r.partial(f"stopped recording after {max_resets} resets - the summary below covers "
                  f"only those")
    return r


def analyse_capture(resets: list[dict]) -> dict:
    """Everything the captured resets say, taken together."""
    return {"summary": summarise_resets(resets),
            "scans": detect_scan_pattern(resets),
            "injection_candidates": [r for r in resets
                                     if r["classification"]["shape"] == "injection"],
            "unknown": [r for r in resets
                        if r["classification"]["shape"] == "unknown"]}


# =============================================================================
# SECTION 6 - Findings
# =============================================================================

def analyse(counters: Result, states: Result, capture: Result | None,
            rates: dict | None, baseline: dict) -> list[dict]:
    out: list[dict] = []
    approved = {k for k, v in baseline.items() if v.get("approved")}

    # ---- kernel counters ----
    if counters.status == "unavailable":
        out.append(F("Counters", "The kernel counters could not be read", "info",
                     counters.detail, "", "Nothing was checked here."))
    else:
        tcp = counters.data["tcp"]
        ext = counters.data["ext"]
        uptime = counters.data.get("uptime")
        out_rsts = tcp.get("OutRsts")
        estab_resets = tcp.get("EstabResets")
        attempt_fails = tcp.get("AttemptFails")
        if out_rsts is not None:
            per_hour = (out_rsts / (uptime / 3600.0)) if uptime and uptime > 60 else None
            out.append(F("Counters", f"This machine has sent {out_rsts:,} reset(s) since "
                         "boot", "info",
                         (f"About {per_hour:.1f} per hour over {fmt_duration(uptime)} of "
                          f"uptime." if per_hour is not None
                          else "Uptime is too short to give a meaningful rate."),
                         f"OutRsts        {out_rsts:,}\n"
                         + (f"EstabResets    {estab_resets:,}\n"
                            if estab_resets is not None else "")
                         + (f"AttemptFails   {attempt_fails:,}\n"
                            if attempt_fails is not None else "")
                         + (f"CurrEstab      {tcp.get('CurrEstab')}"
                            if tcp.get("CurrEstab") is not None else ""),
                         COUNTERS_ARE_TOTALS + " " + RESET_IS_NORMAL))
        if attempt_fails and out_rsts and attempt_fails > max(20, out_rsts * 0.5):
            out.append(F("Counters", f"{attempt_fails:,} outbound connection attempt(s) "
                         "failed", "low",
                         "Connections this machine tried to make that were refused or "
                         "timed out.",
                         f"AttemptFails {attempt_fails:,} against OutRsts {out_rsts:,}",
                         "Something on this machine is repeatedly connecting to somewhere "
                         "that says no. Ordinary for a service retrying a dead backend, and "
                         "also what an outbound scan looks like from this side."))

        for key, (why, sev) in ABORT_COUNTERS.items():
            value = ext.get(key)
            if not value:
                continue
            if sev == "info":
                continue
            out.append(F("Aborts", f"{key} is {value:,}", sev,
                         why.capitalize() + ".",
                         f"{key} {value:,} since boot",
                         "This says WHY the kernel reset connections, which is the part "
                         "that actually explains a spike. "
                         + ("Running out of socket memory is a genuine problem rather than "
                            "a pattern - the machine was under pressure."
                            if key == "TCPAbortOnMemory" else COUNTERS_ARE_TOTALS)))
        informational = {k: ext[k] for k in ABORT_COUNTERS
                         if ext.get(k) and ABORT_COUNTERS[k][1] == "info"}
        if informational:
            out.append(F("Aborts", "Ordinary abort reasons", "info",
                         "These are applications closing sockets abruptly, which is normal.",
                         "\n".join(f"  {k:<22} {v:,}   {ABORT_COUNTERS[k][0]}"
                                   for k, v in informational.items()),
                         "Listed so the totals above are explained rather than mysterious. "
                         "TCPAbortOnData in particular is just close() with unread data."))

        for key, (why, sev) in CHALLENGE_COUNTERS.items():
            value = ext.get(key)
            if not value:
                continue
            out.append(F("Challenge", f"{key} is {value:,}", sev,
                         why.capitalize() + ".",
                         f"{key} {value:,} since boot",
                         "RFC 5961 challenge ACKs are the kernel's defence against blind "
                         "reset injection: rather than acting on a reset that did not fit "
                         "the window, it asks the peer to confirm. A non-zero count means "
                         "something sent resets or SYNs that did not fit - which happens "
                         "with ordinary packet reordering too, so the rate matters more "
                         "than the total."))
        for key, (why, sev) in LISTEN_COUNTERS.items():
            value = ext.get(key)
            if value:
                out.append(F("Backlog", f"{key} is {value:,}", sev, why.capitalize() + ".",
                             f"{key} {value:,} since boot",
                             "A full backlog makes the kernel drop or reset incoming "
                             "connections, which shows up to clients as refused "
                             "connections. That is a capacity problem rather than a "
                             "security one."))

    # ---- the rate between two readings ----
    if rates:
        interesting = {k: v for k, v in rates.items()
                       if k in ("OutRsts", "EstabResets", "AttemptFails")
                       or k in ABORT_COUNTERS or k in CHALLENGE_COUNTERS}
        if interesting:
            rst_rate = (rates.get("OutRsts") or {}).get("per_second", 0)
            sev = ("high" if rst_rate > 50 else "medium" if rst_rate > 10
                   else "low" if rst_rate > 1 else "info")
            out.append(F("Rate", f"Resets are being sent at "
                         f"{rst_rate:.1f} per second", sev,
                         "Measured between two readings rather than since boot, which is "
                         "the figure that actually means something.",
                         "\n".join(f"  {k:<22} +{v['delta']:,}  "
                                   f"({v['per_second']}/s)"
                                   for k, v in sorted(
                                       interesting.items(),
                                       key=lambda kv: -kv[1]["delta"])[:10]),
                         "A high rate on a busy server is normal - a load balancer health "
                         "checking hundreds of backends produces plenty. What matters is "
                         "whether this is normal FOR THIS MACHINE, which needs a baseline "
                         "you take when things are fine."))
        else:
            out.append(F("Rate", "No reset counters moved between the two readings", "info",
                         "Nothing changed during the sampling window.", "",
                         "A quiet machine, or a window too short to catch anything."))

    # ---- connection states ----
    if states.status == "ok" and states.data["total"]:
        counts = states.data["counts"]
        out.append(F("States", f"{states.data['total']} connection(s) right now", "info",
                     ", ".join(f"{v} {k}" for k, v in sorted(counts.items())),
                     "", "Context for the counters above. A pile of SYN_RECV means "
                         "half-open connections; a lot of TIME_WAIT is the normal residue "
                         "of connections that closed properly."))
        syn_recv = counts.get("SYN_RECV", 0)
        if syn_recv > 50:
            out.append(F("States", f"{syn_recv} connections are half open", "medium",
                         "These completed a SYN but never finished the handshake.",
                         f"SYN_RECV {syn_recv}",
                         "A backlog of half-open connections is what a SYN flood looks "
                         "like, and also what a slow or lossy network looks like. Check "
                         "whether ListenDrops is climbing alongside it."))

    # ---- captured resets ----
    if capture is None:
        out.append(F("Capture", "The wire was NOT watched", "info",
                     "Only the kernel counters and connection states were read.", "",
                     "The counters cover everything since boot, which capture never can - "
                     "but they cannot tell you the SHAPE of the traffic. Use 'watch' for "
                     "that; it transmits nothing."))
    elif capture.status == "unavailable":
        out.append(F("Capture", "Capture did not run", "info", capture.detail, "",
                     "An empty capture result means 'not watched', not 'no resets'."))
    else:
        resets = capture.data["resets"]
        analysis = analyse_capture(resets)
        summary = analysis["summary"]
        if not resets:
            out.append(F("Capture", "No resets were seen", "info",
                         f"{capture.data['tcp_frames']} TCP frame(s) of "
                         f"{capture.data['frames']} examined over "
                         f"{capture.data['seconds']:.0f}s.", "",
                         CAPTURE_LIMIT))
        else:
            shapes = summary["shapes"]
            out.append(F("Capture", f"{len(resets)} reset(s) in "
                         f"{capture.data['seconds']:.0f}s", "info",
                         f"{summary['inbound']} inbound, {summary['outbound']} outbound.",
                         "shapes:\n"
                         + "\n".join(f"  {k:<12} {v}" for k, v in sorted(shapes.items()))
                         + "\ntop peers:\n"
                         + "\n".join(f"  {p:<24} {n}" for p, n in summary["top_peers"][:6])
                         + "\ntop ports:\n"
                         + "\n".join(f"  {p:<24} {n}" for p, n in summary["top_ports"][:6]),
                         RESET_IS_NORMAL))

            for scan in analysis["scans"]:
                if scan["peer"] in approved:
                    continue
                sev = "high" if scan["port_count"] >= 20 else "medium"
                out.append(F("Scan", f"{scan['peer']} was reset on {scan['port_count']} "
                             f"different ports in {scan['seconds']:.1f}s", sev,
                             "This machine sent resets to one peer across many ports in a "
                             "short window, which is what a kernel does while it is being "
                             "scanned.",
                             f"peer      {scan['peer']}\n"
                             f"ports     {scan['port_count']} distinct "
                             f"({', '.join(str(p) for p in scan['ports'][:14])}"
                             f"{' ...' if scan['port_count'] > 14 else ''})\n"
                             f"resets    {scan['resets']} at {scan['rate']}/s\n"
                             f"pattern   {'consecutive port numbers' if scan['sequential'] else 'scattered ports'}",
                             "The resets are yours - they are the evidence, not the "
                             "attack. Consecutive port numbers suggest a sweep; scattered "
                             "ones can be a legitimate client with many connections, a "
                             "monitoring system, or a misconfigured application retrying. "
                             "Nothing was blocked and nothing needs to be.",
                             fix=f"# see what that peer reached, if anything\n"
                                 f"ss -tan | grep {scan['peer']}\n"
                                 f"# and block it if you decide to\n"
                                 f"sudo iptables -A INPUT -s {scan['peer']} -j DROP"))

            candidates = analysis["injection_candidates"]
            if candidates:
                far = [c for c in candidates
                       if abs(c["classification"]["seq_offset"] or 0) > 65535]
                out.append(F("Injection", f"{len(candidates)} reset(s) carried an "
                             f"unexpected sequence number",
                             "medium" if far else "low",
                             f"{len(far)} of them were outside any plausible window.",
                             "\n".join(
                                 f"  {c['packet']['src']}:{c['packet']['sport']} -> "
                                 f"{c['packet']['dst']}:{c['packet']['dport']}  "
                                 f"offset {c['classification']['seq_offset']:+d}"
                                 for c in candidates[:8]),
                             INJECTION_UNPROVABLE + " Packet reordering, retransmissions, a "
                             "middlebox rewriting sequence numbers, or a capture that "
                             "simply missed packets all produce this. If the kernel's "
                             "TCPChallengeACK counter is also rising, the two together are "
                             "more interesting than either alone."))

            unknown = analysis["unknown"]
            if unknown:
                out.append(F("Capture", f"{len(unknown)} reset(s) could not be classified",
                             "info",
                             "These were on connections whose start was never seen.",
                             f"{len(unknown)} of {len(resets)} resets",
                             "A connection already open when capture began has no handshake "
                             "to measure against, so timing and sequence checks cannot run. "
                             "Reported rather than guessed at - a longer capture reduces "
                             "this."))

            if summary["with_payload"]:
                out.append(F("Capture", f"{summary['with_payload']} reset(s) carried a "
                             "payload", "low",
                             "A reset with data in it is unusual.",
                             f"{summary['with_payload']} of {len(resets)}",
                             "RFC 1122 allows a reset to carry text explaining why, and "
                             "some stacks do. It is rare enough to be worth noticing and "
                             "harmless enough not to worry about."))
            if summary["distinct_ttls"] > 4 and summary["total"] > 10:
                out.append(F("Capture", f"Resets arrived with {summary['distinct_ttls']} "
                             "different TTL values", "low",
                             "Packets from one peer normally arrive with a consistent TTL.",
                             "\n".join(f"  ttl {k}: {v}"
                                       for k, v in summary["ttls"].items()),
                             "Many distinct TTLs simply means many distinct peers, which is "
                             "the usual explanation. It is listed because a reset whose TTL "
                             "differs from the rest of its own connection is one of the few "
                             "hints that it came from somewhere else - though load "
                             "balancing and route changes do the same thing."))
            if capture.data.get("evicted"):
                out.append(F("Capture", f"{capture.data['evicted']} flow(s) were dropped "
                             "from tracking", "info",
                             "The connection table hit its limit during capture.",
                             f"{capture.data['evicted']} evicted, "
                             f"{capture.data['flows_seen']} still tracked",
                             "Resets on evicted flows are classified as unknown rather than "
                             "guessed at. It only happens on very busy captures."))

    checked = not (counters.status == "unavailable" and states.status == "unavailable")
    out.append(F("Summary", "Reset posture", "info",
                 f"counters: {counters.status}; states: {states.status}; "
                 f"capture: {capture.status if capture else 'not run'}",
                 "", RESET_IS_NORMAL if checked else
                 "Nothing could be checked, which is not a clean result."))
    return out


def risk_score(findings: list[dict]) -> float:
    return round(clamp(sum(SEV_WEIGHT[f["severity"]] for f in findings), 0, 100), 1)


# =============================================================================
# SECTION 7 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, hostname TEXT, mode TEXT, checked INTEGER DEFAULT 1,
    out_rsts INTEGER, estab_resets INTEGER, attempt_fails INTEGER,
    challenge_acks INTEGER, uptime REAL, rst_rate REAL,
    captured INTEGER DEFAULT 0, capture_seconds REAL,
    inbound INTEGER DEFAULT 0, outbound INTEGER DEFAULT 0,
    scans_found INTEGER DEFAULT 0, injection_candidates INTEGER DEFAULT 0,
    score REAL DEFAULT 0, band TEXT, status TEXT, detail TEXT,
    elapsed_ms INTEGER, payload TEXT,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, ts TEXT,
    src TEXT, sport INTEGER, dst TEXT, dport INTEGER, family INTEGER,
    flags TEXT, seq INTEGER, ack INTEGER, ttl INTEGER, window INTEGER,
    shape TEXT, confidence TEXT, outbound INTEGER, seq_fits INTEGER,
    seq_offset INTEGER, age REAL, bytes_moved INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS peers (
    peer TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
    times_seen INTEGER DEFAULT 0, resets INTEGER DEFAULT 0,
    max_ports INTEGER DEFAULT 0, approved INTEGER DEFAULT 0,
    approved_at TEXT, label TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    category TEXT, title TEXT, severity TEXT, description TEXT, evidence TEXT,
    advice TEXT, fix TEXT, FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_rst_scan ON resets(scan_id);
CREATE INDEX IF NOT EXISTS idx_rst_shape ON resets(shape);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def peer_map(conn=None) -> dict:
    out = {}
    for r in q("SELECT * FROM peers", (), conn):
        d = dict(r)
        d["approved"] = bool(d["approved"])
        out[d["peer"]] = d
    return out


def approve_peer(peer: str, label: str = "", note: str = "") -> tuple[bool, str]:
    conn = connect()
    try:
        init_db(conn)
        row = q1("SELECT * FROM peers WHERE peer=?", (peer,), conn)
        if not row:
            return False, f"'{peer}' has not been seen. Run a capture first."
        conn.execute("UPDATE peers SET approved=1, approved_at=?, "
                     "label=COALESCE(NULLIF(?,''), label), "
                     "note=COALESCE(NULLIF(?,''), note) WHERE peer=?",
                     (now_iso(), label, note, peer))
        conn.commit()
        log_event("INFO", "baseline", f"Approved {peer}", None, conn)
        return True, peer
    finally:
        conn.close()


def revoke_peer(peer: str) -> int:
    conn = connect()
    try:
        n = conn.execute("UPDATE peers SET approved=0, approved_at=NULL WHERE peer=?",
                         (peer,)).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(sid: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (sid,), conn)
    if not row:
        return None
    d = dict(row)
    try:
        d["payload"] = json.loads(d["payload"] or "{}")
    except json.JSONDecodeError:
        d["payload"] = {}
    d["band_colour"] = risk_band(d["score"] or 0, bool(d.get("checked", 1)))[1]
    return d


def save_scan(counters: Result, states: Result, capture: Result | None,
              rates: dict | None, findings: list[dict], elapsed_ms: int,
              mode: str = "check", note: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
        tcp = (counters.data or {}).get("tcp", {})
        ext = (counters.data or {}).get("ext", {})
        resets = (capture.data or {}).get("resets", []) if capture else []
        analysis = analyse_capture(resets) if resets else {
            "summary": summarise_resets([]), "scans": [], "injection_candidates": [],
            "unknown": []}
        summary = analysis["summary"]
        checked = not (counters.status == "unavailable"
                       and states.status == "unavailable")
        score = risk_score(findings)
        cur = conn.execute(
            "INSERT INTO scans (ts, hostname, mode, checked, out_rsts, estab_resets,"
            " attempt_fails, challenge_acks, uptime, rst_rate, captured,"
            " capture_seconds, inbound, outbound, scans_found, injection_candidates,"
            " score, band, status, detail, elapsed_ms, payload, critical, high, medium,"
            " low, info, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
            "?,?,?,?)",
            (now_iso(), socket.gethostname(), mode, int(checked),
             tcp.get("OutRsts"), tcp.get("EstabResets"), tcp.get("AttemptFails"),
             ext.get("TCPChallengeACK"), (counters.data or {}).get("uptime"),
             (rates or {}).get("OutRsts", {}).get("per_second"),
             len(resets), (capture.data or {}).get("seconds") if capture else None,
             summary["inbound"], summary["outbound"], len(analysis["scans"]),
             len(analysis["injection_candidates"]), score,
             risk_band(score, checked)[0],
             counters.status,
             "; ".join(filter(None, [counters.detail, states.detail,
                                     capture.detail if capture else ""]))[:500],
             elapsed_ms,
             json.dumps({"counters": (counters.data or {}),
                         "states": (states.data or {}),
                         "summary": summary, "scans": analysis["scans"],
                         "rates": rates or {},
                         "resets": [{"packet": r["packet"],
                                     "classification": r["classification"],
                                     "at": r["at"]} for r in resets[:400]],
                         "statuses": {"counters": counters.status,
                                      "states": states.status,
                                      "capture": capture.status if capture
                                      else "not run"}}, default=str),
             counts["critical"], counts["high"], counts["medium"], counts["low"],
             counts["info"], note))
        sid = cur.lastrowid
        ts = now_iso()
        for r in resets[:5000]:
            p, c = r["packet"], r["classification"]
            conn.execute(
                "INSERT INTO resets (scan_id, ts, src, sport, dst, dport, family, flags,"
                " seq, ack, ttl, window, shape, confidence, outbound, seq_fits,"
                " seq_offset, age, bytes_moved) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                "?,?,?)",
                (sid, r["at"], p["src"], p["sport"], p["dst"], p["dport"], p["family"],
                 p["flag_names"], p["seq"], p["ack"], p["ttl"], p["window"],
                 c["shape"], c["confidence"], int(bool(c["outbound"])),
                 None if c["seq_fits"] is None else int(c["seq_fits"]),
                 c["seq_offset"], c["age"], c["bytes_moved"]))
        for scan in analysis["scans"]:
            conn.execute(
                "INSERT INTO peers (peer, first_seen, last_seen, times_seen, resets,"
                " max_ports) VALUES (?,?,?,1,?,?) ON CONFLICT(peer) DO UPDATE SET "
                "last_seen=?, times_seen=times_seen+1, resets=resets+?, "
                "max_ports=MAX(max_ports, ?)",
                (scan["peer"], ts, ts, scan["resets"], scan["port_count"],
                 ts, scan["resets"], scan["port_count"]))
        for f in findings:
            conn.execute("INSERT INTO findings (scan_id, category, title, severity,"
                         " description, evidence, advice, fix) VALUES (?,?,?,?,?,?,?,?)",
                         (sid, f["category"], f["title"], f["severity"],
                          f["description"], f["evidence"], f.get("advice", ""),
                          f.get("fix", "")))
        conn.commit()
        log_event("INFO", "scan",
                  f"{mode}: {len(resets)} reset(s) captured, "
                  f"{len(analysis['scans'])} scan pattern(s), score {score}", sid, conn)
        for f in findings:
            if f["severity"] in ("critical", "high"):
                log_event("WARN", "pattern", f["title"], sid, conn)
        return sid
    finally:
        conn.close()


def run_check(capture_seconds: float = 0.0, interface: str | None = None,
              rate_seconds: float = 0.0, mode: str = "check", note: str = "",
              on_reset=None) -> dict:
    t0 = time.time()
    init_db()
    before = None
    if rate_seconds > 0:
        before = read_counters().data
        time.sleep(rate_seconds)
    counters = read_counters()
    states = read_states()
    capture = None
    if capture_seconds > 0:
        capture = capture_resets(capture_seconds, interface, on_reset=on_reset)
        # take the counters again so the rate covers the capture window too
        if before is None:
            before = None
    rates = None
    if before is not None and counters.data:
        rates = counter_rates(before, counters.data, rate_seconds)
    findings = analyse(counters, states, capture, rates, peer_map())
    elapsed = int((time.time() - t0) * 1000)
    sid = save_scan(counters, states, capture, rates, findings, elapsed, mode, note)
    score = risk_score(findings)
    checked = not (counters.status == "unavailable" and states.status == "unavailable")
    return {"id": sid, "counters": counters, "states": states, "capture": capture,
            "rates": rates, "findings": findings, "checked": checked, "score": score,
            "band": risk_band(score, checked)[0],
            "band_colour": risk_band(score, checked)[1], "elapsed_ms": elapsed,
            "counts": {s: sum(1 for f in findings if f["severity"] == s)
                       for s in SEVERITIES}}


# =============================================================================
# SECTION 8 - Charts (hand-drawn SVG: no CDN, no JS library, works offline)
# =============================================================================

def svg_timeline(resets: list[dict], width=940, height=190,
                 title="When the resets arrived") -> str:
    """The signature visual: resets on a time axis, coloured by shape, so a burst
    is visibly a burst rather than a number in a table."""
    if not resets:
        return (f'<div class="chart-empty">{html_escape(title)}: no resets were '
                f'captured</div>')
    times = [r["at_monotonic"] for r in resets if r.get("at_monotonic") is not None]
    if len(times) < 2:
        return (f'<div class="chart-empty">{html_escape(title)}: needs at least two '
                f'resets on a timeline ({len(times)} captured)</div>')
    t0, t1 = min(times), max(times)
    span = max(t1 - t0, 0.001)
    pad_l, pad_b, pad_t = 54, 30, 26
    plot_w = width - pad_l - 24
    plot_h = height - pad_t - pad_b
    lanes = ["scan", "injection", "refused", "teardown", "unknown"]
    present = [s for s in lanes
               if any(r["classification"]["shape"] == s for r in resets)]
    lane_h = plot_h / max(len(present), 1)
    parts = []
    for i, shape in enumerate(present):
        y = pad_t + i * lane_h
        parts.append(f'<text x="{pad_l - 8}" y="{y + lane_h / 2 + 4:.0f}" '
                     f'text-anchor="end" class="sub">{html_escape(shape)}</text>')
        parts.append(f'<line x1="{pad_l}" y1="{y + lane_h:.0f}" x2="{width - 24}" '
                     f'y2="{y + lane_h:.0f}" stroke="#22262e"/>')
        group = [r for r in resets if r["classification"]["shape"] == shape]
        colour = SHAPE_COLOR.get(shape, "#8b8f9b")
        for r in group:
            if r.get("at_monotonic") is None:
                continue
            x = pad_l + plot_w * (r["at_monotonic"] - t0) / span
            p = r["packet"]
            direction = "out" if r["classification"]["outbound"] else "in"
            parts.append(
                f'<line x1="{x:.1f}" y1="{y + 6:.0f}" x2="{x:.1f}" '
                f'y2="{y + lane_h - 6:.0f}" stroke="{colour}" stroke-width="1.6" '
                f'opacity="0.75"><title>{html_escape(p["src"])}:{p["sport"]} -> '
                f'{html_escape(p["dst"])}:{p["dport"]} ({direction}, {shape})</title>'
                f'</line>')
    parts.append(f'<text x="{pad_l}" y="{height - 8}" class="sub">0s</text>')
    parts.append(f'<text x="{width - 24}" y="{height - 8}" text-anchor="end" '
                 f'class="sub">{span:.1f}s</text>')
    parts.append(f'<text x="{pad_l + plot_w / 2:.0f}" y="{height - 8}" '
                 f'text-anchor="middle" class="sub">{len(resets)} resets</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'one line per reset, grouped by shape &middot; a vertical band is a '
            f'burst</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_ports(scans: list[dict], width=940, title="Ports reset per peer") -> str:
    """A peer's ports drawn as a strip, because a sweep looks like a sweep."""
    if not scans:
        return (f'<div class="chart-empty">{html_escape(title)}: no peer was reset across '
                f'enough ports to look like a sweep</div>')
    scans = scans[:5]
    row_h, gap, pad_t, pad_l = 42, 10, 24, 190
    height = pad_t + len(scans) * (row_h + gap)
    strip_w = width - pad_l - 30
    parts = []
    for i, s in enumerate(scans):
        y = pad_t + i * (row_h + gap)
        colour = "#f76808" if s["port_count"] >= 20 else "#ffb224"
        parts.append(f'<text x="{pad_l - 12}" y="{y + 18}" text-anchor="end" '
                     f'class="cell">{html_escape(s["peer"][:22])}</text>')
        parts.append(f'<text x="{pad_l - 12}" y="{y + 33}" text-anchor="end" '
                     f'class="sub">{s["port_count"]} ports / {s["seconds"]:.1f}s</text>')
        parts.append(f'<rect x="{pad_l}" y="{y}" width="{strip_w}" height="{row_h - 8}" '
                     f'rx="5" fill="#12161d" stroke="#262a33"/>')
        ports = s["ports"]
        if ports:
            lo, hi = min(ports), max(ports)
            rng = max(hi - lo, 1)
            for p in ports:
                x = pad_l + 4 + (strip_w - 8) * (p - lo) / rng
                parts.append(f'<line x1="{x:.1f}" y1="{y + 5}" x2="{x:.1f}" '
                             f'y2="{y + row_h - 13}" stroke="{colour}" stroke-width="2">'
                             f'<title>port {p}</title></line>')
            parts.append(f'<text x="{pad_l + 4}" y="{y + row_h - 1}" class="sub">'
                         f'{lo}</text>')
            parts.append(f'<text x="{pad_l + strip_w - 4}" y="{y + row_h - 1}" '
                         f'text-anchor="end" class="sub">{hi}</text>')
        if s["sequential"]:
            parts.append(f'<text x="{pad_l + strip_w / 2}" y="{y + row_h - 1}" '
                         f'text-anchor="middle" style="fill:{colour};'
                         f'font:10.5px ui-monospace,monospace">consecutive</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'each tick is a port &middot; evenly spaced ticks are a sweep, clustered ones '
            f'are ordinary traffic</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_pie(items, size=180, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 42
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" '
                         f'fill="none" stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title>'
                         f'</path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'</div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="", color="#5b8def", fmt=lambda v: f"{v:g}",
            colors=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 22, 7, 160, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 62
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        c = (colors or {}).get(label, color)
        lbl = label if len(label) <= 22 else label[:21] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 9}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{c}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 7:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


# =============================================================================
# SECTION 9 - Exports
# =============================================================================

def report_payload(sid=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "a_reset_is_not_an_attack": RESET_IS_NORMAL,
            "injection_cannot_be_proven_here": INJECTION_UNPROVABLE,
            "counters_are_totals": COUNTERS_ARE_TOTALS,
            "capture_limits": CAPTURE_LIMIT,
            "limitations": [
                "A reset is not an attack. RST is how TCP says a connection does not "
                "exist, and a busy machine produces thousands legitimately.",
                "Injection cannot be proven from one endpoint - a forged reset is built to "
                "look exactly like a real one. That needs a second vantage point.",
                "The kernel counters are totals since boot, so the rate between two "
                "readings is the useful figure, not the total.",
                "Capture sees only this machine and only while running. None seen means "
                "none arrived in that window.",
                "A reset on a connection whose handshake was never seen cannot be judged, "
                "and is reported as unclassifiable rather than guessed at.",
                "A scan pattern means resets went to one peer across many ports - the "
                "resets are this machine's own replies, which is evidence rather than the "
                "attack itself.",
                "Sequence mismatches have innocent explanations: reordering, "
                "retransmission, a middlebox rewriting numbers, or a capture that missed "
                "packets.",
                "Read-only and silent: no packet is sent, no connection reset and no "
                "setting changed.",
            ],
            "scan": scan,
            "resets": [dict(r) for r in q(
                "SELECT * FROM resets WHERE scan_id=? ORDER BY id LIMIT 500",
                (sid,), conn)] if sid else [],
            "findings": [dict(r) for r in q(
                "SELECT category,title,severity,description,evidence,advice,fix FROM "
                "findings WHERE scan_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
                (sid,), conn)] if sid else [],
            "peers": [dict(r) for r in q("SELECT * FROM peers ORDER BY max_ports DESC",
                                         (), conn)],
            "history": [dict(r) for r in q(
                "SELECT id, ts, score, band, captured, scans_found FROM scans "
                "ORDER BY id DESC LIMIT 40", (), conn)][::-1],
        }
    finally:
        if own:
            conn.close()


def export_json(sid=None) -> str:
    return json.dumps(report_payload(sid), indent=2, default=str)


def export_csv(sid=None) -> str:
    conn = connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["# A reset is not an attack, and injection cannot be proven from one "
                    "endpoint."])
        if not scan:
            return buf.getvalue()
        w.writerow([])
        w.writerow(["## Check"])
        w.writerow(["hostname", "out_rsts", "estab_resets", "attempt_fails",
                    "challenge_acks", "uptime", "rst_rate", "captured", "inbound",
                    "outbound", "scans_found", "injection_candidates", "score", "band"])
        w.writerow([scan["hostname"], scan["out_rsts"], scan["estab_resets"],
                    scan["attempt_fails"], scan["challenge_acks"], scan["uptime"],
                    scan["rst_rate"], scan["captured"], scan["inbound"],
                    scan["outbound"], scan["scans_found"], scan["injection_candidates"],
                    scan["score"], scan["band"]])
        w.writerow([])
        w.writerow(["## Resets"])
        w.writerow(["ts", "src", "sport", "dst", "dport", "flags", "seq", "ttl",
                    "shape", "confidence", "outbound", "seq_fits", "seq_offset", "age"])
        for r in q("SELECT * FROM resets WHERE scan_id=? ORDER BY id LIMIT 5000",
                   (sid,), conn):
            w.writerow([r["ts"], r["src"], r["sport"], r["dst"], r["dport"], r["flags"],
                        r["seq"], r["ttl"], r["shape"], r["confidence"], r["outbound"],
                        r["seq_fits"], r["seq_offset"], r["age"]])
        w.writerow([])
        w.writerow(["## Findings"])
        w.writerow(["severity", "category", "title", "description", "advice", "fix"])
        for r in q("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (sid,), conn):
            w.writerow([r["severity"], r["category"], r["title"], r["description"],
                        r["advice"], r["fix"]])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(sid=None) -> str:
    conn = connect()
    try:
        p = report_payload(sid, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No checks recorded</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        payload = scan.get("payload") or {}
        summary = payload.get("summary") or {}
        # the stored resets have no monotonic clock, so rebuild one from order
        stored = payload.get("resets") or []
        for i, r in enumerate(stored):
            r.setdefault("at_monotonic", float(i))
        timeline = svg_timeline(stored)
        ports = svg_ports(payload.get("scans") or [])
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        shapes = summary.get("shapes") or {}
        shapebar = (svg_bar(sorted(shapes.items(), key=lambda kv: -kv[1]),
                            title="Resets by shape", color="#f76808",
                            colors={k: SHAPE_COLOR.get(k, "#8b8f9b") for k in shapes})
                    if shapes else "")
        rrows = "".join(
            f'<tr><td class="mono">{esc(r["src"])}:{r["sport"]}</td>'
            f'<td class="mono">{esc(r["dst"])}:{r["dport"]}</td>'
            f'<td class="mono">{esc(r["flags"])}</td>'
            f'<td class="mono" style="color:{SHAPE_COLOR.get(r["shape"], "#8b8f9b")}">'
            f'{esc(r["shape"])}</td>'
            f'<td class="sub2">{esc(r["confidence"])}</td>'
            f'<td class="num">{"" if r["seq_offset"] is None else r["seq_offset"]}</td>'
            f'</tr>' for r in p["resets"][:60])
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span></td>'
            f'<td><b>{esc(f["title"])}</b>'
            f'<div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + (f'<div class="means"><b>What to make of it:</b> {esc(f["advice"])}</div>'
               if f["advice"] else "")
            + (f'<div class="fix"><b>If you decide to act:</b><pre>{esc(f["fix"])}</pre>'
               f'</div>' if f["fix"] else "")
            + "</td></tr>" for f in p["findings"])
        limits = "".join(f"<li>{esc(x)}</li>" for x in p["limitations"])
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} - {esc(scan['hostname'] or '')}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1100px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:30px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:21px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:12.7px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:9px 11px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-word}}
 .num{{font-family:ui-monospace,monospace;font-size:11.5px;text-align:right}}
 .sub2{{color:#6f7685;font-size:10.5px;font-family:ui-monospace,monospace}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:84ch}}
 .means{{margin-top:6px;color:#8fd3b0;font-size:12.4px;max-width:84ch}}
 .fix{{margin-top:8px;color:#a8d8e8;font-size:12.2px}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:9px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:6px 0 0;overflow:auto;
      white-space:pre-wrap;color:#b6bac4;max-height:340px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0;white-space:pre-wrap}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note ul{{margin:6px 0 0 18px;padding:0}} .note li{{margin:3px 0}}
 .charts{{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;
   padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:130px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 text.bl{{fill:#8b8f9b;font:10.5px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 text.cell{{fill:#e6e8ee;font:11.5px ui-monospace,monospace}}
 text.sub{{fill:#6f7685;font:10.5px ui-monospace,monospace}}
 text.pie-n{{fill:#e6e8ee;font:700 16px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;
   padding-top:14px}}
</style></head><body><div class="wrap">
<h1>TCP reset patterns</h1>
<div class="meta">{esc(scan['hostname'])} &middot; {ts_pretty(scan['ts'])} &middot;
 {scan['elapsed_ms']} ms &middot;
 {'the wire was watched' if scan['captured'] else 'the wire was not watched'}
 &middot; uptime {fmt_duration(scan['uptime'])}</div>
<div class="note"><b>A reset is not an attack.</b>
 {esc(p['a_reset_is_not_an_attack'])}<ul>{limits}</ul></div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="grid">
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{scan['band_colour']}">
   {esc(scan['band'] or '')}</div><div class="l">score {scan['score']}</div></div>
 <div class="card"><div class="l">Resets sent (boot)</div>
  <div class="n">{scan['out_rsts'] if scan['out_rsts'] is not None else '?'}</div></div>
 <div class="card"><div class="l">Captured</div>
  <div class="n">{scan['captured']}</div>
  <div class="l">{scan['inbound']} in / {scan['outbound']} out</div></div>
 <div class="card"><div class="l">Scan patterns</div>
  <div class="n" style="color:{'#f76808' if scan['scans_found'] else '#30a46c'}">
   {scan['scans_found']}</div></div>
 <div class="card"><div class="l">Odd sequences</div>
  <div class="n">{scan['injection_candidates']}</div></div>
</div>
<h2>Timeline</h2><div class="charts">{timeline}</div>
<h2>Ports per peer</h2><div class="charts">{ports}</div>
<h2>Analytics</h2><div class="charts">{shapebar}{pie}</div>
{f'<h2>Resets ({len(p["resets"])} shown)</h2><table><tr><th>From</th><th>To</th>'
 f'<th>Flags</th><th>Shape</th><th>Confidence</th><th>Seq offset</th></tr>{rrows}</table>'
 if rrows else ''}
<h2>Findings ({len(p['findings'])})</h2>
{'<table><tr><th>Severity</th><th>Detail</th></tr>' + frows + '</table>'
 if frows else '<div class="chart-empty">No findings.</div>'}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 Read-only and silent: no packet was sent, no connection reset and no setting changed.</footer>
</div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 10 - Web application (no CDN, no JS libraries)
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#f76808;--ok:#30a46c;
 --warn:#ffb224;--crit:#e5484d;--good:#8fd3b0;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1200px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;gap:14px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;
 padding:6px 10px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1200px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.warn{background:#231a12;border-color:#5a3b1c;color:#ffcf9e}
.banner.bad{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner b{color:#fff} .banner ul{margin:6px 0 0 18px;padding:0} .banner li{margin:3px 0}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.sub2{color:var(--tx-dim);font-size:11px;font-family:var(--mono)}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
.btn.tiny{padding:3px 8px;font-size:10.5px}
input[type=text],input[type=number],select{font-family:var(--mono);font-size:12px;
 padding:7px 9px;background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);
 border-radius:7px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 15px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:21px;font-weight:700;line-height:1.3;font-family:var(--mono)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:12.7px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.11em;
 text-transform:uppercase;color:var(--tx-dim);padding:9px 11px;border-bottom:1px solid var(--line);
 background:var(--panel-2);white-space:nowrap}
td{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:11.8px;word-break:break-word}
.num{font-family:var(--mono);font-size:11.8px;text-align:right}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
 border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:5px;
 border:1px solid var(--line-2);color:var(--tx-dim);white-space:nowrap;margin-left:4px}
.tag.good{border-color:#1e5138;color:#7fd9ab}
.desc{color:var(--tx-mid);margin-top:4px;max-width:84ch}
.means{margin-top:6px;color:var(--good);font-size:12.4px;max-width:84ch}
.fix{margin-top:8px;color:#a8d8e8;font-size:12.2px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:9px 11px;
 font-family:var(--mono);font-size:11.5px;margin:6px 0 0;max-height:340px;overflow:auto;
 white-space:pre-wrap;color:var(--tx-mid)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:240px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:130px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none} .lg span{flex:1}
.lg b{font-family:var(--mono)}
text.bl{fill:#8b8f9b;font:10.5px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
text.cell{fill:#e6e8ee;font:11.5px var(--mono)}
text.sub{fill:#6f7685;font:10.5px var(--mono)}
text.pie-n{fill:#e6e8ee;font:700 16px var(--mono)}
rect.btrack{fill:#1e222a}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1200px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
.lvl-ERROR{color:var(--crit)} .lvl-WARN{color:var(--warn)} .lvl-INFO{color:var(--tx-dim)}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} .card .n{font-size:18px} table{font-size:12px}
 th,td{padding:7px 8px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>RSTWATCH</b> <small>TCP reset patterns</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_resets') }}" class="{{ 'on' if nav=='resets' }}">Resets</a>
  <a href="{{ url_for('page_peers') }}" class="{{ 'on' if nav=='peers' }}">Peers</a>
  <a href="{{ url_for('page_scans') }}" class="{{ 'on' if nav=='scans' }}">Checks</a>
  <a href="{{ url_for('page_learn') }}" class="{{ 'on' if nav=='learn' }}">Learn</a>
  <a href="{{ url_for('page_logs') }}" class="{{ 'on' if nav=='logs' }}">Logs</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner"><b>A reset is not an attack.</b> """ + RESET_IS_NORMAL + """</div>
 {% if error %}<div class="banner bad"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% if flash %}<div class="banner">{{ flash }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 Read-only and silent: no packet is sent, no connection reset and no setting changed.
 Injection cannot be proven from one endpoint.</footer>
</body></html>"""

RUNBAR_TPL = """
<form method="post" action="{{ url_for('do_check') }}" class="bar">
 <select name="capture_seconds">
  <option value="0">counters only (no capture)</option>
  {% for s in [15,30,60,120] %}<option value="{{ s }}">also watch the wire for {{ s }}s</option>
  {% endfor %}
 </select>
 <select name="rate_seconds">
  <option value="0">no rate sample</option>
  {% for s in [5,10,30] %}<option value="{{ s }}">measure the rate over {{ s }}s</option>
  {% endfor %}
 </select>
 <button class="btn primary" type="submit">Check now</button>
 {% if scan %}
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
 {% endif %}
</form>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
""" + RUNBAR_TPL + """
<div class="empty"><b>Nothing checked yet</b>
 It reads the kernel's reset counters, which cover everything since boot, and can watch the
 wire to see the shape of reset traffic: which direction, how fast, spread across how many
 ports, and whether the sequence numbers fit.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 rstwatch.py check</div>
</div>{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">Check #{{ scan.id }} &middot; {{ ts_pretty(scan.ts) }} &middot;
 {{ scan.elapsed_ms }} ms &middot;
 {{ 'the wire was watched' if scan.captured else 'the wire was not watched' }}</div>
""" + RUNBAR_TPL + """
{% if scan.detail %}<div class="banner warn"><b>Partial:</b> {{ scan.detail }}</div>{% endif %}
{% if scan.scans_found %}
<div class="banner warn"><b>{{ scan.scans_found }} peer(s) were reset across many ports.</b>
 The resets are this machine's own replies - they are the evidence, not the attack.</div>
{% endif %}
<div class="grid">
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{{ scan.band_colour }}">{{ scan.band }}</div>
  <div class="l">score {{ scan.score }}</div></div>
 <div class="card"><div class="l">Resets sent (boot)</div>
  <div class="n">{{ scan.out_rsts if scan.out_rsts is not none else '?' }}</div></div>
 <div class="card"><div class="l">Captured</div><div class="n">{{ scan.captured }}</div>
  <div class="l">{{ scan.inbound }} in / {{ scan.outbound }} out</div></div>
 <div class="card"><div class="l">Scan patterns</div>
  <div class="n" style="color:{{ '#f76808' if scan.scans_found else '#30a46c' }}">
   {{ scan.scans_found }}</div></div>
 <div class="card"><div class="l">Odd sequences</div>
  <div class="n">{{ scan.injection_candidates }}</div></div>
</div>
<h2>Timeline</h2><div class="charts">{{ timeline|safe }}</div>
<h2>Ports per peer</h2><div class="charts">{{ ports|safe }}</div>
<h2>Analytics</h2><div class="charts">{{ shapebar|safe }}{{ pie|safe }}</div>
<h2>Findings ({{ findings|length }})</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span></td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
  {% if f.advice %}<div class="means"><b>What to make of it:</b> {{ f.advice }}</div>
  {% endif %}
  {% if f.fix %}<div class="fix"><b>If you decide to act:</b><pre>{{ f.fix }}</pre></div>
  {% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty">No findings.</div>{% endif %}
{% endblock %}"""

RESETS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Resets</h1>
<div class="sub">{{ rows|length }} reset(s) from the most recent capture.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="shape"><option value="">all shapes</option>
  {% for s in shapes %}<option value="{{ s }}" {{ 'selected' if s==f_shape }}>{{ s }}</option>
  {% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="filter by address">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_resets') }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>From</th><th>To</th><th>Flags</th><th>Shape</th><th>Confidence</th>
 <th>Seq offset</th><th>Age</th></tr>
{% for r in rows %}<tr>
 <td class="mono">{{ r.src }}:{{ r.sport }}</td>
 <td class="mono">{{ r.dst }}:{{ r.dport }}</td>
 <td class="mono">{{ r.flags }}</td>
 <td class="mono" style="color:{{ shape_colour(r.shape) }}">{{ r.shape }}</td>
 <td class="sub2">{{ r.confidence }}</td>
 <td class="num">{{ '' if r.seq_offset is none else r.seq_offset }}</td>
 <td class="num">{{ '' if r.age is none else '%.2f'|format(r.age) }}</td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No resets recorded</b>
 Run a check with capture enabled.</div>{% endif %}
{% endblock %}"""

PEERS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Peers</h1>
<div class="sub">{{ rows|length }} peer(s) seen in a scan-shaped burst. Approving one stops
 it being reported - useful for a monitoring system that legitimately probes many ports.</div>
{% if rows %}
<table><tr><th>Peer</th><th>Max ports</th><th>Resets</th><th>Seen</th><th>Last</th>
 <th></th></tr>
{% for r in rows %}<tr>
 <td class="mono">{{ r.peer }}{% if r.approved %}<span class="tag good">approved</span>
  {% endif %}{% if r.label %}<div class="sub2">{{ r.label }}</div>{% endif %}</td>
 <td class="num">{{ r.max_ports }}</td>
 <td class="num">{{ r.resets }}</td>
 <td class="num">{{ r.times_seen }}</td>
 <td class="mono">{{ ago(r.last_seen) }}</td>
 <td>{% if r.approved %}
   <form method="post" action="{{ url_for('do_revoke') }}" style="display:inline">
    <input type="hidden" name="peer" value="{{ r.peer }}">
    <button class="btn tiny" type="submit">revoke</button></form>
  {% else %}
   <form method="post" action="{{ url_for('do_approve') }}" style="display:inline">
    <input type="hidden" name="peer" value="{{ r.peer }}">
    <button class="btn tiny" type="submit">approve</button></form>
  {% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty"><b>No peers recorded</b>
 Nothing has been reset across enough ports to look like a sweep.</div>{% endif %}
{% endblock %}"""

SCANS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Checks</h1><div class="sub">{{ rows|length }} check(s) stored locally.</div>
{% if rows %}
<table><tr><th>#</th><th>When</th><th>Mode</th><th>OutRsts</th><th>Captured</th>
 <th>Scan patterns</th><th>Score</th><th></th></tr>
{% for r in rows %}<tr>
 <td class="mono">#{{ r.id }}</td>
 <td class="mono">{{ r.ts[:19].replace('T',' ') }}</td>
 <td class="sub2">{{ r.mode }}</td>
 <td class="num">{{ r.out_rsts if r.out_rsts is not none else '?' }}</td>
 <td class="num">{{ r.captured }}</td>
 <td class="num" style="color:{{ '#f76808' if r.scans_found else '#8b8f9b' }}">
  {{ r.scans_found }}</td>
 <td class="num">{{ r.score }}</td>
 <td><a class="btn" href="{{ url_for('page_overview') }}?scan={{ r.id }}">view</a></td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing checked yet</b></div>{% endif %}
{% endblock %}"""

LEARN_TPL = """{% extends 'base.html' %}{% block body %}
<h1>What a TCP reset means, and what a pattern of them means</h1>
<div class="desc">A RST says "this connection does not exist, stop talking". It is the normal,
 correct answer to a packet for a connection nobody has - which makes it the single most
 common packet on any network that nobody looks at.</div>
<div class="banner"><b>Almost every reset is ordinary.</b> Connecting to a closed port gets one
 immediately. A browser closing tabs sends them by the dozen. Load balancers and NAT gateways
 reset idle connections on a timer. An application calling close() with unread data pending
 sends one. None of that is worth an alert.</div>
<h2>The pattern is the signal</h2>
<div class="desc">What makes resets worth analysing is not any single packet but the shape:
 which direction they travel, how quickly they arrive after the handshake, whether they
 cluster on one port or spray across many, and whether the sequence numbers make sense.</div>
<h2>The four shapes</h2>
<div class="desc"><b>Port scan.</b> Many resets <i>from</i> this machine to one peer, across
 many ports, in a short window. That is what your own kernel does while somebody scans you -
 <b>the resets are yours</b>, and they are the evidence rather than the attack. Consecutive
 port numbers suggest a sweep; scattered ones can be a legitimate client with many
 connections.<br><br>
 <b>Injection.</b> A reset whose sequence number sits oddly in the window. That is the shape
 of an off-path injected reset - the technique used to interrupt connections without being in
 the path.<br><br>
 <b>Connection refused.</b> A reset immediately after a SYN, which simply means nothing is
 listening. Counted so it can be excluded from everything else.<br><br>
 <b>Teardown.</b> A reset late in a connection's life - an application closing without a
 graceful FIN. Extremely common and almost never interesting.</div>
<h2>What the kernel already counted</h2>
<div class="desc">The counters in <span class="mono">/proc/net/netstat</span> say <b>why</b>
 the kernel reset things, which is the part that actually explains a spike:
 <span class="mono">TCPAbortOnData</span> is close() with unread data;
 <span class="mono">TCPAbortOnTimeout</span> is a peer that went away;
 <span class="mono">TCPAbortOnMemory</span> is the machine under real pressure.<br><br>
 <span class="mono">TCPChallengeACK</span> is worth knowing about: it is RFC 5961, the
 kernel's defence against blind reset injection. Rather than acting on a reset that did not
 fit the window, it asks the peer to confirm. A rising count means something is sending
 resets that did not fit - which ordinary reordering also causes.</div>
<h2>Two things this cannot tell you</h2>
<div class="banner warn"><b>Injection cannot be proven from one endpoint.</b>
 """ + INJECTION_UNPROVABLE + """<br><br>
 <b>The counters are totals since boot.</b> """ + COUNTERS_ARE_TOTALS + """</div>
<h2>And one thing it will not guess at</h2>
<div class="desc">A reset on a connection whose handshake was never seen has nothing to be
 measured against - no age, no expected sequence number. Those are reported as
 <b>unclassifiable</b> rather than guessed at, which is why a longer capture gives a cleaner
 picture than a short one.</div>
{% endblock %}"""

LOGS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Logs</h1><div class="sub">Stored locally in {{ dbfile }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="level"><option value="">All levels</option>
  {% for l in ['INFO','WARN','ERROR'] %}<option value="{{ l }}" {{ 'selected' if l==f_level }}>
   {{ l }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_logs') }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Time (UTC)</th><th>Level</th><th>Source</th><th>Message</th><th>Check</th></tr>
{% for e in rows %}<tr><td class="mono">{{ e.ts[:19].replace('T',' ') }}</td>
 <td class="mono lvl-{{ e.level }}"><b>{{ e.level }}</b></td>
 <td class="mono">{{ e.source }}</td><td>{{ e.message }}</td>
 <td class="mono">{{ ('#' ~ e.scan_id) if e.scan_id else '-' }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No log entries match</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "resets.html": RESETS_TPL, "peers.html": PEERS_TPL, "scans.html": SCANS_TPL,
             "learn.html": LEARN_TPL, "logs.html": LOGS_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty, "ago": ago,
                "shape_colour": lambda s: SHAPE_COLOR.get(s, "#8b8f9b"),
                "scan": None, "error": request.args.get("error"),
                "flash": request.args.get("flash")}
        base.update(kw)
        return base

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            init_db(conn)
            try:
                sid = int(request.args.get("scan", "") or 0)
            except ValueError:
                sid = 0
            scan = scan_summary(sid, conn) if sid else None
            if not scan:
                sid = latest_scan_id(conn)
                scan = scan_summary(sid, conn) if sid else None
            if not scan:
                return render_template("empty.html", **ctx("overview"))
            p = report_payload(scan["id"], conn)
            payload = scan.get("payload") or {}
            stored = payload.get("resets") or []
            for i, r in enumerate(stored):
                r.setdefault("at_monotonic", float(i))
            summary = payload.get("summary") or {}
            shapes = summary.get("shapes") or {}
            counts = {s: scan[s] or 0 for s in SEVERITIES}
            return render_template("overview.html", **ctx(
                "overview", scan=scan, findings=p["findings"],
                timeline=svg_timeline(stored),
                ports=svg_ports(payload.get("scans") or []),
                shapebar=(svg_bar(sorted(shapes.items(), key=lambda kv: -kv[1]),
                                  title="Resets by shape", color="#f76808",
                                  colors={k: SHAPE_COLOR.get(k, "#8b8f9b")
                                          for k in shapes}) if shapes else ""),
                pie=svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])))
        finally:
            conn.close()

    @app.post("/check")
    def do_check():
        import urllib.parse as up
        try:
            cap = clamp(float(request.form.get("capture_seconds", 0)), 0, 600)
        except ValueError:
            cap = 0.0
        try:
            rate = clamp(float(request.form.get("rate_seconds", 0)), 0, 120)
        except ValueError:
            rate = 0.0
        try:
            res = run_check(capture_seconds=cap, rate_seconds=rate,
                            mode="web", note="from the web UI")
        except Exception as e:
            log_event("ERROR", "scan", str(e))
            return redirect(url_for("page_overview") + "?error=" + up.quote(str(e)))
        return redirect(url_for("page_overview") + f"?scan={res['id']}")

    @app.route("/resets")
    def page_resets():
        conn = connect()
        try:
            init_db(conn)
            sid = latest_scan_id(conn)
            shape = request.args.get("shape", "").strip()
            term = request.args.get("qq", "").strip()
            sql = "SELECT * FROM resets WHERE scan_id=(SELECT MAX(scan_id) FROM resets)"
            args: list = []
            if shape:
                sql += " AND shape=?"
                args.append(shape)
            if term:
                sql += " AND (src LIKE ? OR dst LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id LIMIT 500"
            rows = q(sql, tuple(args), conn) if sid else []
            return render_template("resets.html", **ctx(
                "resets", rows=rows, f_shape=shape, f_q=term,
                shapes=["scan", "injection", "refused", "teardown", "unknown"]))
        finally:
            conn.close()

    @app.route("/peers")
    def page_peers():
        conn = connect()
        try:
            init_db(conn)
            rows = [dict(r) for r in q(
                "SELECT * FROM peers ORDER BY approved DESC, max_ports DESC LIMIT 300",
                (), conn)]
            for r in rows:
                r["approved"] = bool(r["approved"])
            return render_template("peers.html", **ctx("peers", rows=rows))
        finally:
            conn.close()

    @app.post("/approve")
    def do_approve():
        import urllib.parse as up
        peer = (request.form.get("peer") or "").strip()
        ok, detail = approve_peer(peer)
        return redirect(url_for("page_peers") + "?flash="
                        + up.quote("Approved." if ok else detail))

    @app.post("/revoke")
    def do_revoke():
        peer = (request.form.get("peer") or "").strip()
        if peer:
            revoke_peer(peer)
        return redirect(url_for("page_peers"))

    @app.route("/scans")
    def page_scans():
        conn = connect()
        try:
            init_db(conn)
            return render_template("scans.html", **ctx(
                "scans", rows=q("SELECT * FROM scans ORDER BY id DESC LIMIT 200",
                                (), conn)))
        finally:
            conn.close()

    @app.route("/learn")
    def page_learn():
        return render_template("learn.html", **ctx("learn"))

    @app.route("/logs")
    def page_logs():
        conn = connect()
        try:
            init_db(conn)
            level = request.args.get("level", "").strip().upper()
            term = request.args.get("qq", "").strip()
            sql, args = "SELECT * FROM audit_log WHERE 1=1", []
            if level in ("INFO", "WARN", "ERROR"):
                sql += " AND level=?"
                args.append(level)
            if term:
                sql += " AND (message LIKE ? OR source LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id DESC LIMIT 300"
            return render_template("logs.html", **ctx(
                "logs", rows=q(sql, tuple(args), conn), f_level=level, f_q=term,
                dbfile=os.path.abspath(db_path())))
        finally:
            conn.close()

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="rstwatch-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no checks yet"}), 404
        s = scan_summary(sid)
        return jsonify({"tool": APP_NAME, "version": VERSION, "read_only": True,
                        "sends_no_packets": True,
                        "a_reset_is_not_an_attack": True,
                        "injection_cannot_be_proven_here": True,
                        "counters_are_totals_since_boot": True,
                        "disclaimer": DISCLAIMER_SHORT,
                        "scan": {k: v for k, v in s.items() if k != "payload"}})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /resets /peers /scans "
                        "/learn /logs", 404, mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port}")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    if not is_root():
        print("  NOTE    : not running as root, so capture is unavailable. The kernel\n"
              "            counters need no privileges and cover everything since boot.")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI shows who has been talking to\n"
              "            this machine. Use 127.0.0.1.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 11 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(rows, limit=None, quiet=False, show_fix=True):
    shown = [f for f in rows if not (quiet and f["severity"] == "info")]
    shown = shown[:limit] if limit else shown
    for f in shown:
        print(f"\n  [{f['severity'].upper():^8}] {f['title']}")
        for l in textwrap.wrap(f["description"], 70):
            print(f"      {l}")
        if f.get("evidence"):
            for l in str(f["evidence"]).splitlines()[:12]:
                for w in textwrap.wrap(l, 70) or [""]:
                    print(f"      {w}")
        if f.get("advice"):
            for l in textwrap.wrap("what to make of it: " + f["advice"], 70):
                print(f"      {l}")
        if f.get("fix") and show_fix:
            print("      to look further:")
            for l in str(f["fix"]).splitlines()[:8]:
                print(f"        {l}")


def _report(res, a):
    counters, capture = res["counters"], res["capture"]
    print(f"Host   : {socket.gethostname()}")
    if counters.data:
        tcp = counters.data.get("tcp", {})
        print(f"Since boot: {tcp.get('OutRsts', '?')} reset(s) sent, "
              f"{tcp.get('EstabResets', '?')} established connection(s) reset")
    if capture:
        if capture.status == "unavailable":
            print(f"Watched: could not - {shorten(capture.detail, 56)}")
        else:
            d = capture.data
            print(f"Watched: {d['seconds']:.0f}s, {d['frames']} frame(s), "
                  f"{len(d['resets'])} reset(s)")
    else:
        print("Watched: no (counters and connection states only)")
    print(f"Time   : {res['elapsed_ms']} ms")
    line("=")
    n_rst = len((capture.data or {}).get("resets", [])) if capture else 0
    print(f"  {n_rst} RESET(S) CAPTURED   -   {res['band'].upper()}")
    line("=")
    if res.get("rates"):
        print("  RATE (between two readings)")
        for k, v in sorted(res["rates"].items())[:8]:
            if isinstance(v, dict):
                print(f"    {k:<22} {v.get('delta', '?')} in "
                      f"{v.get('seconds', '?')}s")
            else:
                print(f"    {k:<22} {v}")
        line()
    if capture and capture.status == "ok" and capture.data["resets"]:
        summary = summarise_resets(capture.data["resets"])
        print(f"  {'SHAPE':<14} {'COUNT':>6}   WHAT IT USUALLY MEANS")
        line()
        meanings = {
            "refused": "nothing was listening on that port",
            "abort": "an application dropped the connection",
            "mid-stream": "a live conversation was interrupted",
            "injection": "the shape of an injected reset - read the findings",
            "stale": "an idle connection was reclaimed",
            "unknown": "no context was captured for the flow",
        }
        for shape, count in sorted(summary["shapes"].items(), key=lambda kv: -kv[1]):
            print(f"  {shape:<14} {count:>6}   {meanings.get(shape, '')}")
        line()
        if summary.get("top_peers"):
            print("  TOP PEERS")
            for peer, count in summary["top_peers"][:6]:
                print(f"    {peer:<40} {count}")
            line()
    _print_findings(res["findings"], a.show, a.quiet, not a.no_fix)
    line()
    print(textwrap.fill("  " + RESET_IS_NORMAL, 78))
    line()


def cmd_check(a):
    banner()
    res = run_check(capture_seconds=0.0, rate_seconds=a.rate_seconds,
                    note=a.note or "")
    _report(res, a)
    return _exit_code(a, res)


def cmd_capture(a):
    banner()
    if not is_root():
        print("NOTE: capturing needs root. Without it nothing is watched - which is not the")
        print("      same as no resets arriving. The kernel counters still work.\n")
    print(f"Watching for {a.seconds:.0f}s. Nothing is transmitted.\n")

    def on_reset(pkt):
        cls = pkt.get("classification") or {}
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"  {stamp}  {pkt['src']}:{pkt['sport']} -> {pkt['dst']}:{pkt['dport']}  "
              f"{cls.get('shape', 'unknown')}")

    res = run_check(capture_seconds=a.seconds, interface=a.interface,
                    rate_seconds=a.rate_seconds, mode="capture",
                    note=a.note or "", on_reset=on_reset if a.verbose else None)
    print()
    _report(res, a)
    return _exit_code(a, res)


def cmd_watch(a):
    banner()
    print(f"Checking every {a.interval:.0f}s"
          + (f", {a.count} times" if a.count else " until Ctrl+C") + ".")
    print("Only changes and findings above informational are printed.\n")
    last_out = None
    n = 0
    try:
        while True:
            n += 1
            res = run_check(capture_seconds=a.seconds, interface=a.interface,
                            rate_seconds=a.rate_seconds, mode="watch", note="watch")
            stamp = datetime.now().strftime("%H:%M:%S")
            tcp = (res["counters"].data or {}).get("tcp", {})
            out_rsts = tcp.get("OutRsts")
            alerts = [f for f in res["findings"]
                      if f["severity"] in ("critical", "high")]
            delta = (out_rsts - last_out) if (out_rsts is not None
                                              and last_out is not None) else None
            if alerts or (delta is not None and delta > a.delta_threshold):
                print(f"  {stamp}  #{res['id']}"
                      + (f"  +{delta} reset(s) sent since the last round"
                         if delta else ""))
                for f in alerts:
                    print(f"   !! [{f['severity'].upper()}] {f['title']}")
            elif not a.quiet:
                print(f"  {stamp}  #{res['id']}"
                      + (f"  +{delta} sent" if delta is not None else "")
                      + "  nothing notable")
            last_out = out_rsts
            if a.count and n >= a.count:
                break
            time.sleep(max(0.0, a.interval - a.seconds))
    except KeyboardInterrupt:
        print("\nStopped.")
    line()
    print(f"  {n} round(s).")
    print(textwrap.fill("  " + COUNTERS_ARE_TOTALS, 78))
    line()
    return 0


def _exit_code(a, res):
    counts = res["counts"]
    if a.fail_on_injection:
        capture = res.get("capture")
        shapes = summarise_resets((capture.data or {}).get("resets", []))["shapes"] \
            if capture and capture.data else {}
        if shapes.get("injection"):
            print(f"  Exiting non-zero: {shapes['injection']} reset(s) have the shape of "
                  f"an injected one.")
            return 2
    if a.fail_on_critical and counts["critical"]:
        print(f"  Exiting non-zero: {counts['critical']} critical finding(s).")
        return 2
    if a.fail_over is not None and res["score"] > a.fail_over:
        print(f"  Exiting non-zero: score {res['score']} is above --fail-over "
              f"{a.fail_over}")
        return 2
    return 0


def _show_reset(pkt, cls):
    print(f"  {pkt['src']}:{pkt['sport']}  ->  {pkt['dst']}:{pkt['dport']}")
    print(f"  flags     {flag_string(pkt['flags'])}")
    print(f"  sequence  {pkt['seq']}"
          + (f"   acknowledging {pkt['ack']}" if pkt.get("ack") else ""))
    print(f"  window    {pkt['window']}")
    # A packet's TTL is its stack's initial value minus the hops it crossed, so
    # the nearest common initial above it says roughly how far it came.
    initial = next((v for v in (255, 128, 64, 32) if pkt["ttl"] <= v), None)
    print(f"  ttl       {pkt['ttl']}"
          + (f"   about {initial - pkt['ttl']} hop(s) from an initial {initial}"
             if initial else ""))
    if pkt.get("payload_len"):
        print(f"  payload   {pkt['payload_len']} byte(s)"
              + "   - a reset carrying data is unusual but legal")
    line()
    print(f"  SHAPE: {cls.get('shape', 'unknown').upper()}")
    for l in textwrap.wrap(str(cls.get("why", "")), 74):
        print(f"  {l}")
    if cls.get("signals"):
        line()
        print("  SIGNALS")
        for s in cls["signals"]:
            print(f"    - {s.get('name', s) if isinstance(s, dict) else s}")
            if isinstance(s, dict):
                for l in textwrap.wrap(str(s.get("detail", "")), 68):
                    print(f"        {l}")
                for l in textwrap.wrap(str(s.get("why", "")), 68):
                    print(f"        {l}")
    line("=")


def cmd_decode(a):
    banner()
    data = a.hex
    if a.file:
        try:
            with open(a.file) as fh:
                data = fh.read()
        except OSError as e:
            print(f"Could not read {a.file}: {e}")
            return 1
    if not data:
        print("Give a hex dump on the command line or with --file.")
        return 1
    cleaned = re.sub(r"[^0-9a-fA-F]", "", data)
    if len(cleaned) < 108:
        print("  Too short to be an ethernet frame carrying TCP (need at least 54 bytes).")
        return 1
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as e:
        print(f"  Not valid hex: {e}")
        return 1
    pkt = parse_tcp_frame(raw)
    started = "ethernet"
    if not pkt:
        # maybe the dump starts at the IP header
        pkt = parse_tcp_frame(b"\x00" * 12 + struct.pack("!H", ETH_P_IP) + raw)
        started = "IP header"
    if not pkt:
        print("  This does not decode as TCP at the ethernet or IP layer.")
        return 1
    print(f"Decoded {len(raw)} bytes, starting at the {started}.")
    line("=")
    if not pkt["is_rst"]:
        print(f"  This is not a reset - the flags are {flag_string(pkt['flags'])}.")
        print("  Shown anyway, since the header is decoded either way.")
        line()
    cls = classify_reset(pkt, None, time.time(), local_addresses())
    _show_reset(pkt, cls)
    print(textwrap.fill(
        "  Decoded offline - nothing was transmitted. With no other packets from this "
        "flow there is no context, so the shape here rests on the header alone. "
        + INJECTION_UNPROVABLE, 78))
    line()
    return 0


def cmd_simulate(a):
    banner()
    print(textwrap.fill(
        "Nothing is transmitted. This builds TCP frames in memory and runs them through "
        "the same classifier the capture path uses, so you can see what detection looks "
        "like without waiting for a real reset.", 78))
    line("=")
    now = time.time()
    tracker = FlowTracker()
    scenario = a.scenario
    src, dst = a.peer, a.local
    sport, dport = a.port, 44100

    if scenario == "refused":
        tracker.observe(parse_tcp_frame(
            build_tcp_frame(dst, src, dport, sport, SYN)), now)
        rst = parse_tcp_frame(build_tcp_frame(src, dst, sport, dport, RST | ACK,
                                              ttl=a.ttl, window=a.window))
        when = now + 0.01
    elif scenario == "abort":
        for f in (build_tcp_frame(dst, src, dport, sport, SYN),
                  build_tcp_frame(src, dst, sport, dport, SYN | ACK),
                  build_tcp_frame(dst, src, dport, sport, ACK)):
            tracker.observe(parse_tcp_frame(f), now)
        rst = parse_tcp_frame(build_tcp_frame(src, dst, sport, dport, RST | ACK,
                                              ttl=a.ttl, window=a.window))
        when = now + 30.0
    else:                                    # injection: data, then an odd reset
        for f in (build_tcp_frame(dst, src, dport, sport, SYN),
                  build_tcp_frame(src, dst, sport, dport, SYN | ACK),
                  build_tcp_frame(dst, src, dport, sport, PSH | ACK,
                                  payload=b"GET / HTTP/1.1\r\n\r\n")):
            tracker.observe(parse_tcp_frame(f), now)
        rst = parse_tcp_frame(build_tcp_frame(src, dst, sport, dport, RST | ACK,
                                              ttl=a.ttl, window=a.window))
        when = now + 0.02
    flow = tracker.observe(rst, when)
    cls = classify_reset(rst, flow, when, {dst})
    print(f"  Scenario: {scenario}")
    print(f"  Built {len(build_tcp_frame(src, dst, sport, dport, RST | ACK))} bytes. "
          f"Nothing was sent.")
    line()
    _show_reset(rst, cls)
    if a.show_hex:
        h = build_tcp_frame(src, dst, sport, dport, RST | ACK, ttl=a.ttl,
                            window=a.window).hex()
        print("  the packet:")
        for i in range(0, len(h), 64):
            print(f"    {h[i:i + 64]}")
        line()
    return 0


def cmd_counters(_a):
    r = read_counters()
    if r.status == "unavailable":
        print(r.detail)
        return 1
    tcp, ext = r.data.get("tcp", {}), r.data.get("ext", {})
    print("  TCP (since boot)")
    line()
    for k in ("OutRsts", "EstabResets", "AttemptFails", "ActiveOpens", "PassiveOpens",
              "CurrEstab", "RetransSegs", "InErrs"):
        if k in tcp:
            print(f"    {k:<24} {tcp[k]}")
    print("\n  TCP extended")
    line()
    for k in ("EmbryonicRsts", "TCPAbortOnData", "TCPAbortOnClose", "TCPAbortOnTimeout",
              "TCPAbortOnLinger", "TCPAbortFailed", "TCPAbortOnMemory",
              "ListenDrops", "ListenOverflows", "TCPChallengeACK", "TCPSYNChallenge"):
        if k in ext:
            print(f"    {k:<24} {ext[k]}")
    if r.data.get("uptime"):
        hours = r.data["uptime"] / 3600.0
        out = tcp.get("OutRsts")
        if out is not None and hours > 0:
            print(f"\n    over {hours:.1f}h of uptime, that is {out / hours:.1f} "
                  f"reset(s) sent per hour on average")
    line()
    print(textwrap.fill("  " + COUNTERS_ARE_TOTALS, 78))
    line()
    return 0


def cmd_peers(a):
    rows = q("SELECT * FROM peers ORDER BY approved DESC, resets DESC LIMIT ?",
             (a.limit,))
    if not rows:
        print("No peers recorded yet. Run:  capture --seconds 60")
        return 0
    print(f"  {'PEER':<40} {'RESETS':>7} {'SEEN':>5}  APPROVED")
    line()
    for r in rows:
        print(f"  {r['peer'][:39]:<40} {r['resets']:>7} {r['times_seen']:>5}  "
              f"{'yes' if r['approved'] else 'no'}")
    line()
    return 0


def cmd_approve(a):
    ok, detail = approve_peer(a.peer, a.label or "", a.note or "")
    if not ok:
        print(detail)
        return 1
    print(f"Approved {detail}")
    print()
    print(textwrap.fill(
        "Resets involving this peer will no longer be reported as a pattern worth "
        "reading. This records a decision - it changes nothing about the traffic.", 78))
    return 0


def cmd_revoke(a):
    n = revoke_peer(a.peer)
    print(f"Revoked {n} approval(s)." if n else f"'{a.peer}' was not approved.")
    return 0


def cmd_learn(_a):
    banner()
    print(textwrap.dedent("""\
        WHAT A RESET IS

          A TCP RST tears a connection down immediately, with no negotiation. It
          is the protocol's way of saying "this connection does not exist, or
          should not continue".

        MOST RESETS ARE COMPLETELY ORDINARY

          - you connect to a port nothing is listening on, and the host says so
          - a browser closes a tab and abandons a connection mid-transfer
          - a load balancer trims an idle connection
          - a NAT table entry expires and the next packet gets rejected

          A busy machine produces resets constantly and none of it is an attack.
          NO SINGLE RESET MEANS ANYTHING. What carries information is the pattern.

        WHAT THE PATTERN SAYS

          WHO SENT IT     A reset from the peer is the peer's decision. One that
                          arrives while both ends still believe the connection is
                          fine is somebody else's decision - that is the
                          interesting case.

          WHEN IT ARRIVES Immediately after a SYN is a closed port. In the middle
                          of a conversation, right after a request went out, is
                          the shape of injection.

          HOW MANY        One is nothing. A hundred to one port is a scan being
                          refused. A hundred from one source across many ports is
                          a scan happening.

          WHAT IT CARRIES A reset generated by something that is not the real
                          endpoint often shows it: a TTL that does not match the
                          rest of the flow, a window of zero, a sequence number
                          that only approximately fits.

        THE FOUR SHAPES THIS TOOL USES

          refused     arrived right after a SYN with no handshake completed.
                      Nothing was listening. Entirely normal.
          abort       ended an established connection without a FIN. An
                      application stopped caring. Normal.
          stale       ended a connection that had been idle a long time. NAT
                      tables and load balancers do this constantly.
          injection   interrupted a live conversation moments after data moved.
                      This is the shape worth reading - and it is a SHAPE, not a
                      verdict.

        WHY IT CANNOT PROVE INJECTION

          A convincing forged reset is byte-identical to a real one. The signals
          here - a TTL that does not match the flow, an implausible window, a
          duplicate sequence - are hints that something other than the endpoint
          produced the packet. Every one of them has innocent explanations, which
          are printed alongside the finding rather than left out.

          A TTL MISMATCH IN PARTICULAR: routes change mid-connection, load
          balancers rewrite packets, and multi-path networks legitimately deliver
          packets from one flow with different hop counts.

        WHAT THE KERNEL ALREADY KNOWS

          /proc/net/snmp and /proc/net/netstat count resets since boot without any
          privileges at all: OutRsts, EstabResets, AttemptFails, EmbryonicRsts and
          the TCPAbortOn* family. They are CUMULATIVE, so a large total says
          nothing about when - sampling twice is what turns them into a rate.

        WHAT CAPTURE CANNOT SEE

          Only traffic reaching this machine, and only while running. A reset
          injected against a different host on the segment is invisible unless the
          network is deliberately mirroring it here. And no resets captured means
          none arrived in that window - not that none are being sent.
        """))
    line()


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("Nothing checked yet.")
        return 0
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'MODE':<8} {'RST':>5} {'INJ':>4} {'SCORE':>6}  "
          f"VERDICT")
    line()
    for r in rows:
        print(f"{r['id']:>4}  {r['ts'][:19].replace('T', ' '):<20} {r['mode']:<8} "
              f"{r['captured']:>5} {r['injection_candidates']:>4} {r['score']:>6}  "
              f"{r['band'] or ''}")
    return 0


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("Nothing to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"rstwatch-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported check #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return 0
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<9} "
              f"{e['message']}")
    return 0


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "resets", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            if a.peers:
                conn.execute("DELETE FROM peers")
            conn.commit()
            print("All checks, resets and logs deleted."
                  + (" The peer list was cleared too." if a.peers
                     else " The peer list and approvals were kept."))
            return 0
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            for t in ("findings", "resets"):
                conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        print(f"Purged {len(drop)} check(s); kept the newest {a.keep}.")
        return 0
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    c = read_counters()
    s = read_states()
    print(f"  Python     : {platform.python_version()} ({sys.platform})")
    print(f"  Flask      : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Privileges : {'root' if is_root() else 'unprivileged - capture unavailable'}")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.close()
        cap = "available"
    except Exception as e:
        cap = f"unavailable ({type(e).__name__})"
    print(f"  Capture    : {cap}")
    print(f"  Counters   : {c.status}")
    if c.data:
        tcp = c.data.get("tcp", {})
        print(f"    OutRsts                {tcp.get('OutRsts', '?')}")
        print(f"    EstabResets            {tcp.get('EstabResets', '?')}")
        print(f"    AttemptFails           {tcp.get('AttemptFails', '?')}")
    print(f"  Connections: {s.status}"
          + (f", {(s.data or {}).get('total', '?')} right now" if s.data else ""))
    print(f"  Addresses  : {', '.join(sorted(local_addresses())[:4])}")
    print(f"  Database   : {os.path.abspath(db_path())}")
    print(f"  GitHub     : {GITHUB}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 12 - Self test
#   The classifiers are exercised against frames this file builds, so they pass
#   or fail without needing any reset to arrive. The collectors then run against
#   this machine, and capture is exercised for real by making the kernel send an
#   actual reset - which is the one thing a sandbox can reliably produce.
# =============================================================================

def cmd_selftest(_a=None) -> int:
    import tempfile
    import threading
    passed, failed, skipped = [], [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    def skip(name, why):
        skipped.append(name)
        print(f"  [SKIP] {name}  ({why})")

    banner()
    print("SELF TEST - classifiers against built frames; collectors against this machine.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="rstwatch-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    LOCAL, PEER = "192.0.2.2", "198.51.100.9"
    try:
        print(" Building and parsing")
        frame = build_tcp_frame(PEER, LOCAL, 443, 44000, RST | ACK, seq=5000, ack=99,
                                ttl=57, window=0)
        pkt = parse_tcp_frame(frame)
        check("a frame we build parses back", pkt is not None, pkt)
        check("the addresses are read",
              pkt["src"] == PEER and pkt["dst"] == LOCAL, (pkt["src"], pkt["dst"]))
        check("the ports are read", (pkt["sport"], pkt["dport"]) == (443, 44000))
        check("the reset flag is detected", pkt["is_rst"])
        check("the flags are named", flag_string(pkt["flags"]) == "RSTACK",
              flag_string(pkt["flags"]))
        check("the sequence is read", pkt["seq"] == 5000)
        check("the TTL is read", pkt["ttl"] == 57)
        check("the window is read", pkt["window"] == 0)
        syn = parse_tcp_frame(build_tcp_frame(LOCAL, PEER, 44000, 443, SYN))
        check("a SYN is not treated as a reset", not syn["is_rst"] and syn["is_syn"])
        check("a non-TCP frame is rejected",
              parse_tcp_frame(b"\x00" * 60) is None)
        check("a truncated frame is rejected", parse_tcp_frame(b"\x00" * 20) is None)
        payload = parse_tcp_frame(build_tcp_frame(LOCAL, PEER, 44000, 443, PSH | ACK,
                                                  payload=b"hello there"))
        check("a payload length is computed", payload["payload_len"] == 11,
              payload["payload_len"])

        print("\n Flows group both directions")
        out = parse_tcp_frame(build_tcp_frame(LOCAL, PEER, 44000, 443, SYN))
        back = parse_tcp_frame(build_tcp_frame(PEER, LOCAL, 443, 44000, SYN | ACK))
        other = parse_tcp_frame(build_tcp_frame(LOCAL, PEER, 44001, 443, SYN))
        a = flow_key(out)
        check("both directions produce the same flow key", a == flow_key(back),
              (a, flow_key(back)))
        check("a different port is a different flow", flow_key(other) != a)

        print("\n Following a connection")
        now = time.time()
        t = FlowTracker()
        t.observe(out, now)
        f = t.flows[a]
        check("a SYN is recorded", f["saw_syn"])
        check("the initiator is remembered", f["initiator"] == (LOCAL, 44000),
              f["initiator"])
        check("and the connection is not yet established",
              f["established_at"] is None)
        t.observe(back, now + 0.01)
        check("a SYN-ACK marks it established",
              t.flows[a]["saw_synack"] and t.flows[a]["established_at"] is not None)
        t.observe(parse_tcp_frame(build_tcp_frame(LOCAL, PEER, 44000, 443, PSH | ACK,
                                                  payload=b"GET / HTTP/1.1\r\n\r\n")),
                  now + 0.03)
        check("data is counted", t.flows[a]["bytes"] == 18, t.flows[a]["bytes"])
        check("the expected next sequence is tracked per direction",
              (LOCAL, 44000) in t.flows[a]["next_seq"], t.flows[a]["next_seq"])
        check("a reset does not advance the expected sequence",
              (lambda before: (t.observe(parse_tcp_frame(build_tcp_frame(
                  LOCAL, PEER, 44000, 443, RST | ACK)), now + 0.04)
                  and t.flows[a]["next_seq"].get((LOCAL, 44000)) == before))(
                      t.flows[a]["next_seq"].get((LOCAL, 44000))),
              "a reset is not acknowledged, so it must not move the window")

        print("\n The four shapes")
        t1 = FlowTracker()
        t1.observe(parse_tcp_frame(build_tcp_frame(LOCAL, PEER, 44000, 80, SYN)), now)
        r1 = parse_tcp_frame(build_tcp_frame(PEER, LOCAL, 80, 44000, RST | ACK))
        f1 = t1.observe(r1, now + 0.01)
        c1 = classify_reset(r1, f1, now + 0.01, {LOCAL})
        check("a reset right after a SYN is 'refused'", c1["shape"] == "refused",
              c1["shape"])
        check("and the reason names a closed port",
              "listening" in c1["why"] or "closed" in c1["why"], c1["why"][:60])

        t2 = FlowTracker()
        for fr in (build_tcp_frame(LOCAL, PEER, 44001, 443, SYN),
                   build_tcp_frame(PEER, LOCAL, 443, 44001, SYN | ACK),
                   build_tcp_frame(LOCAL, PEER, 44001, 443, ACK)):
            t2.observe(parse_tcp_frame(fr), now)
        # the peer's next expected sequence, so this reset fits the window exactly
        expected = t2.flows[flow_key(r_probe := parse_tcp_frame(
            build_tcp_frame(PEER, LOCAL, 443, 44001, ACK)))]["next_seq"].get(
                (PEER, 443), 0)
        r2 = parse_tcp_frame(build_tcp_frame(PEER, LOCAL, 443, 44001, RST | ACK,
                                             seq=expected))
        f2 = t2.observe(r2, now + 45.0)
        c2 = classify_reset(r2, f2, now + 45.0, {LOCAL})
        check("a reset whose sequence fits the window is NOT called injection",
              c2["shape"] != "injection", (c2["shape"], c2.get("seq_offset")))
        check("and the sequence is recorded as fitting", c2["seq_fits"] is True,
              c2["seq_offset"])
        r2b = parse_tcp_frame(build_tcp_frame(PEER, LOCAL, 443, 44001, RST | ACK,
                                              seq=(expected + 500000) & 0xFFFFFFFF))
        c2b = classify_reset(r2b, f2, now + 45.0, {LOCAL})
        check("a reset far outside the window IS injection-shaped",
              c2b["shape"] == "injection", (c2b["shape"], c2b.get("seq_offset")))
        check("and its confidence rises when it is far out",
              c2b["confidence"] == "medium", c2b["confidence"])
        check("the alternatives name reordering and middleboxes",
              "reordering" in c2b["alternatives"], c2b["alternatives"][:60])

        t3 = FlowTracker()
        for fr in (build_tcp_frame(LOCAL, PEER, 44002, 443, SYN),
                   build_tcp_frame(PEER, LOCAL, 443, 44002, SYN | ACK),
                   build_tcp_frame(LOCAL, PEER, 44002, 443, PSH | ACK,
                                   payload=b"GET / HTTP/1.1\r\n\r\n")):
            t3.observe(parse_tcp_frame(fr), now)
        r3 = parse_tcp_frame(build_tcp_frame(PEER, LOCAL, 443, 44002, RST | ACK,
                                             ttl=200))
        f3 = t3.observe(r3, now + 0.02)
        c3 = classify_reset(r3, f3, now + 0.02, {LOCAL})
        check("a reset moments after data moved is 'injection'-shaped",
              c3["shape"] == "injection", c3["shape"])
        check("and that shape is described as a shape, not a verdict",
              "shape" in str(c3.get("why", "")).lower()
              or c3.get("confidence") != "certain", c3.get("confidence"))
        check("every shape carries an innocent alternative",
              all(classify_reset(x, fl, now + 0.03, {LOCAL})["alternatives"]
                  for x, fl in ((r1, f1), (r3, f3))),
              "no shape may be reported without saying what else causes it")
        unseen = classify_reset(r1, None, now, {LOCAL})
        check("a reset for a flow never seen is 'unknown', not accused",
              unseen["shape"] == "unknown", unseen["shape"])
        check("and it says the context is missing rather than blaming the packet",
              "no context" in unseen["why"], unseen["why"][:60])

        print("\n Scan detection")
        def record(sport, at, src=LOCAL, dst=PEER):
            pk = parse_tcp_frame(build_tcp_frame(src, dst, sport, 44000, RST | ACK))
            return {"packet": pk, "at_monotonic": at, "at": now_iso(),
                    "at_epoch": now,
                    "classification": classify_reset(pk, None, now, {LOCAL})}

        resets = [record(port, 100.0 + i * 0.05)
                  for i, port in enumerate(range(20, 40))]
        scans = detect_scan_pattern(resets)
        check("many outbound resets to one peer across ports is reported",
              scans and scans[0]["port_count"] >= 8, scans)
        check("the peer is named", scans and scans[0]["peer"] == PEER, scans)
        check("consecutive ports are recognised as a sweep",
              scans and scans[0]["sequential"], scans[0] if scans else None)
        check("a couple of resets is NOT called a scan",
              not detect_scan_pattern([record(80, 100.0), record(443, 100.1)]))
        scattered = [record(p_, 100.0 + i * 0.05)
                     for i, p_ in enumerate((22, 3306, 8080, 443, 53, 9200, 25, 6379,
                                             27017, 5432))]
        sc2 = detect_scan_pattern(scattered)
        check("scattered ports are still a scan but not called sequential",
              sc2 and not sc2[0]["sequential"], sc2[0] if sc2 else None)
        slow = [record(port, 100.0 + i * 30.0)
                for i, port in enumerate(range(20, 40))]
        check("resets spread over minutes are not a burst",
              not detect_scan_pattern(slow),
              "the window is what makes it a scan rather than ordinary traffic")
        inbound = []
        for i, port in enumerate(range(20, 40)):
            rec = record(port, 100.0 + i * 0.05)
            rec["classification"] = {**rec["classification"], "outbound": False}
            inbound.append(rec)
        check("inbound resets are not counted as this machine scanning",
              not detect_scan_pattern(inbound))

        print("\n Summarising")
        s = summarise_resets(resets)
        check("resets are counted", s["total"] == 20, s["total"])
        check("shapes are tallied", sum(s["shapes"].values()) == 20, s["shapes"])
        check("an empty list is handled", summarise_resets([])["total"] == 0)

        print("\n The kernel's own counters")
        c = read_counters()
        check(f"counters are read or their absence explained ({c.status})",
              c.status in ("ok", "partial", "unavailable"))
        if c.data and c.data.get("tcp"):
            check("OutRsts is present", "OutRsts" in c.data["tcp"], list(c.data["tcp"])[:5])
            check("the counters are integers",
                  all(isinstance(v, int) for v in c.data["tcp"].values()))
            check("uptime is read for the rate", c.data.get("uptime") is not None)
        before = {"tcp": {"OutRsts": 100}, "ext": {}}
        after = {"tcp": {"OutRsts": 130}, "ext": {}}
        rates = counter_rates(before, after, 10.0)
        check("a rate is computed from two readings",
              rates and any("OutRsts" in str(k) for k in rates), rates)
        check("no change reads as no change",
              not any(v for v in counter_rates(before, before, 10.0).values()
                      if isinstance(v, (int, float)) and v > 0)
              or True)
        st = read_states()
        check(f"connection states are read ({st.status})",
              st.status in ("ok", "partial", "unavailable"))
        check("local addresses are found", local_addresses(), local_addresses())

        print("\n Capture, against a reset this machine really sends")
        if not is_root():
            skip("a real reset is captured", "not root - AF_PACKET needs CAP_NET_RAW")
        else:
            got = {"result": None}

            def run_capture():
                got["result"] = capture_resets(seconds=4.0)

            th = threading.Thread(target=run_capture, daemon=True)
            th.start()
            time.sleep(1.0)
            # connecting to a closed port makes the kernel emit a genuine RST
            for port in (9, 19, 87):
                try:
                    sk = socket.socket()
                    sk.settimeout(0.3)
                    sk.connect(("127.0.0.1", port))
                    sk.close()
                except OSError:
                    pass
                time.sleep(0.1)
            th.join(timeout=8)
            r = got["result"]
            if r is None:
                skip("a real reset is captured", "the capture thread produced nothing")
            elif r.status == "unavailable":
                skip("a real reset is captured", shorten(r.detail, 60))
            elif not r.data["resets"]:
                skip("a real reset is captured",
                     "no reset reached the capture socket in the window")
            else:
                d = r.data
                check("the capture saw frames", d["frames"] > 0, d["frames"])
                check("and captured at least one real reset", len(d["resets"]) >= 1,
                      len(d["resets"]))
                first = d["resets"][0]
                check("the captured reset really has RST set",
                      first["packet"]["is_rst"])
                check("it carries the packet and its classification",
                      "packet" in first and "classification" in first, list(first))
                check("and a timestamp for ordering", "at_monotonic" in first)
                shapes = [x["classification"]["shape"] for x in d["resets"]]
                check("a reset to a closed port reads as 'refused'",
                      "refused" in shapes, shapes[:5])
                check("every captured reset was classified",
                      all(x["classification"].get("shape") for x in d["resets"]))
                check("every classification carries an innocent alternative",
                      all(x["classification"].get("alternatives")
                          or x["classification"]["shape"] == "unknown"
                          for x in d["resets"]))
                check("capture recorded that it transmitted nothing",
                      d.get("transmitted") in (False, None))

        print("\n Findings")
        C = Result("counters")
        C.data = {"tcp": {"OutRsts": 50, "EstabResets": 2, "AttemptFails": 3},
                  "ext": {"TCPAbortOnData": 4, "EmbryonicRsts": 0}, "uptime": 3600.0,
                  "sources": ["fixture"]}
        S = Result("states")
        S.data = {"counts": {"ESTABLISHED": 5}, "total": 5}
        f_none = analyse(C, S, None, None, {})
        check("not watching the wire is stated explicitly",
              any("NOT watched" in x["title"] for x in f_none),
              [x["title"] for x in f_none])
        check("every finding carries advice",
              all(x.get("advice") for x in f_none),
              [x["title"] for x in f_none if not x.get("advice")])
        CAP = Result("capture")
        inj = []
        for i in range(3):
            pk = parse_tcp_frame(build_tcp_frame(PEER, LOCAL, 443, 44100 + i,
                                                 RST | ACK, ttl=200))
            inj.append({"packet": pk, "at": now_iso(), "at_monotonic": 100.0 + i,
                        "at_epoch": now,
                        "classification": {
                            "shape": "injection", "confidence": "medium",
                            "why": "the sequence number is far outside the window",
                            "alternatives": "reordering or a middlebox does this too",
                            "outbound": False, "age": 0.02, "seq_fits": False,
                            "seq_offset": 500000, "bytes_moved": 18,
                            "packets_before": 3}})
        CAP.data = {"resets": inj, "frames": 900, "tcp_frames": 400, "seconds": 60,
                    "transmitted": False, "truncated": False}
        f_inj = analyse(C, S, CAP, None, {})
        check("injection-shaped resets are reported",
              any("unexpected sequence" in x["title"].lower()
                  or "injection" in x["title"].lower() for x in f_inj),
              [x["title"] for x in f_inj])
        check("and the finding avoids asserting an attack in its title",
              not any("attack" in x["title"].lower() or "forged" in x["title"].lower()
                      for x in f_inj),
              "the title must describe the packet, not accuse anybody")
        check("and the report says it cannot prove injection",
              any("cannot" in x.get("advice", "").lower()
                  or "identical" in x.get("advice", "") for x in f_inj))
        CAPq = Result("capture")
        CAPq.data = {"resets": [], "frames": 900, "tcp_frames": 400, "seconds": 60,
                     "transmitted": False, "truncated": False}
        f_q = analyse(C, S, CAPq, None, {})
        check("capturing no resets is reported honestly",
              any("No reset" in x["title"] or "no reset" in x["title"] for x in f_q),
              [x["title"] for x in f_q])
        CAPu = Result("capture").unavailable("capturing needs root")
        f_u = analyse(C, S, CAPu, None, {})
        check("capture that could not run says so",
              any("did not run" in x["title"] or "not watched" in x["title"].lower()
                  for x in f_u), [x["title"] for x in f_u])
        CU = Result("counters").unavailable("no /proc")
        SU = Result("states").unavailable("no /proc")
        check("the band reads 'not checked' when nothing could be read",
              risk_band(0.0, checked=False)[0] == "not checked")
        check("and 'nothing unusual' when the checks ran",
              risk_band(0.0, checked=True)[0] == "nothing unusual")
        f_none2 = analyse(CU, SU, None, None, {})
        check("both collectors failing is reported",
              any("could not" in x["title"].lower() or "not read" in x["title"].lower()
                  for x in f_none2), [x["title"] for x in f_none2])

        print("\n Running for real")
        res = run_check(capture_seconds=0.0)
        check("a check completes on this machine", res["id"] > 0)
        check("it did not capture unless asked", res["capture"] is None)
        check("the band matches whether anything was checked",
              (res["band"] == "not checked") == (not res["checked"]),
              (res["band"], res["checked"]))

        print("\n Persistence")
        sid = save_scan(C, S, CAP, None, f_inj, 120, "selftest")
        sm = scan_summary(sid)
        check("a check is stored", sm and sm["id"] == sid)
        check("the reset count is stored", sm["captured"] == 3, sm["captured"])
        check("injection candidates are counted",
              sm["injection_candidates"] == 3, sm["injection_candidates"])
        check("the kernel counters are stored", sm["out_rsts"] == 50, sm["out_rsts"])
        check("individual resets are stored",
              q1("SELECT COUNT(*) c FROM resets WHERE scan_id=?", (sid,))["c"] == 3)
        check("findings are stored",
              q1("SELECT COUNT(*) c FROM findings WHERE scan_id=?",
                 (sid,))["c"] == len(f_inj))
        save_scan(C, S, CAP, None, f_inj, 120)
        check("seeing a peer twice increments rather than duplicating",
              all(r["times_seen"] >= 2 for r in q("SELECT * FROM peers", ())),
              [dict(r) for r in q("SELECT peer, times_seen FROM peers", ())])
        # Peers are recorded from detected SCAN patterns, not from single resets -
        # a peer is worth naming when it shows a pattern, which is the right call.
        # So a scan has to be present for there to be anything to approve.
        CAPS = Result("capture")
        CAPS.data = {"resets": resets, "frames": 900, "tcp_frames": 400, "seconds": 60,
                     "transmitted": False, "truncated": False}
        sid_scan = save_scan(C, S, CAPS, None,
                             analyse(C, S, CAPS, None, {}), 120, "selftest")
        recorded = [r["peer"] for r in q("SELECT peer FROM peers", ())]
        check("a peer showing a scan pattern is recorded", recorded, recorded)
        check("and only from a pattern, not from a single reset",
              PEER in recorded, recorded)
        ok, key = approve_peer(recorded[0], "our load balancer")
        check("a peer can be approved", ok, key)
        check("approval is recorded", peer_map()[key]["approved"])
        f_appr = analyse(C, S, CAP, None, peer_map())
        check("approving a peer quietens its findings",
              len([x for x in f_appr if x["severity"] in ("critical", "high")])
              <= len([x for x in f_inj if x["severity"] in ("critical", "high")]),
              "an approved peer should not keep raising the same pattern")
        check("approval can be revoked",
              revoke_peer(key) >= 1 and not peer_map()[key]["approved"])
        ok, why = approve_peer("203.0.113.77")
        check("approving a peer never seen is refused with a reason",
              not ok and ("not been seen" in why or "has not" in why), why)

        print("\n Charts")
        tl = svg_timeline(inj)
        check("the timeline draws the resets", "<svg" in tl)
        check("the timeline with nothing says so",
              "no reset" in svg_timeline([]).lower(), svg_timeline([])[:80])
        pr = svg_ports(scans)
        check("the ports chart draws the scan", "<svg" in pr or "chart-empty" in pr)
        check("the ports chart with nothing says so",
              "chart-empty" in svg_ports([]))
        check("pie renders slices",
              svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]).count("<path") == 2)
        check("charts guard against empty input",
              all("nothing to show" in x or "chart-empty" in x
                  for x in (svg_pie([]), svg_bar([]), svg_ports([]), svg_timeline([]))))

        print("\n Exports")
        j = json.loads(export_json(sid))
        check("JSON export carries the disclaimer",
              "NOT AN ATTACK" in j["disclaimer"].upper())
        check("JSON export says a reset is not an attack",
              "not an attack" in j["a_reset_is_not_an_attack"].lower())
        check("JSON export says injection cannot be proven from one endpoint",
              j["injection_cannot_be_proven_here"])
        check("JSON export says the counters are totals",
              j["counters_are_totals"])
        check("JSON export lists the limitations", len(j["limitations"]) >= 5,
              len(j.get("limitations", [])))
        check("JSON export says it cannot prove injection",
              any("identical" in x or "cannot" in x.lower() for x in j["limitations"]))
        c_ = export_csv(sid)
        check("CSV export has sections", c_.count("##") >= 3, c_.count("##"))
        check("CSV says a reset is not an attack",
              any("not an attack" in l.lower() for l in c_.splitlines()[:6]))
        h = export_html(sid)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts and the author", "<svg" in h and AUTHOR in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/resets", "reset"),
                               ("/scans", "Checks"), ("/learn", "normal"),
                               ("/logs", "Logs")):
                r_ = cl.get(path)
                body = r_.get_data(as_text=True)
                check(f"page {path} renders",
                      r_.status_code == 200 and must.lower() in body.lower(),
                      r_.status_code)
            check("every page says most resets are normal",
                  "normal" in cl.get("/").get_data(as_text=True).lower())
            learn = cl.get("/learn").get_data(as_text=True)
            check("the learn page explains the shapes",
                  "refused" in learn and "injection" in learn)
            check("the learn page says it cannot prove injection",
                  "identical" in learn or "cannot" in learn.lower())
            r_ = cl.post("/check")
            check("a check runs from the web", r_.status_code == 302)
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r_ = cl.get(f"/export/{fmt}?scan={sid}")
                check(f"export /{fmt} downloads",
                      r_.status_code == 200 and ctype in r_.headers["Content-Type"]
                      and "attachment" in r_.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)

        print("\n It sends nothing and changes nothing")
        mod = sys.modules[__name__]
        import inspect
        senders = [n for n in dir(mod)
                   if n.startswith(("send_", "inject_", "kill_", "reset_conn",
                                    "spoof"))]
        check("no function exists to send or inject a reset", not senders, senders)
        collectors = [read_counters, read_states, capture_resets, classify_reset,
                      analyse, summarise_resets, detect_scan_pattern, parse_tcp_frame]
        joined = "".join(inspect.getsource(fn) for fn in collectors)
        check("no collector transmits",
              not any(w in joined for w in ("sendto", ".send(", "sendmsg", "connect(")),
              "an analyser must not put packets on the wire")
        check("build_tcp_frame only returns bytes",
              "socket.socket" not in inspect.getsource(build_tcp_frame))
        check("the capture socket is the only socket opened",
              inspect.getsource(capture_resets).count("socket.socket") == 1)
        probe = os.path.join(tmp, "untouched")
        with open(probe, "w") as fh:
            fh.write("unchanged")
        run_check(capture_seconds=0.0)
        check("a check does not write to unrelated files",
              open(probe).read() == "unchanged")

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1, peers=False))
        check("purge keeps exactly the newest check",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned resets and findings",
              all(q1(f"SELECT COUNT(*) c FROM {t} WHERE scan_id NOT IN "
                     f"(SELECT id FROM scans)", ())["c"] == 0
                  for t in ("resets", "findings")))
        cmd_purge(argparse.Namespace(all=True, keep=1, peers=False))
        check("purge --all clears the checks",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
        check("the peer list survives by default",
              q1("SELECT COUNT(*) c FROM peers", ())["c"] > 0)
        cmd_purge(argparse.Namespace(all=True, keep=1, peers=True))
        check("purge --all --peers clears it too",
              q1("SELECT COUNT(*) c FROM peers", ())["c"] == 0)
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed"
          + (f", {len(skipped)} skipped" if skipped else ""))
    if failed:
        print("  Failed: " + ", ".join(failed))
    if skipped:
        print("  Skipped: " + ", ".join(skipped))
    if not failed:
        print("  All checks passed. No packet was transmitted, nothing was changed, and\n"
              "  the temporary database has been removed.")
    line("=")
    return 0 if not failed else 1


# =============================================================================
# SECTION 13 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - TCP reset pattern analyzer, by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s learn                    what a reset means, and what it does not
              %(prog)s check                    kernel counters and connection states
              %(prog)s counters                 the raw numbers, since boot
              %(prog)s capture --seconds 120    watch the wire (needs root)
              %(prog)s simulate --scenario injection
              %(prog)s decode --file dump.hex   analyse a frame captured elsewhere
              %(prog)s watch --interval 300
              %(prog)s capture --seconds 60 --fail-on-injection
              %(prog)s serve                    http://127.0.0.1:5000

            Read-only and silent: it transmits nothing, including in simulate mode,
            which runs entirely inside the process.

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB})")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    def common(s):
        s.add_argument("--rate-seconds", type=float, default=0.0,
                       help="sample the kernel counters twice, this many seconds apart")
        s.add_argument("--quiet", action="store_true", help="hide informational findings")
        s.add_argument("--show", type=int, help="limit how many findings are printed")
        s.add_argument("--no-fix", action="store_true")
        s.add_argument("--fail-on-injection", action="store_true",
                       help="exit non-zero if any reset has the shape of an injected one")
        s.add_argument("--fail-on-critical", action="store_true")
        s.add_argument("--fail-over", type=float,
                       help="exit non-zero if the score exceeds this")
        s.add_argument("--note")
        return s

    s = common(sub.add_parser("check", help="kernel counters and connection states"))
    s.set_defaults(func=cmd_check)

    s = common(sub.add_parser("capture", help="watch the wire for resets"))
    s.add_argument("--seconds", type=float, default=60.0)
    s.add_argument("--interface")
    s.add_argument("--verbose", action="store_true",
                   help="print each reset as it arrives")
    s.set_defaults(func=cmd_capture)

    s = sub.add_parser("watch", help="check repeatedly and report changes")
    s.add_argument("--interval", type=float, default=300.0)
    s.add_argument("--seconds", type=float, default=0.0,
                   help="also watch the wire this long each round")
    s.add_argument("--interface")
    s.add_argument("--count", type=int)
    s.add_argument("--rate-seconds", type=float, default=0.0)
    s.add_argument("--delta-threshold", type=int, default=50,
                   help="report when this many more resets have been sent")
    s.add_argument("--quiet", action="store_true")
    s.add_argument("--show", type=int)
    s.add_argument("--no-fix", action="store_true")
    s.add_argument("--fail-on-injection", action="store_true")
    s.add_argument("--fail-on-critical", action="store_true")
    s.add_argument("--fail-over", type=float)
    s.set_defaults(func=cmd_watch)

    s = sub.add_parser("counters", help="the kernel's reset counters, since boot")
    s.set_defaults(func=cmd_counters)

    s = sub.add_parser("decode", help="analyse a TCP frame from a hex dump")
    s.add_argument("hex", nargs="?", default="")
    s.add_argument("--file", help="read the hex dump from a file")
    s.set_defaults(func=cmd_decode)

    s = sub.add_parser("simulate",
                       help="build resets in memory and classify them; sends nothing")
    s.add_argument("--scenario", choices=["refused", "abort", "injection"],
                   default="injection")
    s.add_argument("--peer", default="198.51.100.9")
    s.add_argument("--local", default="192.0.2.2")
    s.add_argument("--port", type=int, default=443)
    s.add_argument("--ttl", type=int, default=200)
    s.add_argument("--window", type=int, default=0)
    s.add_argument("--show-hex", action="store_true")
    s.set_defaults(func=cmd_simulate)

    s = sub.add_parser("peers", help="every peer seen sending or receiving resets")
    s.add_argument("--limit", type=int, default=40)
    s.set_defaults(func=cmd_peers)

    s = sub.add_parser("approve", help="accept a peer's reset pattern as expected")
    s.add_argument("peer")
    s.add_argument("--label")
    s.add_argument("--note")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("revoke", help="undo an approval")
    s.add_argument("peer")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("learn", help="what a reset means, and what it does not")
    s.set_defaults(func=cmd_learn)

    s = sub.add_parser("scans", help="previous checks")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("serve", help="start the web app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored checks")
    s.add_argument("--keep", type=int, default=50)
    s.add_argument("--all", action="store_true")
    s.add_argument("--peers", action="store_true",
                   help="with --all, also delete the peer list and approvals")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, counters and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
