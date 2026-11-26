#!/usr/bin/env python3
"""
artex-egressd — kernel-level egress control and live traffic console for ARTEX.

How the cage works
------------------
* nftables owns every decision. One `inet` table (`artex_egress`) hooks the
  forward path at priority -10, i.e. before Docker's own chains, and drops
  anything leaving the ARTEX subnet that is not explicitly allowed. A second
  chain on the input hook blocks container -> host traffic, so an agent inside
  the container can never reach this console and approve itself.
* Denied packets are logged by the kernel. This daemon tails the kernel log,
  turns every distinct destination into a "pending approval" and serves it over
  a small HTTP API. Approving or revoking rebuilds the table in one atomic nft
  transaction; there is no daemon reload and no restart.
* Outbound packets never take the `ct state established` shortcut: every one is
  checked against the allow/block sets, so removing a rule stops a live flow at
  its next packet. Matching conntrack entries are flushed on top of that.
* Allowed connections are read from /proc/net/nf_conntrack for the live view.
* The JSON state file is the source of truth; the nftables tables are
  regenerated atomically from it on every change.
* The kill switch drops traffic to/from the cage and lab subnets before the
  established-connection rules, and flushes their conntrack entries.
  Containers must use explicit Docker DNS upstreams so forwarded DNS also
  travels through their network namespace and the firewall.

Everything here is default-deny. The only ways out are: the lab subnet, an
explicitly allowed destination, and whatever the operator approves by hand.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# defaults / config
# --------------------------------------------------------------------------- #

DEFAULTS = {
    "listen": "127.0.0.1",
    "port": 9099,
    "sources": ["172.30.10.0/24"],
    "bridges": ["artex0"],
    "lab_subnets": ["172.30.20.0/24"],
    "lab_bridges": ["lab0"],
    # Freeze the cage containers while the kill switch is on.
    "killswitch_pause": True,
    # Destinations that are always allowed, no approval needed. Keep this empty
    # if you want to approve absolutely everything by hand.
    "auto_allow": [],
    "token_file": "/etc/artex-lab/ui-token",
    "state_file": "/var/lib/artex-egress/state.json",
    "events_file": "/var/lib/artex-egress/events.jsonl",
    "table": "artex_egress",
}

PROTOS = ("tcp", "udp", "icmp")

# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat(timespec="seconds")


def log(msg: str) -> None:
    sys.stderr.write("%s %s\n" % (iso(), msg))
    sys.stderr.flush()


def load_json(path: str, fallback):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return fallback
    except Exception as exc:  # corrupt state should not wedge the daemon
        log("cannot read %s (%s), using fallback" % (path, exc))
        return fallback


def save_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def parse_net(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def in_any(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


# --------------------------------------------------------------------------- #
# nftables
# --------------------------------------------------------------------------- #

NFT = shutil.which("nft") or "/usr/sbin/nft"


class NftError(RuntimeError):
    pass


def nft_run(commands: list[str], check: bool = True) -> subprocess.CompletedProcess:
    text = "\n".join(commands) + "\n"
    proc = subprocess.run(
        [NFT, "-f", "-"], input=text, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        raise NftError(proc.stderr.strip() or "nft failed")
    return proc


class Nft:
    """Renders the whole table from a rule list and applies it atomically."""

    def __init__(self, table: str):
        self.table = table

    def _set(self, name: str, kind: str, interval: bool) -> list[str]:
        flags = " flags interval ;" if interval else ""
        return ["add set inet %s %s { type %s ;%s }" % (self.table, name, kind, flags)]

    def render(self, cfg: dict, rules: list[dict], killswitch: bool) -> list[str]:
        t = self.table
        # Recreate both tables inside one transaction. `flush table` only empties
        # chains and keeps set elements, so a removed rule would stay live in the
        # kernel. add+delete+add is atomic for packets and works on first start.
        out: list[str] = []
        for fam in ("inet", "bridge"):
            out += ["add table %s %s" % (fam, t), "delete table %s %s" % (fam, t),
                    "add table %s %s" % (fam, t)]
        cage_bridges = list(cfg["bridges"]) + list(cfg.get("lab_bridges", []))

        # --- sets -------------------------------------------------------- #
        out += self._set("srcs", "ipv4_addr", True)
        for net in cfg["sources"]:
            out.append("add element inet %s srcs { %s }" % (t, net))

        out += self._set("labs", "ipv4_addr", True)
        for net in cfg["lab_subnets"]:
            out.append("add element inet %s labs { %s }" % (t, net))

        out.append("add set inet %s bridges { type ifname ; }" % t)
        for br in cfg["bridges"]:
            out.append('add element inet %s bridges { "%s" }' % (t, br))

        out.append("add set inet %s cage_bridges { type ifname ; }" % t)
        for br in cage_bridges:
            out.append('add element inet %s cage_bridges { "%s" }' % (t, br))

        # Concatenated sets (address . port) cannot carry the interval flag, so
        # these hold single addresses. ICMP sets hold plain addresses and can.
        for proto in ("tcp", "udp"):
            for action in ("allow", "block"):
                out += self._set("%s_%s" % (action, proto), "ipv4_addr . inet_service", False)
        for action in ("allow", "block"):
            out += self._set("%s_icmp" % action, "ipv4_addr", True)

        for rule in rules:
            action, proto, dst = rule["action"], rule["proto"], rule["dst"]
            if proto == "icmp":
                out.append("add element inet %s %s_icmp { %s }" % (t, action, dst))
            else:
                out.append(
                    "add element inet %s %s_%s { %s . %s }"
                    % (t, action, proto, dst, rule["port"])
                )

        # --- forward chain ----------------------------------------------- #
        out.append(
            "add chain inet %s out_chain { type filter hook forward priority -10 ; policy accept ; }" % t
        )
        # never leak over IPv6 (the bridge has none, this is belt and braces)
        out.append("add rule inet %s out_chain iifname @bridges meta nfproto ipv6 drop" % t)

        if killswitch:
            # Ahead of everything else and in both directions, for the cage and
            # the lab: a kill switch that lets a lab target keep a reverse shell,
            # or lets the host keep its UI session, is not a kill switch.
            out.append('add rule inet %s out_chain ip saddr @srcs limit rate 60/minute burst 30 packets log prefix "ARTEX-KILL " level info' % t)
            for match in ("ip saddr @srcs", "ip daddr @srcs", "ip saddr @labs", "ip daddr @labs",
                          "iifname @cage_bridges", "oifname @cage_bridges"):
                out.append("add rule inet %s out_chain %s counter drop" % (t, match))

        # Inside the cage (artex <-> postgres). Only visible here when Docker
        # has br_netfilter on; without this the database link would be dropped.
        out.append("add rule inet %s out_chain ip saddr @srcs ip daddr @srcs accept" % t)
        out.append("add rule inet %s out_chain ip saddr @srcs ip daddr @labs accept" % t)
        # Reverse shells: a lab target may call back into the ARTEX container.
        # The lab has no route anywhere else, so this widens nothing external.
        out.append("add rule inet %s out_chain ip saddr @labs ip daddr @srcs accept" % t)
        # Only replies *into* the cage ride on conntrack. Outbound packets are
        # matched against the allow/block sets every time, so deleting a rule
        # cuts a live flow at its next packet, even if conntrack still has it.
        out.append("add rule inet %s out_chain ip daddr @srcs ct state established,related accept" % t)
        for proto in ("tcp", "udp"):
            out.append(
                "add rule inet %s out_chain ip saddr @srcs meta l4proto %s ip daddr . %s dport @block_%s counter drop"
                % (t, proto, proto, proto)
            )
        for proto in ("tcp", "udp"):
            out.append(
                "add rule inet %s out_chain ip saddr @srcs meta l4proto %s ip daddr . %s dport @allow_%s counter accept"
                % (t, proto, proto, proto)
            )
        out.append("add rule inet %s out_chain ip saddr @srcs ip protocol icmp ip daddr @block_icmp counter drop" % t)
        out.append("add rule inet %s out_chain ip saddr @srcs ip protocol icmp ip daddr @allow_icmp counter accept" % t)
        out.append('add rule inet %s out_chain ip saddr @srcs limit rate 240/minute burst 120 packets log prefix "ARTEX-DENY " level info' % t)
        out.append("add rule inet %s out_chain ip saddr @srcs counter drop" % t)

        # --- input chain: container must not talk to the host ------------- #
        out.append(
            "add chain inet %s in_chain { type filter hook input priority -10 ; policy accept ; }" % t
        )
        out.append("add rule inet %s in_chain iifname @bridges meta nfproto ipv6 drop" % t)
        if killswitch:
            # Also cuts established container<->host flows (e.g. a lab target
            # holding a reverse shell into the container).
            out.append('add rule inet %s in_chain iifname @cage_bridges limit rate 60/minute burst 30 packets log prefix "ARTEX-KILL-IN " level info' % t)
            out.append("add rule inet %s in_chain iifname @cage_bridges counter drop" % t)
        out.append("add rule inet %s in_chain iifname @bridges ct state established,related accept" % t)
        out.append('add rule inet %s in_chain iifname @bridges limit rate 120/minute burst 60 packets log prefix "ARTEX-IN-DENY " level info' % t)
        out.append("add rule inet %s in_chain iifname @bridges counter drop" % t)

        if killswitch:
            # Host -> container (published ports, docker-proxy).
            out.append(
                "add chain inet %s kill_out { type filter hook output priority -10 ; policy accept ; }" % t
            )
            out.append("add rule inet %s kill_out oifname @cage_bridges counter drop" % t)
            # Bridged traffic between containers on the same network never hits
            # the inet forward hook unless br_netfilter is loaded. Cut it at L2.
            if cage_bridges:
                names = ", ".join('"%s"' % br for br in cage_bridges)
                out.append(
                    "add chain bridge %s kill_fwd { type filter hook forward priority -10 ; policy accept ; }" % t
                )
                out.append("add rule bridge %s kill_fwd meta ibrname { %s } counter drop" % (t, names))

        return out

    def apply(self, cfg: dict, rules: list[dict], killswitch: bool) -> None:
        nft_run(self.render(cfg, rules, killswitch))

    def teardown(self) -> None:
        for fam in ("inet", "bridge"):
            nft_run(["delete table %s %s" % (fam, self.table)], check=False)


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #


class State:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        data = load_json(path, {"rules": [], "killswitch": False})
        self.rules: list[dict] = data.get("rules", [])
        self.killswitch: bool = bool(data.get("killswitch", False))
        # Containers the kill switch froze, so releasing it thaws only those.
        self.paused: list[str] = list(data.get("paused", []))
        self.pending: dict[str, dict] = {}
        self.events: deque = deque(maxlen=1500)

    # ---- persistence --------------------------------------------------- #
    def save(self) -> None:
        with self.lock:
            save_json(self.path, {
                "rules": self.rules, "killswitch": self.killswitch, "paused": self.paused,
            })

    # ---- rules --------------------------------------------------------- #
    @staticmethod
    def _key(dst: str, port, proto: str) -> str:
        return "%s|%s|%s" % (dst, port if port else "-", proto)

    def find_rule(self, dst: str, port, proto: str):
        k = self._key(dst, port, proto)
        for rule in self.rules:
            if self._key(rule["dst"], rule["port"], rule["proto"]) == k:
                return rule
        return None

    def put_rule(self, dst, port, proto, action, note="", ttl=0, source="operator") -> dict:
        if proto not in PROTOS:
            raise ValueError("proto must be one of %s" % (PROTOS,))
        try:
            addr = ipaddress.ip_address(dst)
        except ValueError:
            raise ValueError("dst must be a single IP address")
        if proto == "icmp":
            port = None
        elif port is None or not (1 <= int(port) <= 65535):
            raise ValueError("port must be 1-65535")
        else:
            port = int(port)
        with self.lock:
            old = self.find_rule(dst, port, proto)
            if old:
                self.rules.remove(old)
            rule = {
                "id": uuid.uuid4().hex[:12],
                "dst": str(addr),
                "port": port,
                "proto": proto,
                "action": action,
                "note": note,
                "source": source,
                "created": iso(),
                "expires": None,
            }
            if ttl:
                rule["expires"] = datetime.fromtimestamp(
                    time.time() + ttl, timezone.utc
                ).isoformat(timespec="seconds")
            self.rules.append(rule)
            self.save()
            return rule

    def drop_rule(self, rule_id: str) -> bool:
        with self.lock:
            before = len(self.rules)
            self.rules = [r for r in self.rules if r["id"] != rule_id]
            if len(self.rules) != before:
                self.save()
                return True
            return False

    def expire(self) -> list:
        now = utcnow()
        with self.lock:
            keep, gone = [], []
            for rule in self.rules:
                exp = rule.get("expires")
                if exp:
                    try:
                        if datetime.fromisoformat(exp) <= now:
                            gone.append(rule)
                            continue
                    except ValueError:
                        pass
                keep.append(rule)
            if gone:
                self.rules = keep
                self.save()
            return gone

    # ---- pending ------------------------------------------------------- #
    def note_denied(self, src, dst, port, proto, kind) -> None:
        if proto not in PROTOS:
            return
        key = self._key(dst, port, proto)
        with self.lock:
            if self.find_rule(dst, port, proto):
                return
            rec = self.pending.get(key)
            if rec is None:
                rec = {
                    "key": key,
                    "dst": dst,
                    "port": port,
                    "proto": proto,
                    "first_seen": iso(),
                    "last_seen": iso(),
                    "count": 0,
                    "sources": [],
                }
                self.pending[key] = rec
            rec["count"] += 1
            rec["last_seen"] = iso()
            if src and src not in rec["sources"]:
                rec["sources"].append(src)

    def resolve_pending(self, key: str) -> None:
        with self.lock:
            self.pending.pop(key, None)

    # ---- events -------------------------------------------------------- #
    def event(self, kind: str, **fields) -> None:
        ev = {"t": iso(), "kind": kind}
        ev.update(fields)
        with self.lock:
            self.events.append(ev)
        try:
            with open(self.cfg_events, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev, sort_keys=True) + "\n")
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# kernel log watcher
# --------------------------------------------------------------------------- #

KV = re.compile(r"([A-Za-z0-9_]+)=(\S+)")
PROTO_NUM = {"6": "tcp", "17": "udp", "1": "icmp"}


class LogWatcher(threading.Thread):
    daemon = True

    def __init__(self, app: "App"):
        super().__init__(name="logwatch")
        self.app = app

    def _spawn(self):
        if shutil.which("journalctl"):
            return subprocess.Popen(
                ["journalctl", "-k", "-n", "0", "-f", "-o", "cat"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
            )
        return subprocess.Popen(
            ["dmesg", "-w"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )

    def run(self):
        while True:
            proc = None
            try:
                proc = self._spawn()
                for line in proc.stdout:
                    self.handle(line)
            except Exception as exc:
                log("log watcher: %s" % exc)
            finally:
                if proc and proc.poll() is None:
                    proc.kill()
            time.sleep(2)

    def handle(self, line: str) -> None:
        if "ARTEX-" not in line:
            return
        if "ARTEX-DENY " in line:
            kind = "deny"
        elif "ARTEX-IN-DENY " in line:
            kind = "in_deny"
        elif "ARTEX-KILL " in line:
            kind = "kill"
        else:
            return
        f = {k.upper(): v for k, v in KV.findall(line)}
        src, dst = f.get("SRC"), f.get("DST")
        proto = (f.get("PROTO") or "").lower()
        proto = PROTO_NUM.get(proto, proto)
        port = f.get("DPT")
        if not src or not dst:
            return
        try:
            port = int(port) if port and port.isdigit() else None
        except ValueError:
            port = None
        self.app.on_denied(kind, src, dst, port, proto)


# --------------------------------------------------------------------------- #
# conntrack
# --------------------------------------------------------------------------- #


def read_conntrack(sources) -> list[dict]:
    rows: list[dict] = []
    try:
        with open("/proc/net/nf_conntrack", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 8 or not parts[0].startswith("ipv"):
                    continue
                proto = parts[2]
                if proto not in ("tcp", "udp", "icmp"):
                    continue
                state = ""
                fields = []
                for tok in parts[3:]:
                    if "=" in tok:
                        k, _, v = tok.partition("=")
                        fields.append((k, v))
                    elif tok.isupper() or tok in ("ASSURED", "UNREPLIED"):
                        state = state or tok.strip("[]")
                tup = [v for k, v in fields if k in ("src", "dst", "sport", "dport")]
                if proto == "icmp":
                    if len(tup) < 2:
                        continue
                    src, dst, sport, dport = tup[0], tup[1], "-", "-"
                elif len(tup) >= 4:
                    src, dst, sport, dport = tup[0], tup[1], tup[2], tup[3]
                else:
                    continue
                if not in_any(src, sources):
                    continue
                nbytes = sum(int(v) for k, v in fields if k == "bytes" and v.isdigit())
                npkts = sum(int(v) for k, v in fields if k == "packets" and v.isdigit())
                rows.append({
                    "src": src, "dst": dst, "sport": sport, "dport": dport,
                    "proto": proto, "state": state,
                    "bytes": nbytes, "packets": npkts,
                })
    except (FileNotFoundError, PermissionError, OSError):
        pass
    rows.sort(key=lambda r: (r["dst"], r["dport"]))
    return rows


def kill_conntrack(row: dict) -> tuple[bool, str]:
    tool = shutil.which("conntrack")
    if not tool:
        return False, "conntrack tool not installed"
    cmd = [tool, "-D", "-s", row["src"], "-d", row["dst"], "-p", row["proto"]]
    if row["proto"] != "icmp":
        cmd += ["--sport", str(row["sport"]), "--dport", str(row["dport"])]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip()


FLOWS_DELETED = re.compile(r"(\d+) flow entr")


def _conntrack_delete(args: list[str]) -> tuple[bool, int, str]:
    """Run `conntrack -D <args>`; returns (ok, flows deleted, message)."""
    tool = shutil.which("conntrack")
    if not tool:
        return False, 0, "conntrack tool not installed"
    try:
        proc = subprocess.run([tool, "-D"] + args, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return False, 0, "conntrack timed out"
    out = (proc.stderr + "\n" + proc.stdout).strip()
    m = FLOWS_DELETED.search(out)
    # `conntrack -D` exits 1 with "0 flow entries have been deleted" when
    # nothing matched. That is the normal case, not a failure.
    if proc.returncode == 0 or m:
        return True, int(m.group(1)) if m else 0, (m.group(0) if m else out)
    return False, 0, out


def flush_conntrack(dst: str, port, proto: str, sources) -> tuple[bool, int, str]:
    """Delete the live cage flows to one destination.

    The ruleset already re-checks every outbound packet, so a revoked flow
    cannot send anything. Dropping the conntrack entries as well stops replies
    already in flight, frees the entries and keeps the live view honest.
    Scoped to the cage subnets so the VM's own flows to that IP are untouched.
    """
    ok_all, total, msgs = True, 0, []
    for net in sources:
        args = ["-s", str(net), "-d", dst, "-p", proto]
        if proto != "icmp" and port:
            args += ["--dport", str(port)]
        ok, n, msg = _conntrack_delete(args)
        ok_all &= ok
        total += n
        if not ok:
            msgs.append(msg)
    if not ok_all:
        log("conntrack flush %s:%s/%s failed: %s" % (dst, port, proto, "; ".join(msgs)))
    return ok_all, total, "; ".join(msgs) or "%d flow(s) deleted" % total


def flush_subnets(subnets) -> int:
    """Drop every conntrack entry touching these networks, both directions."""
    gone = 0
    for net in subnets:
        for direction in ("-s", "-d"):
            _, n, _ = _conntrack_delete([direction, str(net)])
            gone += n
    return gone


# --------------------------------------------------------------------------- #
# docker attribution
# --------------------------------------------------------------------------- #


def container_map() -> dict:
    if not shutil.which("docker"):
        return {}
    try:
        proc = subprocess.run(
            ["docker", "ps", "-q"], capture_output=True, text=True, timeout=5
        )
        ids = proc.stdout.split()
        if not ids:
            return {}
        proc = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"] + ids,
            capture_output=True, text=True, timeout=10,
        )
        out = {}
        for line in proc.stdout.splitlines():
            bits = line.split()
            if not bits:
                continue
            name = bits[0].lstrip("/")
            for ip in bits[1:]:
                if ip:
                    out[ip] = name
        return out
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# application
# --------------------------------------------------------------------------- #


class App:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.state = State(cfg["state_file"])
        self.state.cfg_events = cfg["events_file"]
        self.nft = Nft(cfg["table"])
        self.sources = [n for n in (parse_net(s) for s in cfg["sources"]) if n]
        self.labs = [n for n in (parse_net(s) for s in cfg["lab_subnets"]) if n]
        self.auto = [n for n in (parse_net(s) for s in cfg.get("auto_allow", [])) if n]
        self.containers: dict = {}
        self.containers_at = 0.0
        self.last_error = ""
        self.dns_error = "DNS isolation has not been verified" if self.state.killswitch else ""
        self.started = iso()
        self.nft_lock = threading.Lock()
        self.kill_lock = threading.RLock()

    # ---- lifecycle ----------------------------------------------------- #
    def start(self) -> None:
        self.nft.apply(self.cfg, self.state.rules, self.state.killswitch)
        LogWatcher(self).start()
        threading.Thread(target=self._housekeeping, daemon=True, name="house").start()
        if self.state.killswitch:
            # Docker may still be starting at boot; do not block the console.
            threading.Thread(target=self._restore_freeze, daemon=True, name="freeze").start()
        log("enforcing on %s; %d rule(s)" % (", ".join(self.cfg["sources"]), len(self.state.rules)))

    def _flush(self, dst, port, proto) -> dict:
        ok, n, detail = flush_conntrack(dst, port, proto, self.sources)
        return {"flows": n, "detail": detail, "flush_ok": ok}

    def _housekeeping(self) -> None:
        while True:
            time.sleep(10)
            try:
                expired = self.state.expire()
                if expired:
                    self.reconcile()
                    for rule in expired:
                        extra = {}
                        if rule["action"] == "allow":
                            extra = self._flush(rule["dst"], rule["port"], rule["proto"])
                        self.state.event(
                            "expire", dst=rule["dst"], port=rule["port"],
                            proto=rule["proto"], **extra,
                        )
            except Exception as exc:
                log("expiry: %s" % exc)
            if time.time() - self.containers_at > 10:
                self.containers = container_map()
                self.containers_at = time.time()

    def reconcile(self) -> bool:
        # One nft transaction at a time: concurrent batches would interleave.
        with self.nft_lock:
            try:
                self.nft.apply(self.cfg, self.state.rules, self.state.killswitch)
                self.last_error = ""
                return True
            except Exception as exc:
                self.last_error = str(exc)
                log("nft apply failed: %s" % exc)
                return False

    def _require_reconcile(self) -> None:
        if not self.reconcile():
            raise RuntimeError("nftables rejected the ruleset: %s" % self.last_error)

    # ---- callbacks ----------------------------------------------------- #
    def on_denied(self, kind: str, src: str, dst: str, port, proto: str) -> None:
        if in_any(dst, self.labs) or in_any(dst, self.auto):
            return
        if dst.startswith("224.") or dst.startswith("239.") or dst in ("255.255.255.255", "0.0.0.0"):
            return
        if proto == "icmp":
            port = None
        if self.state.find_rule(dst, port, proto):
            return
        if kind == "in_deny":
            # container talking to the host: recorded, but there is nothing to
            # approve - the host is never a legitimate target for the agent.
            self.state.event("host_denied", src=src, dst=dst, port=port, proto=proto)
            return
        if kind == "kill":
            self.state.event("kill_drop", src=src, dst=dst, port=port, proto=proto)
            return
        self.state.note_denied(src, dst, port, proto, kind)
        self.state.event("deny", src=src, dst=dst, port=port, proto=proto)

    # ---- actions ------------------------------------------------------- #
    def allow(self, dst, port, proto, ttl=0, note="") -> dict:
        rule = self.state.put_rule(dst, port, proto, "allow", note, ttl)
        self.state.resolve_pending(State._key(dst, port, proto))
        self._require_reconcile()
        self.state.event("allow", dst=dst, port=port, proto=proto, ttl=ttl, note=note)
        return rule

    def block(self, dst, port, proto, ttl=0, note="") -> dict:
        rule = self.state.put_rule(dst, port, proto, "block", note, ttl)
        self.state.resolve_pending(State._key(dst, port, proto))
        self._require_reconcile()
        extra = self._flush(dst, rule["port"], proto)
        self.state.event("block", dst=dst, port=port, proto=proto, note=note, **extra)
        return rule

    def remove(self, rule_id: str) -> bool:
        with self.state.lock:
            rule = next((r for r in self.state.rules if r["id"] == rule_id), None)
        ok = self.state.drop_rule(rule_id)
        if ok:
            self._require_reconcile()
            extra = {}
            # Revoking an allow must also revoke the flows it was holding open.
            # Removing a block is a loosening; nothing to cut.
            if rule and rule["action"] == "allow":
                extra = self._flush(rule["dst"], rule["port"], rule["proto"])
            self.state.event(
                "unblock", id=rule_id,
                dst=rule["dst"] if rule else None,
                port=rule["port"] if rule else None,
                proto=rule["proto"] if rule else None,
                **extra,
            )
        return ok

    # ---- kill switch --------------------------------------------------- #
    def _cage_containers(self) -> list[str]:
        self.containers = container_map()
        self.containers_at = time.time()
        nets = self.sources + self.labs
        return sorted({name for ip, name in self.containers.items() if in_any(ip, nets)})

    def _check_cage_dns(self) -> None:
        """Refuse to report success if Docker can forward DNS outside the cage."""
        try:
            version = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=10, check=True,
            ).stdout.strip()
            if not version.split(".", 1)[0].isdigit() or int(version.split(".", 1)[0]) < 28:
                raise RuntimeError("Docker Engine 28 or later is required for DNS isolation")
            ids = subprocess.run(
                ["docker", "ps", "-q"], capture_output=True, text=True,
                timeout=10, check=True,
            ).stdout.split()
            if not ids:
                return
            result = subprocess.run(
                ["docker", "inspect"] + ids, capture_output=True, text=True,
                timeout=20, check=True,
            )
            containers = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise RuntimeError("cannot verify container DNS configuration: %s" % exc) from exc
        unsafe = []
        for container in containers:
            networks = container.get("NetworkSettings", {}).get("Networks") or {}
            addresses = [net.get("IPAddress", "") for net in networks.values() if net]
            if any(in_any(ip, self.sources + self.labs) for ip in addresses):
                if not (container.get("HostConfig", {}).get("Dns") or []):
                    unsafe.append(container.get("Name", container.get("Id", "unknown")).lstrip("/"))
        if unsafe:
            raise RuntimeError(
                "DNS may bypass the kill switch for %s; recreate these containers "
                "with an explicit DNS server" % ", ".join(unsafe)
            )

    def _docker(self, verb: str, name: str) -> tuple[bool, str]:
        try:
            proc = subprocess.run(["docker", verb, name], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
        return proc.returncode == 0, (proc.stderr or proc.stdout).strip()

    def _freeze(self) -> list[str]:
        if not shutil.which("docker"):
            return []
        frozen = []
        for name in self._cage_containers():
            ok, msg = self._docker("pause", name)
            if ok:
                frozen.append(name)
            elif "already paused" not in msg:
                log("docker pause %s: %s" % (name, msg))
        with self.state.lock:
            self.state.paused = sorted(set(self.state.paused) | set(frozen))
            self.state.save()
        return frozen

    def _restore_freeze(self) -> None:
        with self.kill_lock:
            if self.state.killswitch:
                if self.cfg.get("killswitch_pause", True):
                    self._freeze()
                try:
                    self._validate_kill_dns()
                except RuntimeError:
                    pass

    def _validate_kill_dns(self) -> None:
        try:
            self._check_cage_dns()
            self.dns_error = ""
        except RuntimeError as exc:
            self.dns_error = str(exc)
            log("kill switch DNS check failed: %s" % exc)
            self.state.event("killswitch_dns_error", detail=str(exc))
            raise

    def _thaw(self) -> list[str]:
        with self.state.lock:
            names = list(self.state.paused)
        thawed, failed = [], []
        for name in names:
            ok, msg = self._docker("unpause", name)
            if ok:
                thawed.append(name)
            elif "not paused" not in msg:
                log("docker unpause %s: %s" % (name, msg))
                failed.append(name)
        with self.state.lock:
            self.state.paused = failed
            self.state.save()
        if failed:
            raise RuntimeError("could not resume containers: %s" % ", ".join(failed))
        return thawed

    def set_killswitch(self, on: bool) -> None:
        with self.kill_lock:
            on = bool(on)
            if on:
                self.dns_error = "DNS isolation has not been verified"
            with self.state.lock:
                previous = self.state.killswitch
                self.state.killswitch = on
                applied = self.reconcile()
                if not applied and not on:
                    self.state.killswitch = previous
                self.state.save()
            if not applied:
                raise RuntimeError("nftables rejected the ruleset: %s" % self.last_error)
            if on:
                flows = flush_subnets([str(n) for n in self.sources] + [str(n) for n in self.labs])
                frozen = self._freeze() if self.cfg.get("killswitch_pause", True) else []
                self.state.event("killswitch_on", flows=flows, frozen=frozen, applied=True)
                self._validate_kill_dns()
            else:
                self.dns_error = ""
                thawed = self._thaw()
                self.state.event("killswitch_off", thawed=thawed, applied=True)

    def snapshot(self) -> dict:
        with self.state.lock:
            rules = sorted(self.state.rules, key=lambda r: (r["dst"], str(r["port"])))
            pending = sorted(self.state.pending.values(), key=lambda r: -r["count"])
            events = list(self.state.events)[-200:]
        conns = read_conntrack(self.sources)
        for row in conns:
            row["container"] = self.containers.get(row["src"], "")
        return {
            "status": {
                "ok": not self.last_error and not self.dns_error,
                "error": self.last_error,
                "dns_error": self.dns_error,
                "killswitch": self.state.killswitch,
                "paused": list(self.state.paused),
                "started": self.started,
                "sources": self.cfg["sources"],
                "labs": self.cfg["lab_subnets"],
                "bridges": self.cfg["bridges"],
            },
            "pending": pending,
            "connections": conns,
            "rules": rules,
            "events": events,
            "containers": self.containers,
        }


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


class Handler(BaseHTTPRequestHandler):
    app: App
    token: str
    root: str
    server_version = "artex-egressd"

    # -- plumbing ------------------------------------------------------- #
    def log_message(self, fmt, *args):  # keep the journal quiet
        pass

    def _authed(self) -> bool:
        if self.client_address[0] in ("127.0.0.1", "::1"):
            return True
        if not self.token:
            return False
        if self.headers.get("X-Egress-Token") == self.token:
            return True
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "egress_token" and v == self.token:
                return True
        return False

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, data):
        self._send(code, json.dumps(data).encode(), "application/json")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode() or "{}")

    # -- routes --------------------------------------------------------- #
    def do_GET(self):
        path = urlparse(self.path).path
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})
        if path in ("/", "/index.html"):
            return self._file("index.html", "text/html; charset=utf-8")
        if path.startswith("/static/"):
            name = os.path.basename(path)
            ctype = "text/css" if name.endswith(".css") else "application/javascript"
            return self._file(name, ctype)
        if path == "/api/snapshot":
            return self._json(200, self.app.snapshot())
        if path == "/api/events":
            return self._send(200, self._events_jsonl(), "application/x-ndjson")
        if path == "/api/health":
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "not found"})

    def _file(self, name: str, ctype: str):
        full = os.path.join(self.root, name)
        try:
            with open(full, "rb") as fh:
                body = fh.read()
        except OSError:
            return self._json(404, {"error": "not found"})
        self._send(200, body, ctype)

    def _events_jsonl(self) -> bytes:
        try:
            with open(self.app.cfg["events_file"], "rb") as fh:
                return fh.read()[-2_000_000:]
        except OSError:
            return b""

    def do_POST(self):
        path = urlparse(self.path).path
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).hostname not in ("127.0.0.1", "localhost"):
            return self._json(403, {"error": "cross-origin request refused"})
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._json(415, {"error": "application/json required"})
        try:
            body = self._body()
        except Exception:
            return self._json(400, {"error": "bad json"})

        try:
            if path == "/api/allow":
                return self._json(200, self.app.allow(
                    body["dst"], body.get("port"), body.get("proto", "tcp"),
                    int(body.get("ttl") or 0), body.get("note", "")))
            if path == "/api/block":
                return self._json(200, self.app.block(
                    body["dst"], body.get("port"), body.get("proto", "tcp"),
                    int(body.get("ttl") or 0), body.get("note", "")))
            if path == "/api/rule/delete":
                ok = self.app.remove(body["id"])
                return self._json(200 if ok else 404, {"removed": ok})
            if path == "/api/killswitch":
                self.app.set_killswitch(bool(body.get("on")))
                return self._json(200, {"killswitch": self.app.state.killswitch})
            if path == "/api/pending/clear":
                self.app.state.resolve_pending(body["key"])
                return self._json(200, {"cleared": True})
            if path == "/api/conntrack/delete":
                ok, msg = kill_conntrack(body)
                self.app.state.event("conntrack_kill", ok=ok, detail=msg, **{
                    k: body.get(k) for k in ("src", "dst", "dport", "proto")
                })
                return self._json(200 if ok else 500, {"ok": ok, "detail": msg})
        except KeyError as exc:
            return self._json(400, {"error": "missing field %s" % exc})
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})
        except Exception as exc:
            return self._json(500, {"error": str(exc)})
        return self._json(404, {"error": "not found"})


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def load_config(path: str) -> dict:
    cfg = dict(DEFAULTS)
    cfg.update(load_json(path, {}))
    for key in ("sources", "bridges", "lab_subnets", "lab_bridges", "auto_allow"):
        if not isinstance(cfg.get(key), list):
            cfg[key] = list(DEFAULTS[key])
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser(description="ARTEX egress control daemon")
    ap.add_argument("-c", "--config", default="/etc/artex-lab/egress.json")
    ap.add_argument("--print-ruleset", action="store_true", help="print the nftables rules and exit")
    ap.add_argument("--apply", action="store_true", help="apply rules once and exit")
    ap.add_argument("--teardown", action="store_true", help="remove the nftables table and exit")
    args = ap.parse_args()

    cfg = load_config(args.config)

    if args.print_ruleset:
        state = State(cfg["state_file"])
        print("\n".join(Nft(cfg["table"]).render(cfg, state.rules, state.killswitch)))
        return 0

    if os.geteuid() != 0:
        log("must run as root (needs CAP_NET_ADMIN)")
        return 1

    if args.teardown:
        Nft(cfg["table"]).teardown()
        return 0

    app = App(cfg)
    app.start()
    if args.apply:
        return 0

    token = ""
    try:
        with open(cfg["token_file"], "r", encoding="utf-8") as fh:
            token = fh.read().strip()
    except OSError:
        pass

    Handler.app = app
    Handler.token = token
    Handler.root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    srv = ThreadingHTTPServer((cfg["listen"], int(cfg["port"])), Handler)
    srv.daemon_threads = True
    log("console on http://%s:%s" % (cfg["listen"], cfg["port"]))

    stopping = False

    def stop(*_):
        nonlocal stopping
        if stopping:
            return
        stopping = True
        log("shutting down (rules stay in place)")
        # shutdown() must run in a different thread from serve_forever().
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
