#!/usr/bin/env python3
"""Local dashboard: every TCP port listening on this Mac and every known project server.

Stdlib only. Serves http://127.0.0.1:7777/ (port from config.json). Nothing is exposed to
the network: the server binds 127.0.0.1 and answers only to localhost Host headers.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import json
import os
import plistlib
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import knowledge

HERE = Path(__file__).resolve().parent
HOME = Path.home()
UID = os.getuid()
USER = os.environ.get("USER") or HOME.name
AGENTS_DIR = HOME / "Library" / "LaunchAgents"
STATE_DIR = HERE / "state"
SEEN_FILE = STATE_DIR / "seen.json"
INDEX_FILE = HERE / "static" / "index.html"

# Full paths: a launchd job gets a minimal PATH.
LSOF = "/usr/sbin/lsof"
NETSTAT = "/usr/sbin/netstat"
PS = "/bin/ps"
LAUNCHCTL = "/bin/launchctl"
TOP = "/usr/bin/top"
VM_STAT = "/usr/bin/vm_stat"
SYSCTL = "/usr/sbin/sysctl"
OSASCRIPT = "/usr/bin/osascript"
HISTORY_FILE = STATE_DIR / "history.json"

DEFAULT_CONFIG = {
    "port": 7777,
    "refresh_seconds": 15,
    "scan_roots": ["~/Projects", "~/Developer", "~/code", "~/src"],
    "ignore_labels": [],
    "forget_after_days": 30,
    "sample_seconds": 10,
    "live_seconds": 2,
    "history_hours": 6,
    "alert_swap_pct": 80,
    "alert_process_mb": 2048,
    "alert_growth_mb_per_hour": 700,
    "notify": True,
}

SHELLS = {"zsh", "bash", "sh", "fish", "dash", "tcsh", "csh", "login", "tmux", "screen"}
INTERPRETERS = {"bash", "sh", "zsh", "env", "python", "python3", "node", "uv", "ruby", "perl"}
WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
SKIP_DIRS = {"node_modules", "venv", "__pycache__", "dist", "build", "target", "Library"}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    for name in ("config.json", "config.local.json"):
        path = HERE / name
        if path.is_file():
            try:
                cfg.update(json.loads(path.read_text()))
            except (OSError, ValueError) as exc:
                print(f"config: cannot read {path}: {exc}", file=sys.stderr)
    cfg["refresh_seconds"] = max(10, int(cfg.get("refresh_seconds") or 15))
    cfg["sample_seconds"] = max(5, int(cfg.get("sample_seconds") or 10))
    cfg["live_seconds"] = max(1, int(cfg.get("live_seconds") or 2))
    return cfg


def run(cmd: list[str], timeout: float = 10) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


# --------------------------------------------------------------------------- system readers

def read_processes() -> dict[int, dict]:
    procs: dict[int, dict] = {}
    for line in run([PS, "-axww", "-o", "pid=,ppid=,user=,etime=,command="]).splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        pid, ppid, user, etime = parts[:4]
        procs[int(pid)] = {"pid": int(pid), "ppid": int(ppid), "user": user, "etime": etime,
                           "command": parts[4] if len(parts) > 4 else "", "name": ""}
    # `comm` may hold spaces (app paths), so it is read on its own.
    for line in run([PS, "-axww", "-o", "pid=,comm="]).splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit() and int(parts[0]) in procs:
            procs[int(parts[0])]["comm"] = parts[1]
            procs[int(parts[0])]["name"] = os.path.basename(parts[1])
    return procs


def parse_netstat(text: str) -> list[dict]:
    """Listening sockets from `netstat -anv -p tcp`: proto, addr, port, pid."""
    pid_idx = 10
    rows = []
    for line in text.splitlines():
        if line.startswith("Proto") and "(state)" in line:
            after = line.split("(state)", 1)[1].split()
            if "pid" in after:
                pid_idx = 6 + after.index("pid")
            continue
        fields = line.split()
        if len(fields) <= pid_idx or not fields[0].startswith("tcp") or fields[5] != "LISTEN":
            continue
        addr, _, port = fields[3].rpartition(".")
        if not port.isdigit() or not fields[pid_idx].isdigit():
            continue
        rows.append({"proto": fields[0], "addr": addr, "port": int(port),
                     "pid": int(fields[pid_idx])})
    return rows


def read_listeners() -> list[dict]:
    rows = parse_netstat(run([NETSTAT, "-anv", "-p", "tcp"]))
    if rows:
        return rows
    # Fallback (own processes only): lsof.
    out = run([LSOF, "-nP", "-iTCP", "-sTCP:LISTEN", "-FpPn"])
    pid = None
    for line in out.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and pid:
            addr, _, port = line[1:].rpartition(":")
            if port.isdigit():
                rows.append({"proto": "tcp", "addr": addr.strip("[]"), "port": int(port),
                             "pid": pid})
    return rows


def read_launchctl() -> dict[str, dict]:
    jobs = {}
    for line in run([LAUNCHCTL, "list"]).splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        pid, status, label = parts
        jobs[label] = {"pid": int(pid) if pid.isdigit() else None,
                       "status": int(status) if status.lstrip("-").isdigit() else None}
    return jobs


def read_disabled() -> dict[str, bool]:
    out = run([LAUNCHCTL, "print-disabled", f"gui/{UID}"])
    return {m.group(1): m.group(2) in ("disabled", "true")
            for m in re.finditer(r'"([^"]+)"\s*=>\s*(\w+)', out)}


def read_cwds(pids: set[int]) -> dict[int, str]:
    if not pids:
        return {}
    out = run([LSOF, "-a", "-d", "cwd", "-p", ",".join(map(str, sorted(pids))), "-Fpn"])
    cwds, pid = {}, None
    for line in out.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and pid is not None:
            cwds[pid] = line[1:]
    return cwds


# --------------------------------------------------------------------------- launchd plists

PORT_PATTERNS = [
    r"--port[= ](\d{2,5})\b",
    r"(?:^|\s)-p\s*(\d{2,5})\b",
    r"http\.server\s+(\d{2,5})\b",
    r"--(?:bind|listen|host)[= ]\S*:(\d{2,5})\b",
    r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(\d{2,5})\b",
]


# Default ports of Homebrew services, keyed by formula name (homebrew.mxcl.<formula>).
HOMEBREW_PORTS = {"mysql": 3306, "mariadb": 3306, "postgresql": 5432, "redis": 6379,
                  "mongodb-community": 27017, "ollama": 11434, "memcached": 11211,
                  "rabbitmq": 5672, "nginx": 8080, "elasticsearch": 9200}


def infer_ports(args: list[str], env: dict) -> set[int]:
    text = " ".join(str(a) for a in args)
    ports = {int(p) for pat in PORT_PATTERNS for p in re.findall(pat, text)}
    for key, value in (env or {}).items():
        if key.upper().endswith("PORT") and str(value).isdigit():
            ports.add(int(value))
    return {p for p in ports if 0 < p < 65536}


def describe_schedule(d: dict) -> str:
    parts = []
    cal = d.get("StartCalendarInterval")
    for item in ([cal] if isinstance(cal, dict) else cal or []):
        if not isinstance(item, dict):
            continue
        hour, minute = item.get("Hour"), item.get("Minute")
        if hour is not None:
            when = f"{hour:02d}:{(minute or 0):02d}"
        elif minute is not None:
            when = f"hourly at :{minute:02d}"
        else:
            when = "every minute"
        if "Weekday" in item:
            when = f"{WEEKDAYS[item['Weekday'] % 8]} {when}"
        if "Day" in item:
            when = f"day {item['Day']} {when}"
        if hour is not None and "Weekday" not in item and "Day" not in item:
            when = f"daily {when}"
        parts.append(when)
    if d.get("StartInterval"):
        secs = int(d["StartInterval"])
        parts.append(f"every {secs // 3600} h" if secs % 3600 == 0 else
                     f"every {secs // 60} min" if secs % 60 == 0 else f"every {secs} s")
    if d.get("WatchPaths") or d.get("QueueDirectories"):
        parts.append("when files change")
    if d.get("StartOnMount"):
        parts.append("when a disk is mounted")
    return ", ".join(parts)


def read_plists() -> dict[str, dict]:
    jobs = {}
    for path in sorted(AGENTS_DIR.glob("*.plist")):
        try:
            d = plistlib.loads(path.read_bytes())
        except Exception:  # noqa: BLE001 - a broken plist must not break the page
            continue
        if not isinstance(d, dict):
            continue
        label = d.get("Label") or path.stem
        args = [str(a) for a in (d.get("ProgramArguments") or [])]
        if not args and d.get("Program"):
            args = [str(d["Program"])]
        env = d.get("EnvironmentVariables") or {}
        schedule = describe_schedule(d)
        keepalive = d.get("KeepAlive")
        keepalive = bool(keepalive) if not isinstance(keepalive, dict) else True
        if schedule:
            kind = "scheduled"
        elif keepalive or d.get("RunAtLoad"):
            kind = "service"
        else:
            kind = "on-demand"
        jobs[label] = {
            "label": label, "path": str(path), "file": path.name, "args": args, "env": env,
            "workdir": d.get("WorkingDirectory"), "kind": kind, "schedule": schedule,
            "disabled_key": bool(d.get("Disabled")),
            "logs": [p for p in (d.get("StandardOutPath"), d.get("StandardErrorPath")) if p],
            "ports": infer_ports(args, env),
        }
        if label.startswith("homebrew.mxcl.") and not jobs[label]["ports"]:
            formula = label[len("homebrew.mxcl."):].split("@")[0]
            if formula in HOMEBREW_PORTS:
                jobs[label]["ports"] = {HOMEBREW_PORTS[formula]}
    return jobs


# --------------------------------------------------------------------------- launch.json

_launch_cache: dict = {"at": 0.0, "roots": None, "files": []}


def find_launch_jsons(roots: list[str], max_depth: int = 3) -> list[Path]:
    now = time.time()
    if _launch_cache["roots"] == roots and now - _launch_cache["at"] < 60:
        return _launch_cache["files"]
    found: list[Path] = []

    def walk(d: Path, depth: int) -> None:
        candidate = d / ".claude" / "launch.json"
        if candidate.is_file():
            found.append(candidate)
        if depth >= max_depth:
            return
        try:
            entries = list(os.scandir(d))
        except OSError:
            return
        for e in entries:
            if (not e.name.startswith(".") and e.name not in SKIP_DIRS
                    and e.is_dir(follow_symlinks=False)):
                walk(Path(e.path), depth + 1)

    for root in roots:
        walk(Path(root).expanduser(), 0)
    _launch_cache.update(at=now, roots=list(roots), files=found)
    return found


def read_launch_configs(roots: list[str]) -> list[dict]:
    configs = []
    for path in find_launch_jsons(roots):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        project = path.parent.parent
        for c in data.get("configurations") or []:
            if not isinstance(c, dict):
                continue
            port = c.get("port")
            if port is None and c.get("url"):
                m = re.search(r":(\d{2,5})(?:/|$)", str(c["url"]))
                port = int(m.group(1)) if m else None
            cmd = " ".join([str(c.get("runtimeExecutable") or "")] +
                           [str(a) for a in c.get("runtimeArgs") or []]).strip()
            configs.append({
                "name": c.get("name") or "?", "file": str(path), "project": str(project),
                "port": int(port) if str(port or "").isdigit() else None,
                "command": cmd, "cwd": str(project / c["cwd"]) if c.get("cwd") else str(project),
                "url": c.get("url"),
            })
    return configs


# --------------------------------------------------------------------------- helpers

def etime_seconds(etime: str) -> int:
    days = 0
    if "-" in etime:
        d, etime = etime.split("-", 1)
        days = int(d)
    nums = [int(x) for x in etime.split(":") if x.isdigit()]
    while len(nums) < 3:
        nums.insert(0, 0)
    h, m, s = nums[-3:]
    return days * 86400 + h * 3600 + m * 60 + s


def git_root(path: str) -> str | None:
    try:
        p = Path(path)
        if not p.is_dir():
            p = p.parent
        p = p.resolve()
    except (OSError, RuntimeError):
        return None
    for d in [p, *p.parents]:
        if d == HOME or d == d.parent:
            return None
        if (d / ".git").exists():
            return str(d)
    return None


HOME_PATH_RE = re.compile(re.escape(str(HOME)) + r"/[^\s\"':;,]+")


def guess_project(candidates: list[str]) -> str | None:
    """The git repo (or else the folder under ~) that a process belongs to."""
    paths = []
    for c in candidates:
        if not c:
            continue
        if c.startswith("/"):
            paths.append(c)
        paths.extend(HOME_PATH_RE.findall(c))
    inside = [p for p in paths if p.startswith(str(HOME) + "/")]
    for p in inside:
        root = git_root(p)
        if root and "/.claude/worktrees/" in root:
            root = root.split("/.claude/worktrees/")[0]  # a session's worktree -> its repo
        if root and not is_tool_dir(root):
            return root
    for p in inside:
        d = p if os.path.isdir(p) else os.path.dirname(p)
        if not d or d == str(HOME) or is_tool_dir(d):
            continue
        return d
    return None


def is_tool_dir(d: str) -> bool:
    """Where interpreters and tools live, not projects: ~/.nvm (a git clone itself),
    ~/.local/bin, ~/bin, ~/Library."""
    rel = os.path.relpath(d, HOME)
    parts = rel.split(os.sep)
    return (d.startswith(str(HOME / "Library")) or any(part.startswith(".") for part in parts)
            or parts[0] in ("bin", "go", "miniconda3", "anaconda3"))


def is_loopback(addr: str) -> bool:
    return addr.startswith("127.") or addr in ("::1", "localhost") or addr.endswith("%lo0")


def probe_target(listen: list[dict]) -> tuple[str | None, str | None]:
    """(host to probe, host for the link) for a set of listening addresses."""
    v4 = v6 = other = None
    for row in listen:
        a = row["addr"]
        if a == "*":
            if row["proto"] in ("tcp4", "tcp46"):
                v4 = "127.0.0.1"
            else:
                v6 = v6 or "::1"
        elif a.startswith("127."):
            v4 = a
        elif a == "::1":
            v6 = "::1"
        elif not a.startswith("fe80"):
            other = other or a
    if v4 or v6:
        return v4 or v6, "localhost"
    if other:
        return other, f"[{other}]" if ":" in other else other
    return None, None


_probe_cache: dict[tuple, tuple[float, dict | None, float]] = {}


def probe_http(host: str, port: int, wait: float = 5.0) -> tuple[dict | None, bool]:
    """GET / on a port: (status/title or None, whether the answer is final).

    Slow pages (some build their first response from a remote database) get `wait` seconds
    for the first byte; a port that stays silent until then is "unknown", not "not HTTP".
    """
    data = b""
    timed_out = False
    try:
        with socket.create_connection((host, port), timeout=1.0) as s:
            s.sendall(f"GET / HTTP/1.0\r\nHost: localhost:{port}\r\nAccept: text/html\r\n"
                      f"User-Agent: porthole\r\nConnection: close\r\n\r\n".encode())
            deadline = time.monotonic() + wait
            while len(data) < 65536:
                left = deadline - time.monotonic()
                if left <= 0:
                    timed_out = True
                    break
                s.settimeout(left)
                try:
                    chunk = s.recv(8192)
                except socket.timeout:
                    timed_out = True
                    break
                except OSError:
                    break
                if not chunk:
                    break
                data += chunk
                if b"</title>" in data.lower():
                    break
    except socket.timeout:
        timed_out = True
    except OSError:
        pass
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", data)
    if not m:
        return None, not (timed_out and not data)
    head, _, body = data.partition(b"\r\n\r\n")
    title = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    loc = re.search(rb"\r\nlocation:\s*([^\r\n]+)", head, re.I)
    ctype = re.search(rb"\r\ncontent-type:\s*([^\r\n;]+)", head, re.I)
    status = int(m.group(1))
    is_html = bool(ctype and b"html" in ctype.group(1).lower()) or bool(title) or \
        body.lstrip()[:15].lower().startswith((b"<!doctype html", b"<html"))
    # Only a real page earns a link: an API, a login wall or "404 at /" is not one.
    if 300 <= status < 400:
        kind = "page"
    elif 200 <= status < 300:
        kind = "page" if is_html else "api"
    elif status in (401, 403):
        kind = "auth"
    elif status == 426:
        kind = "websocket"
    else:
        kind = "nopage"
    return {
        "status": status, "kind": kind,
        "title": re.sub(r"\s+", " ", html.unescape(title.group(1).decode("utf-8", "replace")))
        .strip()[:120] if title else "",
        "location": loc.group(1).decode("utf-8", "replace").strip()[:200] if loc else "",
    }, True


def probe_cached(key: tuple, host: str, port: int) -> dict | None:
    now = time.time()
    hit = _probe_cache.get(key)
    # A firm "not HTTP" is kept for 5 min: no point poking a database tunnel every refresh.
    if hit and now - hit[0] < hit[2]:
        return hit[1]
    result, final = probe_http(host, port)
    if result:
        ttl = 20
    elif final:
        ttl = 300
    elif hit and hit[1]:
        # Timed out after answering before: keep the last answer so the link does not
        # flicker, and retry soon.
        result, ttl = hit[1], 20
    else:
        ttl = 300  # silent from the start: treat as not HTTP for a while
    _probe_cache[key] = (now, result, ttl)
    return result


def exit_text(status: int | None) -> str:
    if status is None or status == 0:
        return ""
    if status < 0:
        sig = -status
        names = {9: "SIGKILL", 15: "SIGTERM", 6: "SIGABRT", 11: "SIGSEGV", 2: "SIGINT"}
        return f"killed by signal {sig}" + (f" ({names[sig]})" if sig in names else "")
    if status > 128 and status - 128 < 32:
        return f"exit code {status} (signal {status - 128})"
    return f"exit code {status}"


# --------------------------------------------------------------------------- resources

def parse_size(text: str) -> int:
    """top's MEM column: 1215M, 12K, 1.2G, 900B, maybe with a trailing + or -."""
    m = re.match(r"([\d.]+)([BKMGT]?)", text.strip())
    if not m:
        return 0
    mult = {"": 1, "B": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m.group(2)]
    return int(float(m.group(1)) * mult)


def parse_top(text: str) -> dict:
    """The last sample of `top -l 2`: CPU usage and per-process footprint (= Activity
    Monitor's "Memory") and CPU %. The first sample's CPU is meaningless, so it is skipped."""
    samples = text.split("Processes:")
    last = samples[-1] if len(samples) > 1 else text
    cpu = {"user": 0.0, "sys": 0.0, "idle": 100.0}
    m = re.search(r"CPU usage:\s*([\d.]+)% user,\s*([\d.]+)% sys,\s*([\d.]+)% idle", last)
    if m:
        cpu = {"user": float(m.group(1)), "sys": float(m.group(2)), "idle": float(m.group(3))}
    procs: dict[int, dict] = {}
    in_table = False
    for line in last.splitlines():
        if line.startswith("PID"):
            in_table = True
            continue
        if not in_table:
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            try:
                cpu_pct = float(parts[2])
            except ValueError:
                cpu_pct = 0.0
            procs[int(parts[0])] = {"mem": parse_size(parts[1]), "cpu": cpu_pct}
    return {"cpu": cpu, "procs": procs}


def read_top(limit: int = 120) -> dict:
    cmd = [TOP, "-l", "2", "-s", "1", "-o", "mem", "-n", str(limit), "-stats", "pid,mem,cpu"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"top failed: {exc}", file=sys.stderr)
        return {"cpu": {"user": 0.0, "sys": 0.0, "idle": 100.0}, "procs": {}}
    result = parse_top(r.stdout)
    if not result["procs"]:
        print(f"top gave no processes (code {r.returncode}): {r.stderr.strip()[:300]!r} "
              f"{r.stdout[:200]!r}", file=sys.stderr)
    return result


def sysctl(*names: str) -> dict[str, str]:
    out = run([SYSCTL] + list(names))
    values = {}
    for line in out.splitlines():
        key, sep, val = line.partition(":")
        if sep:
            values[key.strip()] = val.strip()
    return values


def read_vm() -> dict:
    """Memory the way Activity Monitor counts it, plus swap, pressure and load."""
    out = run([VM_STAT])
    page = int(m.group(1)) if (m := re.search(r"page size of (\d+)", out)) else 16384
    pages = {k.strip().strip('"'): int(v.strip().rstrip("."))
             for k, v in re.findall(r"^([^:\n]+):\s+(\d+)\.?$", out, re.M)}
    sc = sysctl("hw.memsize", "vm.swapusage", "kern.memorystatus_vm_pressure_level",
                "kern.memorystatus_level", "hw.ncpu", "vm.loadavg")
    total = int(sc.get("hw.memsize") or 0)
    g = lambda name: pages.get(name, 0) * page  # noqa: E731
    app = max(0, g("Anonymous pages") - g("Pages purgeable"))
    wired = g("Pages wired down")
    compressed = g("Pages occupied by compressor")
    cached = g("File-backed pages") + g("Pages purgeable")
    used = app + wired + compressed
    swap = {"total": 0, "used": 0}
    for key, val in re.findall(r"(total|used) = ([\d.]+)M", sc.get("vm.swapusage", "")):
        swap[key] = int(float(val) * (1 << 20))
    level = sc.get("kern.memorystatus_vm_pressure_level", "1")
    pressure = {"1": "normal", "2": "warn", "4": "critical"}.get(level, "normal")
    load = [float(x) for x in re.findall(r"[\d.]+", sc.get("vm.loadavg", ""))[:3]]
    return {"total": total, "used": used, "app": app, "wired": wired,
            "compressed": compressed, "cached": cached,
            "free": max(0, total - used - cached), "swap": swap, "pressure": pressure,
            "free_pct": int(sc.get("kern.memorystatus_level") or 0),
            "ncpu": int(sc.get("hw.ncpu") or 1), "load": load}


def read_disk(path: str = "/System/Volumes/Data") -> dict:
    try:
        st = os.statvfs(path if os.path.exists(path) else "/")
    except OSError:
        return {"total": 0, "free": 0}
    return {"total": st.f_blocks * st.f_frsize, "free": st.f_bavail * st.f_frsize}


APP_RE = re.compile(r"/([^/]+)\.app/")
# Bundles that only host something else (an interpreter): grouped by project instead.
HOST_APPS = {"Python", "plugin-container", "Electron"}
APP_ALIASES = {"claude": "Claude Code (sessions)"}


def group_key(proc: dict) -> tuple[str, str]:
    """('app', name) for an app bundle and its helpers, else ('proc', '')."""
    comm = proc.get("comm", "")
    names = [m.group(1) for m in APP_RE.finditer(comm)]
    # An interpreter bundle runs someone's script, wherever it lives: Xcode's
    # .../Xcode.app/.../Python.app/.../Python is your project, not Xcode.
    if not names or names[-1] == "Python":
        return "proc", ""
    # The outermost bundle names the app: Chrome Helper (Renderer) -> Google Chrome,
    # Firefox.app/.../plugin-container.app -> Firefox.
    name = next((n for n in names if n not in HOST_APPS), None)
    if name is None:
        return "proc", ""
    return "app", APP_ALIASES.get(name, name)


TOP_ROWS = 120
LIVE_HOLD_S = 8  # live sampling stays on this long after the page last asked


class TopStream:
    """One long-running `top -l 0` instead of a new `top` per sample.

    A fresh `top -l 2 -s 1` costs ~0.6 s CPU and a fork/exec, which crawls when the
    machine is swapping; a running one costs ~0.1 s CPU per sample and only wakes up
    on its interval. The interval is switched (by restarting it) between the slow
    background pace and the live pace while the page is being watched.
    """

    def __init__(self, on_sample):
        self.on_sample = on_sample
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.interval = 0
        self.started_at = 0.0
        self.last_at = 0.0

    def ensure(self, interval: int) -> None:
        with self.lock:
            alive = self.proc is not None and self.proc.poll() is None
            stalled = alive and time.time() - max(self.last_at, self.started_at) > interval * 3 + 10
            if alive and self.interval == interval and not stalled:
                return
            if stalled:
                print(f"top stream silent for {time.time() - self.last_at:.0f} s: restarting",
                      file=sys.stderr)
            self._stop()
            cmd = [TOP, "-l", "0", "-s", str(interval), "-o", "mem", "-n", str(TOP_ROWS),
                   "-stats", "pid,mem,cpu"]
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, text=True,
                                             errors="replace", bufsize=1)
            except OSError as exc:
                print(f"top stream failed to start: {exc}", file=sys.stderr)
                self.proc = None
                return
            self.interval = interval
            self.started_at = time.time()
            threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def _stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def _read(self, proc: subprocess.Popen) -> None:
        # A sample is complete once its table has TOP_ROWS rows (top flushes per sample);
        # the next "Processes:" line also closes it, in case fewer processes exist.
        buf: list[str] = []
        rows, first = -1, True  # rows = -1 until the "PID" header of the table
        assert proc.stdout is not None
        for line in proc.stdout:
            if line.startswith("Processes:"):
                if buf:
                    self._emit(buf, first)
                    first = False
                buf, rows = [], -1
            elif not buf:
                continue  # tail of a sample already emitted
            buf.append(line)
            if line.startswith("PID"):
                rows = 0
            elif rows >= 0 and line[:1].isdigit():
                rows += 1
                if rows == TOP_ROWS:
                    self._emit(buf, first)
                    first, buf, rows = False, [], -1
        proc.stdout.close()

    def _emit(self, lines: list[str], first: bool) -> None:
        self.last_at = time.time()
        try:
            # The first sample of a run has no CPU deltas: its CPU numbers are bogus.
            self.on_sample(parse_top("".join(lines)), first)
        except Exception as exc:  # noqa: BLE001 - never kill the reader
            print(f"sample failed: {exc}", file=sys.stderr)


class Sampler:
    """Samples memory/CPU in the background so the page gets them at once, keeps history
    for the charts and per-process footprint for an hour to spot growth (leaks)."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.latest: dict | None = None
        self.history: list[list[float]] = []  # [t, used, swap_used, cpu_pct, compressed]
        self.proc_hist: dict[tuple[int, str], list[tuple[float, int]]] = {}
        self.alerted: dict[str, float] = {}
        self.saved_at = time.time()
        self.procs_at = 0.0
        self.live_until = 0.0
        self.stream = TopStream(self._on_top)
        try:
            data = json.loads(HISTORY_FILE.read_text())
            cutoff = time.time() - cfg["history_hours"] * 3600
            self.history = [p for p in data.get("history", []) if p[0] >= cutoff]
        except (OSError, ValueError):
            pass

    def _on_top(self, top: dict, first: bool) -> None:
        if first and self.latest is not None:
            # A fresh top has no CPU deltas yet: keep its memory, borrow the last CPU.
            top = {"cpu": self.latest["cpu"], "procs": {
                pid: {**p, "cpu": self.latest["top"].get(pid, {}).get("cpu", 0.0)}
                for pid, p in top["procs"].items()}}
        self.sample(top)

    def touch_live(self) -> None:
        was_live = self.live
        self.live_until = time.time() + LIVE_HOLD_S
        if not was_live:  # switch the pace now, not on the next loop turn
            self.stream.ensure(self.cfg["live_seconds"])

    @property
    def live(self) -> bool:
        return time.time() < self.live_until

    def sample(self, top: dict | None = None) -> dict:
        if top is None:
            top = read_top()
        if not top["procs"] and self.latest:
            # top timed out or was killed: keep the last table rather than show nothing.
            top = {"cpu": self.latest["cpu"], "procs": self.latest["top"]}
        vm = read_vm()
        now = time.time()
        cpu = top["cpu"]
        snap = {"t": now, "vm": vm, "cpu": cpu, "disk": read_disk(), "top": top["procs"]}
        # Live samples come every couple of seconds; history and per-process memory keep
        # the slow pace so the chart, the file and the growth math stay the same size.
        slow = self.cfg["sample_seconds"] - 0.5
        point = [round(now, 1), vm["used"], vm["swap"]["used"],
                 round(cpu["user"] + cpu["sys"], 1), vm["compressed"]]
        snap["point"] = point
        commands = None
        if now - self.procs_at >= slow and top["procs"]:
            commands = {pid: p["command"] for pid, p in read_processes().items()}
        with self.lock:
            self.latest = snap
            if not self.history or now - self.history[-1][0] >= slow:
                self.history.append(point)
            cutoff = now - self.cfg["history_hours"] * 3600
            while self.history and self.history[0][0] < cutoff:
                self.history.pop(0)
            if commands is not None:
                self._remember_procs(now, top["procs"], commands)
                self.procs_at = now
            if now - self.saved_at > 300:
                self._save()
        return snap

    def _remember_procs(self, now: float, procs: dict[int, dict],
                        commands: dict[int, str]) -> None:
        # One point a minute, 65 minutes back; keyed by pid + command so a reused pid
        # does not look like growth.
        alive = set()
        for pid, p in procs.items():
            key = (pid, commands.get(pid, ""))
            alive.add(key)
            hist = self.proc_hist.setdefault(key, [])
            if not hist or now - hist[-1][0] >= 60:
                hist.append((now, p["mem"]))
            else:
                hist[-1] = (hist[-1][0], max(hist[-1][1], p["mem"]))
            while hist and now - hist[0][0] > 65 * 60:
                hist.pop(0)
        for key in [k for k in self.proc_hist if k not in alive]:
            del self.proc_hist[key]

    def growth(self, pid: int, command: str, mem_now: int) -> tuple[int | None, int]:
        """(bytes grown over the last hour or since first seen, minutes covered)."""
        with self.lock:
            hist = self.proc_hist.get((pid, command))
            if not hist or time.time() - hist[0][0] < 10 * 60:
                return None, 0
            return mem_now - hist[0][1], int((time.time() - hist[0][0]) / 60)

    def _save(self) -> None:
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            tmp = HISTORY_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps({"history": self.history}))
            os.replace(tmp, HISTORY_FILE)
            self.saved_at = time.time()
        except OSError as exc:
            print(f"history: cannot save: {exc}", file=sys.stderr)

    def snapshot(self) -> tuple[dict | None, list]:
        with self.lock:
            return self.latest, list(self.history)

    def run_forever(self) -> None:
        """Keeps one `top` running at the right pace: live while the page is watched,
        slow otherwise; restarts it when it dies or goes silent."""
        while True:
            pace = self.cfg["live_seconds"] if self.live else self.cfg["sample_seconds"]
            try:
                self.stream.ensure(pace)
            except Exception as exc:  # noqa: BLE001
                print(f"sampler failed: {exc}", file=sys.stderr)
            time.sleep(1)

    def notify(self, alerts: list[dict]) -> None:
        """macOS notification for an alert that is new or came back after an hour."""
        if not self.cfg.get("notify"):
            return
        now = time.time()
        for a in alerts:
            if a["level"] != "bad" or now - self.alerted.get(a["key"], 0) < 3600:
                continue
            self.alerted[a["key"]] = now
            script = (f"display notification {json.dumps(a['text'])} "
                      f"with title \"porthole\"")
            try:
                subprocess.Popen([OSASCRIPT, "-e", script], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            except OSError:
                pass


_CWD_LOCK = threading.Lock()
_CWD_CACHE: dict[int, tuple[str, str]] = {}  # pid -> (command, cwd)


def cached_cwds(pids: set[int], procs: dict[int, dict]) -> dict[int, str]:
    """`lsof` only for processes not seen before: a cwd almost never changes, and the
    live view regroups every couple of seconds."""
    with _CWD_LOCK:
        missing = {p for p in pids
                   if p not in _CWD_CACHE or _CWD_CACHE[p][0] != procs[p]["command"]}
        if missing:
            got = read_cwds(missing)
            for pid in missing:
                _CWD_CACHE[pid] = (procs[pid]["command"], got.get(pid, ""))
        for pid in [p for p in _CWD_CACHE if p not in procs]:
            del _CWD_CACHE[pid]
        return {p: _CWD_CACHE[p][1] for p in pids if _CWD_CACHE[p][1]}


def slim_groups(groups: list[dict], open_keys: set[str], flat: bool = False) -> dict:
    """Child processes only for the groups the page has expanded (and one-process
    groups, whose row carries the kill button): cuts the payload ~5x. With `flat`,
    every process as one list for the "all processes" view."""
    out = {"groups": [g if not flat and (g["key"] in open_keys or g["count"] == 1)
                      else {**g, "pids": []} for g in groups]}
    if flat:
        out["procs"] = [{**p, "group": g["key"], "group_name": g["name"]}
                        for g in groups for p in g["pids"]]
    return out


SYSTEM_PREFIXES = ("/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/")


_DESC_CACHE: dict[tuple, tuple[dict, dict, str]] = {}


def cmd_id(command: str) -> str:
    """Short fingerprint of a full command line: the page sends it back with a kill so a
    reused pid is never killed, without shipping kilobytes of browser flags each tick."""
    return hashlib.sha1(command.encode("utf-8", "replace")).hexdigest()[:16]


def build_processes(snap: dict, procs: dict[int, dict], pid2label: dict, plists: dict,
                    sampler: Sampler, pid_ports: dict[int, list[int]] | None = None
                    ) -> list[dict]:
    """Processes grouped as you think of them: an app with all its helpers, or a
    project's processes; sorted by footprint. Each process carries a short human
    description (knowledge.describe)."""
    top = snap["top"]
    pid_ports = pid_ports or {}
    candidates = [pid for pid in top if pid in procs]
    plain = [pid for pid in candidates if group_key(procs[pid])[0] == "proc"]
    plain = sorted(plain, key=lambda p: -top[p]["mem"])[:80]
    cwds = cached_cwds(set(plain), procs)
    groups: dict[str, dict] = {}
    for pid in candidates:
        proc = procs[pid]
        kind, name = group_key(proc)
        app = name if kind == "app" else None
        project = None
        if kind == "proc":
            if pid in cwds or pid in plain:
                project = guess_project([cwds.get(pid, ""), proc["command"]])
            name = project.split("/")[-1] if project else proc["name"] or "?"
            kind = "project" if project else "proc"
        key = f"{kind}:{project or name}"
        mem, cpu = top[pid]["mem"], top[pid]["cpu"]
        grown, minutes = sampler.growth(pid, proc["command"], mem)
        is_system = proc["user"] != USER or proc.get("comm", "").startswith(SYSTEM_PREFIXES)
        g = groups.setdefault(key, {
            "key": key, "kind": kind, "name": name, "project": project, "mem": 0, "cpu": 0.0,
            "growth": None, "growth_minutes": 0, "pids": [], "ports": [],
            "system": is_system})
        g["mem"] += mem
        g["cpu"] += cpu
        if grown is not None:
            g["growth"] = (g["growth"] or 0) + grown
            g["growth_minutes"] = max(g["growth_minutes"], minutes)
        ports = pid_ports.get(pid, [])
        g["ports"] += ports
        # Who started it and what it is do not change for a living process: cache them
        # per process and per launchd snapshot (plists is re-read every 15 s).
        ck = (pid, proc["command"], id(plists), project, tuple(ports))
        hit = _DESC_CACHE.get(ck)
        if hit is None:
            origin = classify_origin(pid, procs, pid2label, plists)
            hit = (origin, knowledge.describe(proc, origin, project, app, ports),
                   cmd_id(proc["command"]))
            if len(_DESC_CACHE) > 3000:
                _DESC_CACHE.clear()
            _DESC_CACHE[ck] = hit
        origin, desc, cid = hit
        g["pids"].append({"pid": pid, "name": proc["name"], "mem": mem, "cpu": cpu,
                          "command": proc["command"][:200], "cmd_id": cid,
                          "user": proc["user"],
                          "uptime_s": etime_seconds(proc["etime"]), "growth": grown,
                          "origin": origin, "own": proc["user"] == USER and pid != os.getpid(),
                          "system": is_system, "ports": ports, "project": project,
                          "desc": desc["short"], "hint": desc["hint"]})
    result = sorted(groups.values(), key=lambda g: -g["mem"])
    for g in result:
        g["pids"].sort(key=lambda p: -p["mem"])
        g["count"] = len(g["pids"])
        g["cpu"] = round(g["cpu"], 1)
        g["ports"] = sorted(set(g["ports"]))
        labels = {p["origin"].get("label") for p in g["pids"]
                  if p["origin"]["kind"] == "launchd"}
        g["labels"] = sorted(label for label in labels if label)
        g["origin"] = g["pids"][0]["origin"]["text"]
        g["uptime_s"] = max(p["uptime_s"] for p in g["pids"])
        if g["kind"] == "app":
            g["desc"] = knowledge.describe_app(g["name"])
        elif g["count"] == 1:
            g["desc"] = g["pids"][0]["desc"]
        else:
            g["desc"] = (knowledge.plural(g["count"], "process", "processes")
                         + f" · main: {g['pids'][0]['desc']}")
        g["hint"] = g["pids"][0]["hint"]
        g["pids"] = g["pids"][:40]
    return result


def build_alerts(cfg: dict, snap: dict, groups: list[dict]) -> list[dict]:
    alerts = []
    vm = snap["vm"]
    if vm["pressure"] != "normal":
        alerts.append({"key": "pressure", "level": "bad" if vm["pressure"] == "critical"
                       else "warn", "text": "Memory pressure: " +
                       ("critical" if vm["pressure"] == "critical" else "elevated")})
    swap = vm["swap"]
    if swap["total"] and swap["used"] * 100 / swap["total"] >= cfg["alert_swap_pct"]:
        alerts.append({"key": "swap", "level": "bad",
                       "text": f"Swap {swap['used'] * 100 // swap['total']}% full "
                               f"({swap['used'] / (1 << 30):.1f} GB)"})
    big = cfg["alert_process_mb"] << 20
    grow = cfg["alert_growth_mb_per_hour"] << 20
    for g in groups:
        if g["kind"] != "app" and not g["system"] and g["mem"] >= big:
            alerts.append({"key": f"big:{g['key']}", "level": "bad", "group": g["key"],
                           "text": f"{g['name']} holds {g['mem'] / (1 << 30):.1f} GB"})
        if g["growth"] and g["growth_minutes"] and \
                g["growth"] * 60 / max(g["growth_minutes"], 30) >= grow:
            alerts.append({"key": f"grow:{g['key']}", "level": "warn", "group": g["key"],
                           "text": f"{g['name']} grew by {g['growth'] / (1 << 20):.0f} MB "
                                   f"in {g['growth_minutes']} min"})
    return alerts


def monitor_state(cfg: dict, sampler: Sampler, procs: dict, pid2label: dict,
                  plists: dict, pid_ports: dict[int, list[int]] | None = None) -> dict | None:
    snap, history = sampler.snapshot()
    if snap is None:
        return None
    groups = build_processes(snap, procs, pid2label, plists, sampler, pid_ports)
    alerts = build_alerts(cfg, snap, groups)
    sampler.notify(alerts)
    # The chart needs ~300 points at most: thin the history evenly.
    step = max(1, len(history) // 360)
    return {"sampled_at": snap["t"], "vm": snap["vm"], "cpu": snap["cpu"],
            "disk": snap["disk"], "history": history[::step], "groups": groups,
            "alerts": alerts, "sample_seconds": cfg["sample_seconds"],
            "live_seconds": cfg["live_seconds"], "live": sampler.live,
            "history_hours": cfg["history_hours"]}


# --------------------------------------------------------------------------- memory

class Memory:
    """Ports each launchd job was seen on, and servers started by hand (to spot them gone)."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.saved_at = 0.0
        try:
            self.data = json.loads(path.read_text())
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("labels", {})
        self.data.setdefault("manual", {})
        # Records written before worth_remembering existed: unreadable processes ("?"),
        # empty commands, random ports and app helpers.
        junk = [k for k, r in self.data["manual"].items()
                if r.get("name") in (None, "", "?") or not r.get("command")
                or int(r.get("port") or 0) >= EPHEMERAL_PORT
                or is_temp_place(r.get("cwd"), r.get("project"))
                or (".app/Contents/" in r.get("command", "")
                    and not re.search(r"/(Python|Electron)\.app/", r.get("command", "")))]
        for k in junk:
            del self.data["manual"][k]

    def label_ports(self, label: str) -> set[int]:
        return {int(p) for p in self.data["labels"].get(label, {})}

    def update(self, label_ports: dict[str, set[int]], manual: dict[str, dict],
               forget_after_days: int) -> None:
        now = time.time()
        changed = False
        with self.lock:
            for label, ports in label_ports.items():
                known = self.data["labels"].setdefault(label, {})
                for p in ports:
                    changed |= str(p) not in known
                    known[str(p)] = now
            for key, rec in manual.items():
                old = self.data["manual"].get(key)
                changed |= old is None
                rec["first_seen"] = old.get("first_seen", now) if old else now
                rec["last_seen"] = now
                for field in ("title", "url"):  # a scan without probes leaves them empty
                    if old and not rec.get(field):
                        rec[field] = old.get(field) or rec.get(field)
                self.data["manual"][key] = rec
            cutoff = now - forget_after_days * 86400
            for key in [k for k, r in self.data["manual"].items() if r["last_seen"] < cutoff]:
                del self.data["manual"][key]
                changed = True
            if changed or now - self.saved_at > 60:
                self._save()

    def forget(self, key: str) -> bool:
        with self.lock:
            found = self.data["manual"].pop(key, None) is not None
            if found:
                self._save()
            return found

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1))
            os.replace(tmp, self.path)
            self.saved_at = time.time()
        except OSError as exc:
            print(f"memory: cannot save {self.path}: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------- scan

EPHEMERAL_PORT = 49152  # 49152-65535: random ports picked anew on every start
# Throwaway folders: a server started there is never coming back.
TEMP_DIR_RE = re.compile(r"/scratch-workspaces/|/\.claude/shell-snapshots|^/(private/)?tmp/|/T/")


def is_temp_place(*paths: str | None) -> bool:
    return any(p and TEMP_DIR_RE.search(p) for p in paths)


def worth_remembering(r: dict) -> bool:
    """A server you would start again: a known process with a command, on a fixed port,
    not a helper of an app (Chrome debugging, Claude, Tailscale), not one we failed to read."""
    return (r["name"] not in ("", "?") and bool(r["command"]) and r["port"] < EPHEMERAL_PORT
            and not r.get("app_internal") and not is_temp_place(r.get("cwd"), r.get("project")))


def ancestry(pid: int, procs: dict[int, dict]) -> list[int]:
    chain, seen = [], set()
    while pid and pid in procs and pid not in seen:
        chain.append(pid)
        seen.add(pid)
        if pid == 1:
            break
        pid = procs[pid]["ppid"]
    return chain


def app_name(proc: dict | None, label: str) -> str:
    comm = (proc or {}).get("comm", "")
    m = re.search(r"/([^/]+)\.app/", comm)
    if m:
        return m.group(1)
    parts = label.split(".")
    return parts[3] if len(parts) > 3 and label.startswith("application.") else label


def match_plist_by_command(command: str, plists: dict[str, dict]) -> str | None:
    for label, pl in plists.items():
        significant = [a for a in pl["args"] if a.startswith("/")
                       and os.path.basename(a) not in INTERPRETERS]
        if significant and any(a in command for a in significant):
            return label
    return None


def classify_origin(pid: int, procs: dict, pid2label: dict, plists: dict) -> dict:
    chain = ancestry(pid, procs)
    proc = procs.get(pid, {})
    for i, p in enumerate(chain):
        label = pid2label.get(p)
        if not label:
            continue
        if label in plists:
            return {"kind": "launchd", "label": label, "plist": plists[label]["file"],
                    "text": f"launchd · {label}"}
        if label.startswith("application."):
            app = app_name(procs.get(p), label)
            between = [procs[c]["name"] for c in chain[:i] if c in procs]
            if i == 0:
                return {"kind": "app", "label": label, "text": f"app · {app}"}
            if any(n.lstrip("-") in SHELLS for n in between):
                return {"kind": "manual", "label": label, "text": f"started by hand · from {app}"}
            return {"kind": "app", "label": label, "text": f"app · {app}"}
        if label.startswith("com.apple."):
            return {"kind": "system", "label": label, "text": f"macOS · {label}"}
        return {"kind": "launchd-other", "label": label, "text": f"launchd · {label}"}
    if proc.get("user") not in (USER, None):
        return {"kind": "system", "label": None, "text": f"service · {proc.get('user')}"}
    top = procs.get(chain[-2]) if len(chain) >= 2 and chain[-1] == 1 else None
    guessed = match_plist_by_command(proc.get("command", ""), plists) or (
        match_plist_by_command(top["command"], plists) if top else None)
    if guessed:
        return {"kind": "launchd", "label": guessed, "plist": plists[guessed]["file"],
                "text": f"launchd · {guessed}"}
    if proc.get("comm", "").startswith(("/System/", "/usr/libexec/", "/usr/sbin/")):
        return {"kind": "system", "label": None, "text": "macOS"}
    kind, app = group_key(proc)
    if kind == "app":  # e.g. Tailscale's network extension, started by the system for the app
        return {"kind": "app", "label": None, "text": f"app · {app}"}
    return {"kind": "manual", "label": None, "text": "started by hand · parent has exited"}


def scan(cfg: dict, memory: Memory, probe: bool = True,
         sampler: Sampler | None = None) -> dict:
    t0 = time.time()
    procs = read_processes()
    listeners = read_listeners()
    jobs = read_launchctl()
    disabled = read_disabled()
    plists = read_plists()
    pid2label = {j["pid"]: label for label, j in jobs.items() if j["pid"]}
    ignore = cfg.get("ignore_labels") or []
    is_ignored = lambda label: any(fnmatch.fnmatch(label, pat) for pat in ignore)  # noqa: E731

    # Group sockets by (port, pid).
    groups: dict[tuple[int, int], list[dict]] = {}
    for row in listeners:
        groups.setdefault((row["port"], row["pid"]), []).append(row)

    chains = {pid: ancestry(pid, procs) for _, pid in groups}
    cwds = read_cwds({p for chain in chains.values() for p in chain if p != 1})

    ports = []
    for (port, pid), rows in sorted(groups.items()):
        proc = procs.get(pid, {"name": "?", "command": "", "user": "?", "etime": "0"})
        origin = classify_origin(pid, procs, pid2label, plists)
        chain = [p for p in chains[pid] if p != 1]
        pl = plists.get(origin.get("label") or "")
        candidates = [cwds.get(p, "") for p in chain if cwds.get(p) not in (None, "/")]
        candidates += [procs[p]["command"] for p in chain if p in procs]
        if pl:
            candidates += [pl["workdir"] or ""] + pl["args"] + pl["logs"]
        addrs = sorted({r["addr"] for r in rows})
        host, link_host = probe_target(rows)
        ports.append({
            "port": port, "pid": pid, "name": proc.get("name") or "?",
            "command": proc.get("command", ""), "user": proc.get("user", "?"),
            "uptime_s": etime_seconds(proc.get("etime", "0")), "addrs": addrs,
            "exposed": any(not is_loopback(a) for a in addrs),
            "cwd": cwds.get(pid), "project": guess_project(candidates),
            "origin": origin, "system": origin["kind"] == "system",
            "app_internal": origin["kind"] == "app" or group_key(proc)[0] == "app",
            "desc": knowledge.describe({**proc, "comm": proc.get("comm", "")}, origin,
                                       guess_project(candidates),
                                       group_key(proc)[1] or None, [port])["short"],
            "cmd_id": cmd_id(proc.get("command", "")),
            "own": proc.get("user") == USER and pid != os.getpid(),
            "_host": host, "_link": link_host, "http": None, "url": None,
        })

    if probe:
        with ThreadPoolExecutor(max_workers=32) as pool:
            futures = {pool.submit(probe_cached, (r["pid"], r["port"]), r["_host"], r["port"]): r
                       for r in ports if r["_host"] and not r["system"]}
            for fut, r in futures.items():
                r["http"] = fut.result()
                if r["http"] and r["http"].get("kind", "page") == "page":
                    r["url"] = f"http://{r['_link']}:{r['port']}/"
    for r in ports:
        r.pop("_host")
        r.pop("_link")

    # Remember what we saw.
    seen_label_ports: dict[str, set[int]] = {}
    manual_now: dict[str, dict] = {}
    for r in ports:
        label = r["origin"].get("label")
        if r["origin"]["kind"] == "launchd" and label:
            seen_label_ports.setdefault(label, set()).add(r["port"])
        elif r["origin"]["kind"] == "manual" and worth_remembering(r):
            key = f"{r['port']}|{r['project'] or r['name']}"
            r["memory_key"] = key
            manual_now[key] = {"port": r["port"], "name": r["name"], "command": r["command"],
                               "project": r["project"], "cwd": r["cwd"],
                               "title": (r["http"] or {}).get("title", ""),
                               "url": r["url"]}
    memory.update(seen_label_ports, manual_now, int(cfg.get("forget_after_days") or 30))

    listening = {}
    for r in ports:
        listening.setdefault(r["port"], r)
    launch_configs = read_launch_configs(cfg.get("scan_roots") or [])

    services, scheduled, hidden = [], [], []
    for label, pl in sorted(plists.items()):
        if is_ignored(label):
            hidden.append(label)
            continue
        job = jobs.get(label)
        pid = job["pid"] if job else None
        status_code = job["status"] if job else None
        is_disabled = disabled.get(label, pl["disabled_key"])
        ports_now = sorted({r["port"] for r in ports if r["origin"].get("label") == label})
        expected = sorted(pl["ports"] | memory.label_ports(label))
        project = guess_project([pl["workdir"] or ""] + pl["args"] + pl["logs"])
        base = {"label": label, "plist": pl["path"], "plist_file": pl["file"],
                "project": project, "ports_now": ports_now, "expected_ports": expected,
                "pid": pid, "loaded": job is not None, "disabled": is_disabled,
                "last_exit": exit_text(status_code)}
        if pl["kind"] != "service":
            scheduled.append({**base, "schedule": pl["schedule"] or "on demand",
                              "running": pid is not None,
                              "action": None if is_disabled else "start"})
            continue
        if is_disabled:
            status, reason, action = "off", "disabled (launchctl disable)", None
        elif pid:
            missing = [p for p in expected if p not in listening]
            if expected and not ports_now and missing:
                status = "warn"
                reason = "process is alive, but port " + ", ".join(map(str, missing)) + " is not listening"
            else:
                status, reason = "up", ""
            action = None
        elif job is not None:
            status = "down"
            reason = "loaded but not running" + (f" — {base['last_exit']}"
                                                   if base["last_exit"] else "")
            action = "start"
        else:
            # Not loaded at all: unloaded on purpose (brew services stop, launchctl bootout)
            # or replaced (postgresql@16 -> @18). Grey with a Start button, not an alarm.
            status, reason, action = "off", "unloaded — won't start on its own", "start"
        services.append({**base, "id": f"launchd:{label}", "source": "launchd", "name": label,
                         "status": status, "reason": reason, "action": action,
                         "launch_json": []})

    for c in launch_configs:
        twin = next((s for s in services if c["port"] and c["port"] in
                     (s["expected_ports"] or []) + s["ports_now"]), None)
        if twin:
            twin["launch_json"].append(c["name"])
            continue
        listener = listening.get(c["port"]) if c["port"] else None
        if not c["port"]:
            status, reason = "unknown", "no port in launch.json"
        elif listener is None:
            status, reason = "down", "not running"
        elif listener["project"] and listener["project"] != c["project"]:
            status = "warn"
            reason = f"port {c['port']} is taken by {listener['name']} ({listener['project']})"
        else:
            status, reason = "up", ""
        services.append({
            "id": f"launch:{c['file']}:{c['name']}", "source": "launch.json",
            "name": f"{Path(c['project']).name} · {c['name']}", "label": None,
            "plist": None, "file": c["file"], "project": c["project"],
            "expected_ports": [c["port"]] if c["port"] else [],
            "ports_now": [c["port"]] if listener else [], "status": status, "reason": reason,
            "action": None, "command": c["command"], "cwd": c["cwd"], "launch_json": [],
        })

    order = {"down": 0, "warn": 1, "unknown": 2, "up": 3, "off": 4}
    services.sort(key=lambda s: (order[s["status"]], s["name"]))

    current_keys = {r.get("memory_key") for r in ports}
    gone, seen_gone = [], set()
    for key, rec in sorted(memory.data["manual"].items(), key=lambda kv: -kv[1]["last_seen"]):
        if key in current_keys:
            continue
        taken = listening.get(rec["port"])
        if taken and (not rec.get("project") or taken.get("project") == rec.get("project")):
            continue  # the same thing listens there again (maybe now under launchd)
        ident = (rec["port"], rec.get("command", "")[:300])
        if ident in seen_gone:
            continue
        seen_gone.add(ident)
        gone.append({**rec, "key": key,
                     "port_taken_by": f"{taken['name']} (pid {taken['pid']})" if taken else ""})
    gone.sort(key=lambda g: -g["last_seen"])

    monitor = None
    if sampler is not None:
        try:
            pid_ports: dict[int, list[int]] = {}
            for r in ports:
                pid_ports.setdefault(r["pid"], []).append(r["port"])
            monitor = monitor_state(cfg, sampler, procs, pid2label, plists, pid_ports)
        except Exception as exc:  # noqa: BLE001 - the port list must still render
            print(f"monitor failed: {exc}", file=sys.stderr)
    return {
        "generated_at": time.time(), "scan_ms": int((time.time() - t0) * 1000),
        "dashboard_port": cfg["port"], "refresh_seconds": cfg["refresh_seconds"],
        "dashboard_label": DASHBOARD_LABEL,
        "ports": ports, "services": services, "scheduled": scheduled, "gone": gone,
        "hidden": hidden, "monitor": monitor,
    }


def start_job(label: str) -> dict:
    plists = read_plists()
    if label not in plists:
        return {"ok": False, "missing": True, "message": f"no such plist in {AGENTS_DIR}"}
    jobs = read_launchctl()
    if label in jobs:
        cmd = [LAUNCHCTL, "kickstart", f"gui/{UID}/{label}"]
    else:
        cmd = [LAUNCHCTL, "bootstrap", f"gui/{UID}", plists[label]["path"]]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "message": str(exc), "command": " ".join(cmd)}
    out = (r.stdout + r.stderr).strip()
    return {"ok": r.returncode == 0, "command": " ".join(cmd),
            "message": out or ("started" if r.returncode == 0 else f"exit code {r.returncode}")}


DASHBOARD_LABEL = "com.porthole.dashboard"


def control_job(label: str, action: str) -> dict:
    """restart = kickstart -k (KeepAlive brings it straight back); stop = bootout (stays
    down until "Start" or the next login)."""
    plists = read_plists()
    if label not in plists:
        return {"ok": False, "missing": True, "message": f"no such plist in {AGENTS_DIR}"}
    if label == DASHBOARD_LABEL and action == "stop":
        return {"ok": False, "message": "the dashboard does not stop itself"}
    if action == "restart":
        cmd = [LAUNCHCTL, "kickstart", "-k", f"gui/{UID}/{label}"]
    elif action == "stop":
        cmd = [LAUNCHCTL, "bootout", f"gui/{UID}/{label}"]
    else:
        return {"ok": False, "message": f"unknown action {action}"}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "message": str(exc), "command": " ".join(cmd)}
    out = (r.stdout + r.stderr).strip()
    done = {"restart": "restarted", "stop": "stopped"}[action]
    return {"ok": r.returncode == 0, "command": " ".join(cmd),
            "message": out or (done if r.returncode == 0 else f"exit code {r.returncode}")}


def kill_process(pid: int, command: str, force: bool) -> dict:
    """SIGTERM (or SIGKILL) to one of the user's own processes. The command must still
    match what the page showed, so a pid reused since then is never hit."""
    procs = read_processes()
    proc = procs.get(pid)
    if proc is None:
        return {"ok": False, "missing": True, "message": f"process {pid} is gone"}
    if pid in (0, 1, os.getpid()) or proc["user"] != USER:
        return {"ok": False, "message": "only your own processes can be stopped, not the dashboard"}
    if command not in (proc["command"], cmd_id(proc["command"])):
        return {"ok": False, "message": f"pid {pid} is now a different process, reload the page"}
    sig = 9 if force else 15
    try:
        os.kill(pid, sig)
    except OSError as exc:
        return {"ok": False, "message": str(exc)}
    jobs = read_launchctl()
    keepalive = next((label for label, j in jobs.items() if j["pid"] == pid), None)
    note = f" — launchd ({keepalive}) may start it again" if keepalive else ""
    return {"ok": True, "message": f"{'SIGKILL' if force else 'SIGTERM'} → {proc['name']} "
                                   f"(pid {pid}){note}"}


# --------------------------------------------------------------------------- process card

GIT = "/usr/bin/git"
OPEN = "/usr/bin/open"
_GIT_CACHE: dict[str, tuple[float, dict]] = {}


def file_info(path: str | None) -> dict | None:
    if not path:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return {"path": path, "created": getattr(st, "st_birthtime", None), "modified": st.st_mtime,
            "size": st.st_size, "is_dir": os.path.isdir(path)}


def git_info(root: str | None) -> dict | None:
    """First and last commit of a project: "when did I make this". Cached 5 min."""
    if not root or not os.path.isdir(os.path.join(root, ".git")):
        return None
    hit = _GIT_CACHE.get(root)
    if hit and time.time() - hit[0] < 300:
        return hit[1]
    last = run([GIT, "-C", root, "log", "-1", "--format=%ct%x00%s"], timeout=5).strip()
    first = run([GIT, "-C", root, "rev-list", "--max-parents=0", "--format=%ct", "HEAD"],
                timeout=5).split()
    count = run([GIT, "-C", root, "rev-list", "--count", "HEAD"], timeout=5).strip()
    info = None
    if last:
        t, _, subject = last.partition("\0")
        firsts = [int(x) for x in first if x.isdigit() and len(x) >= 9]
        info = {"last_commit": int(t), "last_subject": subject,
                "first_commit": min(firsts) if firsts else None,
                "commits": int(count) if count.isdigit() else None}
    _GIT_CACHE[root] = (time.time(), info)
    return info


def app_bundle(comm: str) -> dict | None:
    """Outermost .app of an executable with its version."""
    m = re.match(r"(.*?/[^/]+\.app)/", comm)
    if not m:
        return None
    path = m.group(1)
    try:
        info = plistlib.loads(Path(path, "Contents", "Info.plist").read_bytes())
    except Exception:  # noqa: BLE001
        info = {}
    return {"path": path, "name": Path(path).stem,
            "version": info.get("CFBundleShortVersionString") or info.get("CFBundleVersion"),
            "id": info.get("CFBundleIdentifier"), **(file_info(path) or {})}


def script_of(command: str, cwd: str | None = None) -> str | None:
    """The file an interpreter runs (python foo.py, node x.js, bash run.sh)."""
    try:
        args = shlex.split(command)
    except ValueError:
        args = command.split()
    if not args or os.path.basename(args[0]).lower().rstrip("0123456789.") not in INTERPRETERS:
        return None
    for a in args[1:]:
        if a == "-m":
            return None
        if a.startswith("-"):
            continue
        path = a if os.path.isabs(a) or not cwd else os.path.join(cwd, a)
        if os.path.isfile(path):
            return os.path.normpath(path)
    return None


def proc_details(pid: int, sampler: Sampler) -> dict | None:
    procs = read_processes()
    proc = procs.get(pid)
    if proc is None:
        return None
    jobs = read_launchctl()
    plists = read_plists()
    pid2label = {j["pid"]: label for label, j in jobs.items() if j["pid"]}
    origin = classify_origin(pid, procs, pid2label, plists)
    chain = ancestry(pid, procs)
    cwds = read_cwds({p for p in chain if p != 1})
    pl = plists.get(origin.get("label") or "")
    candidates = [cwds.get(p, "") for p in chain if cwds.get(p) not in (None, "/")]
    candidates += [procs[p]["command"] for p in chain if p in procs]
    if pl:
        candidates += [pl["workdir"] or ""] + pl["args"] + pl["logs"]
    kind, app = group_key(proc)
    project = guess_project(candidates) if kind != "app" else None
    ports = sorted({(r["port"], r["addr"]) for r in read_listeners() if r["pid"] == pid})
    port_list = sorted({p for p, _ in ports})
    desc = knowledge.describe(proc, origin, project, app if kind == "app" else None, port_list)
    snap, _ = sampler.snapshot()
    top = (snap or {}).get("top", {}).get(pid, {})
    with sampler.lock:
        hist = list(sampler.proc_hist.get((pid, proc["command"]), []))
    uptime = etime_seconds(proc["etime"])
    plist_info = None
    if pl:
        try:
            raw = plistlib.loads(Path(pl["path"]).read_bytes())
        except Exception:  # noqa: BLE001
            raw = {}
        plist_info = {**(file_info(pl["path"]) or {}), "label": pl["label"], "kind": pl["kind"],
                      "keepalive": bool(raw.get("KeepAlive")), "run_at_load": bool(raw.get("RunAtLoad")),
                      "schedule": pl["schedule"], "workdir": pl["workdir"],
                      "logs": [f for f in (file_info(x) for x in pl["logs"]) if f]}
    return {
        "pid": pid, "ppid": proc["ppid"], "name": proc["name"], "exe": proc.get("comm", ""),
        "command": proc["command"], "user": proc["user"], "own": proc["user"] == USER and pid != os.getpid(),
        "system": proc["user"] != USER or proc.get("comm", "").startswith(SYSTEM_PREFIXES),
        "uptime_s": uptime, "started_at": time.time() - uptime,
        "mem": top.get("mem"), "cpu": top.get("cpu"), "history": hist,
        "growth": sampler.growth(pid, proc["command"], top["mem"])[0] if top else None,
        "desc": desc, "origin": origin, "app": app_bundle(proc.get("comm", "")),
        "chain": [{"pid": p, "name": procs[p]["name"], "command": procs[p]["command"][:300],
                   "user": procs[p]["user"]} for p in reversed(chain)],
        "children": [{"pid": c["pid"], "name": c["name"]} for c in procs.values()
                     if c["ppid"] == pid][:30],
        "cwd": cwds.get(pid), "project": project,
        "project_dir": file_info(project), "git": git_info(project),
        "script": file_info(script_of(proc["command"], cwds.get(pid))),
        "plist": plist_info, "ports": [{"port": p, "addr": a} for p, a in ports],
    }


def reveal(path: str) -> dict:
    """Show a file in Finder: only existing paths in your home or /Applications."""
    real = os.path.realpath(path)
    if not real.startswith((str(HOME) + "/", "/Applications/")) or not os.path.exists(real):
        return {"ok": False, "message": "only an existing path in ~ or /Applications can be shown"}
    subprocess.Popen([OPEN, "-R", real], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "message": f"Shown in Finder: {real}"}


# --------------------------------------------------------------------------- HTTP server

class App:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.memory = Memory(SEEN_FILE)
        self.lock = threading.Lock()
        self.cache: tuple[float, dict] | None = None
        self.sampler = Sampler(cfg)
        self.meta_lock = threading.Lock()
        self.meta: tuple[float, dict, dict, dict] | None = None
        self.pid_ports: dict[int, list[int]] = {}

    def _meta(self, top: dict[int, dict]) -> tuple[dict, dict, dict]:
        """Process list, launchd labels and plists change slowly: re-read every 15 s,
        or sooner when a big process is not in the list yet."""
        with self.meta_lock:
            now = time.time()
            heavy = sorted(top, key=lambda p: -top[p]["mem"])[:40]
            stale = self.meta is None or now - self.meta[0] > 15 or (
                now - self.meta[0] > 3 and any(p not in self.meta[1] for p in heavy))
            if stale:
                jobs = read_launchctl()
                pid2label = {j["pid"]: label for label, j in jobs.items() if j["pid"]}
                self.meta = (now, read_processes(), pid2label, read_plists())
            assert self.meta is not None
            return self.meta[1], self.meta[2], self.meta[3]

    def live(self, open_keys: set[str], flat: bool = False) -> dict:
        """Only what changes second to second: memory, CPU and the process table."""
        self.sampler.touch_live()
        snap, _ = self.sampler.snapshot()
        if snap is None:
            snap = self.sampler.sample()
        procs, pid2label, plists = self._meta(snap["top"])
        groups = build_processes(snap, procs, pid2label, plists, self.sampler, self.pid_ports)
        alerts = build_alerts(self.cfg, snap, groups)
        self.sampler.notify(alerts)
        return {"generated_at": time.time(), "monitor": {
            "sampled_at": snap["t"], "vm": snap["vm"], "cpu": snap["cpu"],
            "disk": snap["disk"], "point": snap.get("point"),
            **slim_groups(groups, open_keys, flat), "alerts": alerts,
            "sample_seconds": self.cfg["sample_seconds"],
            "live_seconds": self.cfg["live_seconds"], "live": True}}

    def state(self) -> dict:
        with self.lock:
            if self.cache and time.time() - self.cache[0] < 3:
                return self.cache[1]
            if self.sampler.latest is None:
                self.sampler.sample()
            result = scan(self.cfg, self.memory, sampler=self.sampler)
            pid_ports: dict[int, list[int]] = {}
            for r in result["ports"]:
                pid_ports.setdefault(r["pid"], []).append(r["port"])
            self.pid_ports = pid_ports
            self.cache = (time.time(), result)
            return result

    def background_learner(self) -> None:
        """Keeps learning ports and hand-started servers while no page is open."""
        while True:
            time.sleep(60)
            try:
                with self.lock:
                    scan(self.cfg, self.memory, probe=False)
            except Exception as exc:  # noqa: BLE001
                print(f"background scan failed: {exc}", file=sys.stderr)


def make_handler(app: App):
    port = app.cfg["port"]
    allowed_hosts = {f"localhost:{port}", f"127.0.0.1:{port}", f"[::1]:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "porthole"

        def log_message(self, fmt, *args):  # only POSTs and errors
            if self.command == "POST" or (len(args) > 1 and str(args[1])[:1] in "45"):
                sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode(),
                       "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            # Blocks DNS rebinding: only localhost names reach the data.
            if self.headers.get("Host", "") in allowed_hosts:
                return True
            self._json(403, {"error": "bad host"})
            return False

        def do_GET(self):
            if not self._host_ok():
                return
            path, _, query = self.path.partition("?")
            qs = parse_qs(query)
            open_keys = set(qs.get("open", []))
            flat = qs.get("flat") == ["1"]
            if path in ("/", "/index.html"):
                self._send(200, INDEX_FILE.read_bytes(), "text/html; charset=utf-8")
            elif path == "/api/state":
                try:
                    result = app.state()
                    if result.get("monitor"):
                        mon = result["monitor"]
                        result = {**result, "monitor": {
                            **mon, **slim_groups(mon["groups"], open_keys, flat)}}
                    self._json(200, result)
                except Exception as exc:  # noqa: BLE001
                    self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
            elif path == "/api/live":
                try:
                    self._json(200, app.live(open_keys, flat))
                except Exception as exc:  # noqa: BLE001
                    self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
            elif path == "/api/proc":
                try:
                    pid = int((qs.get("pid") or ["0"])[0])
                    info = proc_details(pid, app.sampler)
                    if info is None:
                        self._json(404, {"error": f"process {pid} is gone"})
                    else:
                        self._json(200, info)
                except ValueError:
                    self._json(400, {"error": "bad pid"})
                except Exception as exc:  # noqa: BLE001
                    self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok():
                return
            origin = self.headers.get("Origin")
            if (self.headers.get("X-Dashboard") != "1" or
                    (origin and origin.split("://", 1)[-1] not in allowed_hosts)):
                self._json(403, {"error": "forbidden"})
                return
            try:
                length = min(int(self.headers.get("Content-Length") or 0), 4096)
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._json(400, {"error": "bad json"})
                return
            if self.path == "/api/start":
                result = start_job(str(body.get("label", "")))
                with app.lock:
                    app.cache = None
                self._json(200 if result["ok"] else 404 if result.get("missing") else 500, result)
            elif self.path in ("/api/restart", "/api/stop"):
                result = control_job(str(body.get("label", "")), self.path.rsplit("/", 1)[1])
                with app.lock:
                    app.cache = None
                self._json(200 if result["ok"] else 404 if result.get("missing") else 500, result)
            elif self.path == "/api/kill":
                try:
                    pid = int(body.get("pid"))
                except (TypeError, ValueError):
                    self._json(400, {"error": "bad pid"})
                    return
                result = kill_process(pid, str(body.get("command", "")), bool(body.get("force")))
                with app.lock:
                    app.cache = None
                self._json(200 if result["ok"] else 404 if result.get("missing") else 409, result)
            elif self.path == "/api/reveal":
                result = reveal(str(body.get("path", "")))
                self._json(200 if result["ok"] else 400, result)
            elif self.path == "/api/forget":
                ok = app.memory.forget(str(body.get("key", "")))
                with app.lock:
                    app.cache = None
                self._json(200 if ok else 404, {"ok": ok})
            else:
                self._json(404, {"error": "not found"})

    return Handler


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=cfg["port"])
    parser.add_argument("--dump", action="store_true", help="print one scan as JSON and exit")
    args = parser.parse_args()
    cfg["port"] = args.port
    app = App(cfg)
    if args.dump:
        json.dump(app.state(), sys.stdout, ensure_ascii=False, indent=1)
        print()
        return
    server = ThreadingHTTPServer(("127.0.0.1", cfg["port"]), make_handler(app))
    server.daemon_threads = True
    threading.Thread(target=app.background_learner, daemon=True).start()
    threading.Thread(target=app.sampler.run_forever, daemon=True).start()
    print(f"porthole on http://127.0.0.1:{cfg['port']}/", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
