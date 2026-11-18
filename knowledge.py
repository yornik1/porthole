"""Plain-language descriptions of processes: what it is, why it holds memory, whether it is safe to kill.

`describe()` combines three sources, most specific first:
1. the command line (a Python/Node server from one of your projects, uvicorn, vite, ...),
2. a table of known macOS daemons and apps,
3. where it lives (an app bundle helper, a system path) and who started it.
"""

from __future__ import annotations

import os
import re
import shlex

# hint: "safe"   - can be killed, nothing important is lost
#       "app"    - part of an app: better to quit the app (or close tabs) than kill it
#       "server" - your server or script: killing it stops it (launchd may restart it)
#       "system" - macOS: do not kill; it is restarted automatically or the session breaks
HINTS = {
    "safe": "Safe to quit: nothing important is lost.",
    "app": "Part of an app. Close tabs or windows, or quit the app, rather than killing the process.",
    "server": "Your process. Killing it stops it; if launchd keeps it alive (KeepAlive) it comes back, so use Stop instead.",
    "system": "macOS system process. Leave it alone: macOS restarts it, or the session breaks.",
}

# name (basename of the executable) -> (short, long, hint)
KNOWN: dict[str, tuple[str, str, str]] = {
    "kernel_task": ("macOS kernel", "The system kernel itself. Its \"memory\" is kernel and driver memory; high CPU usually means overheating, as macOS throttles the system.", "system"),
    "WindowServer": ("Screen rendering", "Draws all windows, animations and the cursor. Memory grows with the number of displays, windows and their size.", "system"),
    "launchd": ("Process launcher", "The first macOS process (pid 1): starts system services and your LaunchAgents.", "system"),
    "loginwindow": ("User session", "Holds your login session. Killing it logs you out.", "system"),
    "Finder": ("Finder", "File manager and desktop. If it hangs, you can restart it; macOS relaunches it.", "safe"),
    "Dock": ("Dock and Mission Control", "Dock, Launchpad and Spaces switching. macOS restarts it.", "safe"),
    "SystemUIServer": ("Menu bar", "Menu bar icons on the right. macOS restarts it.", "safe"),
    "ControlCenter": ("Control Center", "Control Center and menu bar icons. Ports 5000 and 7000 belong to the AirPlay receiver (turn it off in Settings > General > AirDrop & Handoff). macOS restarts it.", "safe"),
    "NotificationCenter": ("Notifications", "Notification Center and widgets.", "safe"),
    "mds": ("Spotlight indexer", "Keeps the Spotlight search index up to date. Adds load after updates and after copying many files.", "system"),
    "mds_stores": ("Spotlight database", "Stores the Spotlight index database. Temporary load after disk changes.", "system"),
    "mdworker_shared": ("Spotlight file reader", "Reads new files for the Spotlight index. Many copies are normal; they are short-lived.", "system"),
    "mdworker": ("Spotlight file reader", "Reads new files for the Spotlight index.", "system"),
    "corespotlightd": ("Spotlight app data", "Indexes app content for search.", "system"),
    "spotlightknowledged": ("Spotlight suggestions", "Siri and Spotlight suggestions.", "system"),
    "mediaanalysisd": ("Photo and video analysis", "Recognizes faces, objects and text in Photos (and video). Can hold gigabytes while the library is analyzed; releases them on its own.", "safe"),
    "mediaanalysisd-access": ("Photo analysis access", "Helper for Photos library analysis.", "safe"),
    "photoanalysisd": ("Photos library analysis", "Memories, faces and search in Photos. Runs when the Mac is idle.", "safe"),
    "photolibraryd": ("Photos library", "Access to the Photos library.", "system"),
    "backupd": ("Time Machine", "Time Machine backups.", "system"),
    "cloudd": ("iCloud", "iCloud data sync.", "system"),
    "bird": ("iCloud Drive", "iCloud Drive file sync.", "system"),
    "nsurlsessiond": ("Background transfers", "Downloads and uploads in the background for apps (updates, iCloud, App Store).", "system"),
    "softwareupdated": ("macOS updates", "Checks for and downloads system updates.", "system"),
    "trustd": ("Certificate checks", "Validates certificates for HTTPS and signatures.", "system"),
    "syspolicyd": ("Gatekeeper", "Checks programs before they run (signature, notarization).", "system"),
    "XprotectService": ("XProtect", "Built-in macOS antivirus.", "system"),
    "XProtect": ("XProtect", "Built-in macOS antivirus.", "system"),
    "XProtectPluginService": ("XProtect", "Built-in macOS antivirus.", "system"),
    "coreaudiod": ("Audio", "All system audio. Restarting it cuts sound for a second.", "system"),
    "bluetoothd": ("Bluetooth", "Bluetooth devices.", "system"),
    "airportd": ("Wi-Fi", "Wi-Fi connection.", "system"),
    "sharingd": ("AirDrop and Handoff", "AirDrop, Handoff and the shared clipboard.", "system"),
    "rapportd": ("Apple device link", "Connection to nearby iPhone, iPad and Watch.", "system"),
    "distnoted": ("System notifications", "Distributes events between processes. One copy per user.", "system"),
    "cfprefsd": ("Preferences", "Reads and writes app preferences (plist).", "system"),
    "logd": ("System log", "Collects logs from all processes.", "system"),
    "powerd": ("Power", "Sleep, battery and wake.", "system"),
    "secd": ("Keychain", "Keychain access.", "system"),
    "tccd": ("Privacy permissions", "Permissions for camera, microphone, files and so on.", "system"),
    "lsd": ("Launch Services", "Which apps open which files and links.", "system"),
    "MTLCompilerService": ("Shader compiler", "Compiles Metal graphics shaders for apps. Short-lived.", "safe"),
    "VTDecoderXPCService": ("Video decoder", "Hardware video decoding for apps.", "safe"),
    "ReportCrash": ("Crash reports", "Writes a report when an app crashes.", "safe"),
    "UserEventAgent": ("System events", "Handles system events for services.", "system"),
    "iconservicesagent": ("Icons", "Prepares and caches icons.", "safe"),
    "com.apple.WebKit.WebContent": ("Web page (WebKit)", "Page content in Safari, Mail or a help window. One tab is one process.", "app"),
    "com.apple.WebKit.GPU": ("WebKit graphics", "GPU process for Safari/WebKit.", "app"),
    "com.apple.WebKit.Networking": ("WebKit networking", "Network requests for Safari/WebKit.", "app"),
    "zsh": ("zsh shell", "Command line in a terminal (or started by a program).", "safe"),
    "bash": ("bash shell", "Command line (often started by scripts).", "safe"),
    "sh": ("sh shell", "Usually a wrapper around a script or command.", "safe"),
    "login": ("Terminal login", "A terminal tab session.", "safe"),
    "tmux": ("tmux", "Terminal multiplexer: keeps sessions alive without an open window.", "safe"),
    "ssh": ("SSH connection", "Connection to another computer (or a tunnel).", "safe"),
    "sshd": ("SSH server", "Accepts incoming SSH connections.", "system"),
    "claude": ("Claude Code", "A Claude Code session (CLI or the Code tab in the Claude app). Each open session is a separate process; memory grows with the length of the conversation.", "app"),
    "esbuild": ("esbuild", "JS bundler: a helper for vite or another dev server.", "server"),
    "uv": ("uv", "Python package manager; runs a script or server.", "server"),
    "postgres": ("PostgreSQL", "PostgreSQL database. Many processes: one per connection.", "server"),
    "redis-server": ("Redis", "In-memory key-value store.", "server"),
    "mysqld": ("MySQL", "MySQL database.", "server"),
    "mongod": ("MongoDB", "MongoDB database.", "server"),
    "ollama": ("Ollama", "Local LLMs. Keeps the loaded model in memory while it is in use.", "server"),
    "com.docker.backend": ("Docker", "Docker Desktop engine.", "app"),
    "com.docker.virtualization": ("Docker virtual machine", "The Linux VM that runs containers. Its memory is the memory of all containers.", "app"),
    "qemu-system-aarch64": ("QEMU virtual machine", "Virtual machine (Docker/Colima/UTM).", "app"),
    "xray": ("Xray proxy/VPN", "Xray proxy core (V2Ray-compatible): a local SOCKS/HTTP proxy for a VPN client.", "server"),
    "tailscaled": ("Tailscale", "Tailscale VPN service.", "system"),
    "top": ("top", "Samples memory and CPU for this dashboard (or was started in a terminal).", "safe"),
    "Activity Monitor": ("System monitor", "Activity Monitor.", "safe"),
}

# Apps (outermost .app bundle name) -> description of the whole group.
APPS: dict[str, str] = {
    "Firefox": "Firefox browser. Processes: tabs (one group per site), GPU, extensions, network.",
    "Google Chrome": "Chrome browser. One process per tab and extension, which is why there are many.",
    "Safari": "Safari browser. Tabs run in com.apple.WebKit.WebContent processes.",
    "Arc": "Arc browser (Chromium): one process per tab and extension.",
    "Claude": "Claude app (Electron): windows, chat, Code tab.",
    "Claude Code (sessions)": "Claude Code sessions: each open session is a separate claude process.",
    "Telegram": "Telegram messenger. Memory grows with the media cache and the number of open chats.",
    "Slack": "Slack (Electron).",
    "Discord": "Discord (Electron).",
    "Notion": "Notion (Electron).",
    "Code": "Visual Studio Code (Electron): windows, extensions, language servers.",
    "Visual Studio Code": "Visual Studio Code (Electron): windows, extensions, language servers.",
    "Cursor": "Cursor editor (a VS Code fork).",
    "PyCharm": "PyCharm IDE (Java): project indexes hold a lot of memory.",
    "Docker": "Docker Desktop: the engine and the virtual machine running containers.",
    "Spotify": "Spotify.",
    "zoom.us": "Zoom.",
    "Terminal": "macOS Terminal.",
    "iTerm": "iTerm2 terminal.",
    "Warp": "Warp terminal.",
}

HELPER_ROLES = [
    (re.compile(r"Renderer|Web Content|WebContent|tab", re.I), "tab or window with web content"),
    (re.compile(r"GPU", re.I), "graphics (GPU)"),
    (re.compile(r"Plugin|Extension", re.I), "extension or plugin"),
    (re.compile(r"Network|Socket", re.I), "network"),
    (re.compile(r"Utility|Helper", re.I), "helper process"),
]

WEB_SERVERS = {"uvicorn": "ASGI web server", "gunicorn": "WSGI web server",
               "hypercorn": "ASGI web server", "flask": "Flask server", "fastapi": "FastAPI server",
               "streamlit": "Streamlit app", "http": "simple web server (serves the folder's files)", "jupyter": "Jupyter", "celery": "Celery task queue"}
NODE_TOOLS = {"vite": "Vite dev server", "next": "Next.js", "nuxt": "Nuxt", "webpack": "webpack bundler",
              "tsc": "TypeScript compiler", "esbuild": "esbuild bundler", "nodemon": "nodemon (restarts on changes)",
              "npm": "npm", "pnpm": "pnpm", "yarn": "yarn", "tsx": "tsx", "eslint": "ESLint linter",
              "prettier": "Prettier", "typescript-language-server": "TypeScript language server",
              "mcp": "MCP server (tools for Claude)"}


def _args(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def _short_path(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home) else path


def describe_command(name: str, command: str) -> tuple[str, str] | None:
    """(short, long) for interpreters and dev tools, from the command line."""
    args = _args(command)
    if not args:
        return None
    base = os.path.basename(args[0]).lower()
    rest = args[1:]
    if base.startswith("python") or name.lower().startswith("python"):
        if "-m" in rest and rest.index("-m") + 1 < len(rest):
            mod = rest[rest.index("-m") + 1]
            what = WEB_SERVERS.get(mod.split(".")[0], f"module {mod}")
            target = next((a for a in rest[rest.index("-m") + 2:] if not a.startswith("-")), "")
            return (f"Python: {what}" + (f" {target}" if target else ""),
                    f"Python runs {what}: {' '.join(rest[rest.index('-m') + 1:])[:160]}")
        script = next((a for a in rest if not a.startswith("-")), "")
        if script:
            tool = os.path.basename(script)
            for key, what in WEB_SERVERS.items():
                if key in tool.lower():
                    target = next((a for a in rest[rest.index(script) + 1:] if not a.startswith("-")), "")
                    return (f"Python: {what}" + (f" {target}" if target else ""),
                            f"{_cap(what)} ({tool} {target}).")
            return (f"Python script {tool}", f"Python runs {_short_path(script)}.")
        return ("Python", "Python interpreter.")
    if base in WEB_SERVERS:
        target = next((a for a in rest if not a.startswith("-")), "")
        return (f"{_cap(WEB_SERVERS[base])} {target}".strip(), f"{base} {target}".strip())
    if base == "node" or name == "node":
        script = next((a for a in rest if not a.startswith("-")), "")
        low = script.lower()
        for key, what in NODE_TOOLS.items():
            if f"/{key}/" in low or low.endswith(f"/{key}") or os.path.basename(low).startswith(key):
                return (f"Node: {what}", f"Node.js runs {what} ({_short_path(script)}).")
        if script:
            return (f"Node script {os.path.basename(script)}", f"Node.js runs {_short_path(script)}.")
        return ("Node.js", "Node.js runtime.")
    if base in NODE_TOOLS:
        return (_cap(NODE_TOOLS[base]), f"{base} {' '.join(rest)[:160]}")
    return None


def describe(proc: dict, origin: dict, project: str | None, app: str | None = None,
             ports: list[int] | None = None) -> dict:
    """{'short', 'text', 'hint', 'hint_text'} for one process."""
    name = proc.get("name") or os.path.basename(proc.get("comm", "")) or "?"
    comm = proc.get("comm", "")
    command = proc.get("command", "")
    kind = origin.get("kind")
    short = text = None
    hint = None

    by_cmd = describe_command(name, command)
    if by_cmd:
        short, text = by_cmd
        hint = "server"
    elif name in KNOWN:
        short, text, hint = KNOWN[name]
    elif app and comm.startswith("/System/") and app not in APPS:
        short, text, hint = f"macOS service: {app}", f"System component ({_short_path(comm)}).", "system"
    elif app:
        role = next((r for rx, r in HELPER_ROLES if rx.search(name)), None)
        if name == app or (not role and name.lower() == app.lower()):
            short, text = app, APPS.get(app, f"{app} app: main process.")
        else:
            short = f"{app}: {role or 'helper process'}"
            text = f"{app} app process: {role or 'helper process'}. " + APPS.get(app, "")
        hint = "app"
    elif comm.startswith(("/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/")):
        short, text, hint = "macOS service", f"System process ({_short_path(comm)}).", "system"
    else:
        short, text = name, f"Program {_short_path(comm) or name}."
        hint = "server" if proc.get("user") == os.environ.get("USER") else "system"

    extra = []
    if project:
        extra.append(f"Project {os.path.basename(project)} ({_short_path(project)}).")
        if hint == "server" and not short.endswith(os.path.basename(project)):
            short = f"{short} · {os.path.basename(project)}"
    if ports:
        extra.append("Listening on port " + ", ".join(map(str, ports)) + ".")
    if kind == "launchd":
        extra.append(f"Started by the launchd agent {origin.get('label')}: starts on its own at login.")
    elif kind == "manual":
        extra.append("Started by hand (from a terminal or Claude): will not come back after a reboot.")
    elif kind == "system" and hint not in ("system",):
        hint = "system" if proc.get("user") != os.environ.get("USER") else hint
    text = " ".join([text or "", *extra]).strip()
    return {"short": short or name, "text": text, "hint": hint, "hint_text": HINTS[hint]}


def describe_app(app: str) -> str:
    return APPS.get(app, f"{app} app with all its processes.")
