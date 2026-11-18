# porthole

A small window into everything running on your Mac's localhost.

porthole is a single-page dashboard for macOS that answers the questions Activity Monitor doesn't: which of my dev servers came back after a reboot, what is listening on port 5173, who is eating memory and is it growing, and what was that process I started three weeks ago.

- **No dependencies.** One Python file using only the standard library, plus a static HTML page.
- **Cheap.** About 2% of one core in the background; live updates only while the tab is visible and focused.
- **Local only.** Listens on `127.0.0.1` and accepts only `Host: localhost`, so other machines and DNS-rebinding pages can't reach it.

## What you get

| Tab | Shows |
|---|---|
| **Processes** | Top processes by memory footprint (the "Memory" column of Activity Monitor, not RSS). Grouped by app with its helpers, or by project folder; filters for your own processes, apps, servers and macOS. Every row has a plain-English description and a hint whether it is safe to quit. "Growth/h" shows leaks. |
| **Ports** | Every TCP port in `LISTEN`, including root processes: what owns it, which project, who started it. A port gets a link only when it serves a real page; otherwise you see what it is: an API, a login wall (401/403), a WebSocket, a bare HTTP service, or not HTTP. |
| **Projects** | launchd agents from `~/Library/LaunchAgents` and dev servers from `.claude/launch.json` under your `scan_roots`. Red means loaded but crashed, yellow means alive but the port is silent, grey means unloaded on purpose. Servers you started by hand and that are gone now are listed too, for 30 days. |
| **Schedule** | Jobs with `StartCalendarInterval` / `StartInterval`: when they run, last exit code, "Run now". |
| **Resources** | Memory split the way Activity Monitor does it (app / wired / compressed / cache), pressure, swap, CPU, load, disk, with a 1 h or 6 h chart. |

Click any row to open the **process card**: what it is, whether killing it is safe, memory over the last hour, where it came from (launchd agent, app, or started by hand from a terminal), the parent chain, ports, child processes, the project's first and last commit, the agent's logs and the full command line. From there you can reveal the file in Finder, restart or stop a launchd agent, or kill your own process.

The header stays on screen with RAM / swap / CPU meters, alerts, tabs, search and filters. Keys: `/` search, `1`–`5` tabs, `Esc` clear or close, `R` refresh.

**Alerts** fire on elevated memory pressure, swap above `alert_swap_pct`, a non-app process above `alert_process_mb`, or a process growing faster than `alert_growth_mb_per_hour`. Red ones also send a macOS notification, at most once an hour each.

## Install

```sh
git clone https://github.com/yornik1/porthole.git
cd porthole
./install.sh
```

This writes `~/Library/LaunchAgents/com.porthole.dashboard.plist`, starts it now and at every login, and restarts it if it dies. Open http://localhost:7777/. The log is in `~/Library/Logs/porthole.log`. Run `./install.sh` again after changing the port.

Without launchd:

```sh
python3 dashboard.py --port 7778   # serve
python3 dashboard.py --dump        # print one snapshot as JSON and exit
```

To remove it, run `./uninstall.sh`. It stops the agent and deletes the plist.

Requires macOS and Python 3.10+.

## Configuration

Settings live in `config.json`. Put personal overrides in `config.local.json`; it is git-ignored and wins over `config.json`.

| Key | Default | Meaning |
|---|---|---|
| `port` | `7777` | Dashboard port. Re-run `./install.sh` after changing it. |
| `refresh_seconds` | `15` | Full refresh of ports, agents and schedules (min 10). |
| `scan_roots` | `~/Projects`, `~/Developer`, `~/code`, `~/src` | Where to look for `.claude/launch.json`, up to 3 levels deep. |
| `ignore_labels` | `[]` | launchd labels to hide, as globs, e.g. `"com.google.*"`. |
| `forget_after_days` | `30` | How long to remember hand-started servers that are gone. |
| `sample_seconds` | `10` | Background memory/CPU sampling interval (min 5). |
| `live_seconds` | `2` | Update interval while the page is visible and focused. |
| `history_hours` | `6` | Hours of history kept for the chart. |
| `alert_swap_pct` | `80` | Swap usage that raises an alert. |
| `alert_process_mb` | `2048` | Memory a non-app process may hold before an alert. |
| `alert_growth_mb_per_hour` | `700` | Growth rate that looks like a leak. |
| `notify` | `true` | macOS notifications for red alerts. |

## How it works

- **One `top`, not one per sample.** A single `top -l 0` stays running and is read as a stream: every `sample_seconds` in the background, every `live_seconds` while someone is watching. It drops back 8 s after the page stops asking.
- **Ports** come from `netstat -anv`, which sees root processes without `sudo`. Each port gets a short `GET /` probe to tell a page from an API or a login wall.
- **"Who started it"** walks the parent chain from `ps` up to launchd and matches pids against `launchctl list`: a launchd agent's pid means the agent owns it, an app with a shell in between means you started it by hand from that app, and an orphan is matched to a plist by its script path.
- **launchd ports** are read from the plist (`--port N`, `http.server N`, `PORT=…`) and remembered once seen, so a dead agent still shows which port it should be on.
- **State** (`state/seen.json`, `state/history.json`) stays local and out of git.

## Safety

Every action (start, restart, stop, kill, reveal) is a `POST` that needs the `X-Dashboard: 1` header, which a cross-site page can't send without CORS. Kill takes a fingerprint of the full command line, so a recycled pid is never hit, and it only touches your own processes, never the dashboard itself. Reveal only opens existing paths under `~` or `/Applications`.

## License

MIT
