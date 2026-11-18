#!/bin/sh
# Installs the dashboard as a launchd user agent: starts now and at every login,
# restarts if it dies. Safe to run again (reinstalls).
set -e
cd "$(dirname "$0")"
DIR=$(pwd)
LABEL=com.porthole.dashboard
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PYTHON=${PYTHON:-/opt/homebrew/bin/python3}
[ -x "$PYTHON" ] || PYTHON=/usr/bin/python3
PORT=$("$PYTHON" -c 'import dashboard; print(dashboard.load_config()["port"])')
LOG="$HOME/Library/Logs/porthole.log"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON</string>
    <string>$DIR/dashboard.py</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Adaptive</string>
  <key>Nice</key><integer>5</integer>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF

launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed $PLIST"
echo "open http://localhost:$PORT/"
