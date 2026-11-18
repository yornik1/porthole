#!/bin/sh
# Stops the dashboard and removes its launchd agent. The project folder stays.
LABEL=com.porthole.dashboard
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null && echo "stopped $LABEL" || echo "$LABEL was not running"
rm -f "$PLIST" && echo "removed $PLIST"
