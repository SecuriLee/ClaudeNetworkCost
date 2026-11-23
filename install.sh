#!/usr/bin/env bash
# Add (or with --uninstall, remove) the ClaudeNetworkCost hooks in ~/.claude/settings.json.
# A timestamped backup of settings.json is written first.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
MODE="${1:-install}"
[ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"
cp -p "$SETTINGS" "$SETTINGS.bak-netcost-$(date +%Y%m%d%H%M%S)"
python3 - "$SETTINGS" "$HERE/netcost.py" "$MODE" <<'PY'
import json, sys
path, script, mode = sys.argv[1:]
cfg = json.load(open(path))
hooks = cfg.setdefault("hooks", {})
events = {"UserPromptSubmit": "start", "Stop": "stop", "SessionEnd": "end"}
for ev, sub in events.items():
    lst = [g for g in hooks.get(ev, [])
           if not any("netcost.py" in h.get("command", "") for h in g.get("hooks", []))]
    if mode != "--uninstall":
        lst.append({"hooks": [{"type": "command", "command": f"python3 {script} {sub}", "timeout": 10}]})
    if lst:
        hooks[ev] = lst
    else:
        hooks.pop(ev, None)
if not hooks:
    cfg.pop("hooks")
json.dump(cfg, open(path, "w"), indent=2)
open(path, "a").write("\n")
print(("removed" if mode == "--uninstall" else "installed") + f" ClaudeNetworkCost hooks in {path}")
PY
