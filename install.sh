#!/usr/bin/env bash
# Installs the intrupt approval plugin into goose (Open Plugins layout).
#
# One-line install (no clone needed):
#   curl -fsSL https://raw.githubusercontent.com/Aegmis/goose-intrupt-hook/main/install.sh | bash
#
# Or, after cloning:
#   bash install.sh

set -euo pipefail

REPO_RAW="${AEGMIS_REPO_RAW:-https://raw.githubusercontent.com/Aegmis/goose-intrupt-hook/main}"

# goose discovers plugins under ~/.agents/plugins/<name>/ (user scope).
PLUGIN_NAME="goose-intrupt-hook"
PLUGIN_DIR="$HOME/.agents/plugins/$PLUGIN_NAME"
ENV_FILE="$HOME/.config/goose/.env.intrupt"

if [ -n "${BASH_SOURCE:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR=""
fi

fetch() {
  local rel="$1" dest="$2"
  mkdir -p "$(dirname "$dest")"
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$rel" ]; then
    cp "$SCRIPT_DIR/$rel" "$dest"
  elif command -v curl &>/dev/null; then
    curl -fsSL "$REPO_RAW/$rel" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -qO "$dest" "$REPO_RAW/$rel"
  else
    echo "✗ Need curl or wget to download $rel" >&2
    exit 1
  fi
}

echo "→ Installing plugin into $PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR"
fetch "plugin.json"       "$PLUGIN_DIR/plugin.json"
fetch "hooks/hooks.json"  "$PLUGIN_DIR/hooks/hooks.json"
fetch "scripts/hook.py"   "$PLUGIN_DIR/scripts/hook.py"
chmod +x "$PLUGIN_DIR/scripts/hook.py"

if [ ! -f "$ENV_FILE" ]; then
  echo "→ Creating env file at $ENV_FILE"
  mkdir -p "$(dirname "$ENV_FILE")"
  cat > "$ENV_FILE" <<'EOF'
# intrupt hook configuration — sourced by your shell profile
export AEGMIS_BASE_URL=https://api.aegmis.com
export AEGMIS_API_KEY=sk_org_xxxx_yyyy      # replace with your API key
export AEGMIS_APPROVAL=true          # set false to disable the gate entirely
export AEGMIS_FORWARD_ALL=false        # local mode: the hook decides (no server round-trip)
export AEGMIS_GATED_TOOLS=developer__shell   # gate shell only (not developer__text_editor)
export AEGMIS_PROTECTED_PATHS="re:^$HOME$"  # gate rm of the home dir ITSELF (not its contents)
# export AEGMIS_BLOCKED_PATHS="re:^$HOME$"  # HARD-DENY these targets locally (denied instantly, never asks); opt-in
export AEGMIS_TIMEOUT=600
export AEGMIS_POLL_INTERVAL=5
export AEGMIS_CHANNEL=slack           # approval delivery channel: slack | email
EOF
  echo ""
  echo "   Edit $ENV_FILE and fill in your AEGMIS_API_KEY."
  echo "   Then add  source $ENV_FILE  to ~/.zshrc (or ~/.bashrc)."
  echo ""
fi

echo ""
echo "✓ Installation complete."
echo ""
echo "  Plugin:   $PLUGIN_DIR"
echo "  Env file: $ENV_FILE"
echo ""
echo "  Next steps:"
echo "  1. Edit $ENV_FILE with your API key"
echo "  2. Add  source $ENV_FILE  to ~/.zshrc (or ~/.bashrc) so goose inherits it"
echo "  3. Restart goose and try a gated command (e.g. git push)"
echo ""
echo "  IMPORTANT (goose fail-OPEN semantics): goose treats a hook timeout or"
echo "  any non-2 exit as ALLOW. Keep AEGMIS_TIMEOUT (600) BELOW the hooks.json"
echo "  \"timeout\" (630) so the hook denies before goose kills it. Do a one-time"
echo "  live check: ask goose to 'git push' and confirm it blocks pending approval."
echo ""
