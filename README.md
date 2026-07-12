# goose-intrupt-hook

A [goose](https://block.github.io/goose/) plugin that gates high-risk tool calls behind a human approval. Before goose runs a destructive shell command (`developer__shell`) or writes/edits a file (`developer__text_editor`), it pauses, notifies your approver via Slack (or any intrupt channel), and waits. The tool only runs if a human clicks **Approve**.

Built on the [Open Plugins](https://open-plugins.com) hook scaffold (`plugin.json` + `hooks/hooks.json` + `scripts/`), the same structure as goose's `hello-hooks` example.

```
goose
  └─ wants to run: git push origin main
        │
        ▼
  PreToolUse hook fires
        │
        ▼
  POST /org/{id}/approval  ──►  intrupt API  ──►  Slack message
        │                                              │
        │  poll every 5s                     human clicks Approve / Reject
        │                                              │
        ▼                                              ▼
  GET /approval/{id}  ◄──────────────────────  status = "approved"
        │
        ▼
  exit 0                    →  goose continues
  exit 2 / decision:block   →  goose blocks the tool
```

---

## ⚠️ Read this first — goose fails OPEN

Per goose's PreToolUse denial design ([PR #9304](https://github.com/aaif-goose/goose/pull/9304)):

> Runs hooks in order and stops at the first explicit deny (**exit code 2 or `{"decision":"block",...}` on stdout**). **Any other failure — spawn errors, timeouts, other non-zero exits — is logged and treated as Allow**, so a misbehaving hook can't block.

That means a crashed hook, a non-2 exit, **or a hook timeout all let the tool run**. This plugin is engineered around that:

- It blocks **only** via exit 2 (and also prints `{"decision":"block"}`).
- **Every** error path — bad payload, missing key, unreachable API, unexpected exception — is converted to an explicit exit-2 block. It never leaks an exit-1 traceback (which goose would treat as Allow).
- **`AEGMIS_TIMEOUT` (600 s) must stay below the `hooks.json` `timeout` (630 s)** so the hook denies on its own timeout *before* goose kills it. If goose kills it first, that's an Allow.

Do a **one-time live check** after install (ask goose to `git push`, confirm it blocks pending approval) to validate the block path on your goose build.

---

## Prerequisites

- goose with PreToolUse-denial hooks (PR #9304, merged) — check with a recent build
- Python 3.10+
- An [Aegmis](https://aegmis.com) account with an API key
- Slack workspace connected to your Aegmis org (for the default channel)

---

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Aegmis/goose-intrupt-hook/main/install.sh | bash
```

<details>
<summary>Prefer to clone first?</summary>

```bash
git clone https://github.com/Aegmis/goose-intrupt-hook.git
cd goose-intrupt-hook
bash install.sh
```

</details>

`install.sh`:

1. Copies the plugin (`plugin.json`, `hooks/hooks.json`, `scripts/hook.py`) into `~/.agents/plugins/goose-intrupt-hook/` and `chmod +x`es the script
2. Creates `~/.config/goose/.env.intrupt` with placeholder env vars

Then fill in your credentials and **restart goose**:

```bash
nano ~/.config/goose/.env.intrupt
source ~/.config/goose/.env.intrupt   # add this to ~/.zshrc or ~/.bashrc too
```

> goose inherits its environment from the shell that launches it, so the
> `AEGMIS_*` vars must be exported there (hence the `source` line).

---

## How it works

goose runs the plugin's `PreToolUse` hook before `developer__shell` / `developer__text_editor` calls, piping a JSON payload on stdin:

```json
{
  "event": "PreToolUse",
  "tool_name": "developer__shell",
  "tool_input": { "command": "git push origin main" },
  "session_id": "…",
  "working_dir": "/home/you/project"
}
```

- **`developer__shell`** → gate the command (`tool_input.command`)
- **`developer__text_editor`** → `tool_input.command` is the sub-command; `view` is a read (allowed), while `write` / `str_replace` / `insert` / `undo_edit` are gated (file at `tool_input.path`)
- any other tool → allowed immediately

Shell commands are checked against a risk-pattern list in local mode (**catastrophic `rm`** targeting home/root/system dirs — routine & project-local deletes pass, `git push`, `sudo`, `terraform apply`, `curl … | sh`, etc.). In **forward-all mode** (the default), every gated call is sent to the Aegmis policy engine instead.

| Outcome | Hook | goose |
|---|---|---|
| Human clicks **Approve** | exit 0 | Tool runs normally |
| Human clicks **Reject** | exit 2 + `decision:block` | Tool blocked, reason shown to goose |
| Timeout (`AEGMIS_TIMEOUT`) | exit 2 + `decision:block` | Tool blocked |
| API unreachable / hook crash | exit 2 + `decision:block` | Tool blocked (fail closed) |

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `AEGMIS_BASE_URL` | yes | — | intrupt API base URL |
| `AEGMIS_API_KEY` | yes | — | API key from Account → API Keys |
| `AEGMIS_APPROVAL` | no | `true` | Master kill switch — set `false` to disable the gate entirely (allow all) |
| `AEGMIS_GATED_TOOLS` | no | `developer__shell,developer__text_editor` | Comma-separated tool names to gate |
| `AEGMIS_FORWARD_ALL` | no | `true` | Forward every gated call to the policy engine (unmatched auto-approve) |
| `AEGMIS_TIMEOUT` | no | `600` | Max seconds to wait. **Must be < the `hooks.json` `timeout`** |
| `AEGMIS_POLL_INTERVAL` | no | `5` | Seconds between status polls |
| `AEGMIS_BYPASS_PATTERNS` | no | — | Comma-separated regex; matching shell commands skip approval |
| `AEGMIS_PROTECTED_PATHS` | no | `re:^$HOME$` (set by installer) | Comma-separated dir(s) to also gate `rm` on — each dir **and everything under it**, cwd-resolved. List **one or many** (e.g. `~/work,~/secrets`). Prefix an entry with **`re:`** for a regex tested against the resolved absolute path, e.g. `re:^$HOME$` (home dir only) or `re:^$HOME/(work\|important)(/\|$)` |

---

## goose plugin config

`install.sh` writes `hooks/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "developer__shell|developer__text_editor",
        "hooks": [
          {
            "type": "command",
            "command": "${PLUGIN_ROOT}/scripts/hook.py",
            "timeout": 630
          }
        ]
      }
    ]
  }
}
```

`${PLUGIN_ROOT}` is expanded by goose to the plugin's directory. The `matcher` is a regex compared against `tool_name`.

To disable temporarily, add the plugin to `disabledPlugins` in `~/.config/goose/settings.json`:

```json
{ "disabledPlugins": ["goose-intrupt-hook"] }
```

---

## Example: catastrophic-deletion gate + protecting your own paths

In **local mode** (`AEGMIS_FORWARD_ALL=false`) the hook gates only *catastrophic*
deletions and lets routine ones run untouched:

```bash
rm abc.txt                 # runs   — routine single-file delete
rm -rf node_modules        # runs   — project-local
rm -rf ~                   # ⛔ approval — wipes home
rm -rf /                   # ⛔ approval — wipes root
rm *                       # ⛔ approval — bare glob
```

To also require approval before deleting **specific dirs of yours**, list them:

```bash
export AEGMIS_PROTECTED_PATHS=/Users/you/work,/Users/you/important
```

### `AEGMIS_PROTECTED_PATHS` — literal paths and `re:` regexes

Comma-separated entries — each a **literal** dir or a **`re:`**-prefixed **regex** (the regex is tested against the resolved absolute `rm` target):

| Entry | Effect |
|---|---|
| `re:^$HOME$` | gate `rm` of the **home dir itself only** — `rm -rf ~` gates, but `rm -rf ~/project` and `rm ~/notes.txt` run free *(installer default)* |
| `re:^$HOME/(work\|important)(/\|$)` | gate the `work` + `important` **subtrees** |
| `~/work,re:^$HOME$` | **mixed** — literal `work` subtree *and* regex home-exact both gate; anything else runs free |
| `~/work` | plain **literal** — that dir and everything under it |

Anchor a regex with `^…$` to match a dir exactly (not its contents). Invalid regexes are skipped with a stderr warning.

**Worked examples** (write these as `AEGMIS_PROTECTED_PATHS` entries; `$HOME` expands when the env file is sourced):

| Intent | Entry |
|---|---|
| Protect **only the home dir itself**, not its contents | `re:^$HOME$` |
| Protect `work` + `important` (and their subtrees) | `re:^$HOME/(work\|important)(/\|$)` |
| Protect `project/demo` **except** `project/demo/scratch` | `re:^$HOME/project/demo/(?!scratch(/\|$)).*` |
| Protect any `.env` / secrets file anywhere under home | `re:^$HOME/.*(\.env(\|\.)\|/secrets?/)` |
| Multiple, mixed with literal | `$HOME/work,re:^$HOME$` |


Targets are resolved against the command's working directory, so relative refs are
caught too:

```bash
# with AEGMIS_PROTECTED_PATHS=/Users/you/work
cd /Users/you && rm -rf ./work     # ⛔ approval  (./work → /Users/you/work)
rm -rf /Users/you/work/build       # ⛔ approval  (under a protected dir)
rm -rf /Users/you/other            # runs        — not protected
```

---

## Testing

```bash
python3 test_hook.py
```

Expected output:

```
[PASS] shell — git push (gated)
[PASS] shell — ls (allowed)
[PASS] shell — rm -rf ~ (catastrophic, gated)
[PASS] shell — git status (allowed)
[PASS] text_editor — write (gated)
[PASS] text_editor — str_replace (gated)
[PASS] text_editor — view (allowed)
[PASS] other tool — not gated
[PASS] shell — deploy (gated)
[PASS] shell — sudo apt (gated)
[PASS] shell — curl | sh (gated)

Results: 11/11 passed ✓
```

The tests also assert the hook's exit code is always `0` or `2` — never another
non-zero code, which goose would silently treat as **Allow**.

---

## Security notes

- **Fails closed** on reject / timeout / unreachable API / crash — always via exit 2.
- The one residual fail-open risk is goose killing the hook on **its** timeout; the `AEGMIS_TIMEOUT` < `hooks.json timeout` ordering is what closes it. Keep that ordering if you tune either value.
- `AEGMIS_API_KEY` is a `Bearer` token — keep it in `.env.intrupt` with `600` permissions, not in shell history.

---

## Project structure

```
goose-intrupt-hook/
├── plugin.json           # Open Plugins manifest
├── hooks/
│   └── hooks.json        # PreToolUse trigger (matcher + ${PLUGIN_ROOT}/scripts/hook.py)
├── scripts/
│   └── hook.py           # the approval gate (zero runtime dependencies)
├── test_hook.py          # smoke tests for gating logic
├── install.sh            # one-line installer (Open Plugins layout)
├── policies.example.sh   # example Aegmis approval policies
├── .env.example          # environment variable template
└── README.md
```

---

## Uninstalling

```bash
rm -rf ~/.agents/plugins/goose-intrupt-hook
```
