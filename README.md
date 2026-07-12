# goose-intrupt-hook

A [goose](https://block.github.io/goose/) plugin that gates high-risk tool calls behind a human approval. Before goose runs a destructive shell command (`developer__shell`) or writes/edits a file (`developer__text_editor`), it pauses, notifies your approver via Slack (or any intrupt channel), and waits. The tool only runs if a human clicks **Approve**.

Built on the [Open Plugins](https://open-plugins.com) hook scaffold (`plugin.json` + `hooks/hooks.json` + `scripts/`), the same structure as goose's `hello-hooks` example.

```
goose
  │
  ├─ rm -rf /home/user          (matches AEGMIS_BLOCKED_PATHS)
  │     ⇒  ⛔ denied locally — no API call, no Slack
  │
  └─ kubectl delete pod nginx   (matches a risk pattern)
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

## Quick start

```bash
# 1. Install
curl -fsSL https://raw.githubusercontent.com/Aegmis/goose-intrupt-hook/main/install.sh | bash

# 2. Set your API key, then load the env
nano ~/.config/goose/.env.intrupt          # set AEGMIS_API_KEY=sk_org_...
source ~/.config/goose/.env.intrupt        # also add this line to ~/.zshrc or ~/.bashrc

# 3. Restart goose — done. High-risk actions now pause for Slack approval.
```

Installer defaults: **local mode**, **shell-only** gating, and deleting the home
dir itself routes to approval (`AEGMIS_PROTECTED_PATHS=re:^$HOME$`). To make a path
**impossible to delete** — denied instantly, never sent to a human — add it to
`AEGMIS_BLOCKED_PATHS` (e.g. `export AEGMIS_BLOCKED_PATHS=re:^$HOME$` in your env file).

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
  "tool_input": { "command": "rm -rf /home/user" },
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

## What gets gated

Two tiers, evaluated in **local mode** (`AEGMIS_FORWARD_ALL=false`, the installer default):

**Hard-blocked — denied instantly, never sent to a human** (`AEGMIS_BLOCKED_PATHS`)

Only an `rm` whose target (resolved against the command's cwd, so relative paths
count) matches a `AEGMIS_BLOCKED_PATHS` entry. Denied locally with no approval
round-trip. Opt-in — nothing is hard-blocked unless you list it.

**Gated — paused for Slack approval**

The hook ships **20 built-in risk patterns**, identical across all 9 hooks. Several are families (one pattern, many commands), so they cover **30+ distinct dangerous commands**:

| Category | Matches | Passes through |
|---|---|---|
| Catastrophic `rm` | `rm -rf ~`, `rm -rf /`, `rm -rf /Users/you`, `rm *`, `rm -rf .` | `rm file.txt`, `rm -rf node_modules`, `rm -rf build` |
| Protected paths | `rm` of any dir in `AEGMIS_PROTECTED_PATHS` (default `re:^$HOME$`) + its subtree | anything not listed |
| Git | `git push` (incl. `--force`), `git reset --hard` | `git status`, `git commit`, `git pull` |
| Publish / release | `gh pr merge`, `gh release`, `npm publish`, `deploy` | builds, tests |
| Infra | `kubectl delete`/`apply`, `terraform apply`/`destroy` | `kubectl get`, `terraform plan` |
| Database | `DROP TABLE`, `TRUNCATE TABLE` | `SELECT`, `INSERT` |
| Disk | `dd if=`, `mkfs` | — |
| Privilege / perms | `sudo`, `chmod 777`, `chown … root` | `chmod 644` |
| Remote-to-shell | `curl … \| sh`, `wget -O- … \| sh` | plain `curl`/`wget` downloads |

Plus any **file write/edit** tool call is gated whenever that tool is in
`AEGMIS_GATED_TOOLS` — the installer default gates the **shell only**, so file
writes run free out of the box until you add them.

Everything else — reads, listings, `ls`, routine deletes — runs untouched. In
**forward-all mode** (`AEGMIS_FORWARD_ALL=true`) these local patterns are bypassed
and every gated tool call is sent to the **server-side policy engine** instead,
where your Aegmis policies decide — any command you write a policy for. The
`policies.example.sh` reference ships **~23 more** ready-to-use destructive-action
regexes (`find -delete`, `shred`, `docker push`, `crontab -r`, cloud-CLI deletes,
`kill`/`shutdown`, and more).

---

## Guarding your paths (approval vs hard-block)

Two env vars control what happens when the agent tries to `rm` a path you care
about. Both take a comma-separated list of **literal dirs** or **`re:`-prefixed
regexes**, resolved against the command's cwd (so relative targets like `./work`
are caught too).

| Variable | A matching `rm`… | Reach for it when |
|---|---|---|
| `AEGMIS_PROTECTED_PATHS` | pauses for **Slack approval** — a human can still allow it | the path matters but is *sometimes* legitimately deleted |
| `AEGMIS_BLOCKED_PATHS` | is **denied locally, instantly** — no Slack, nothing to approve | the path must **never** be deleted by the agent |

If a path matches **both**, the hard block wins — it's checked first, before any
approval round-trip. Both are **local-mode** features (`AEGMIS_FORWARD_ALL=false`,
the installer default).

### Minimal steps

1. Open your env file: `~/.config/goose/.env.intrupt`
2. Add either variable — one path or many, comma-separated:

   ```bash
   # Ask a human before deleting these  →  approval
   export AEGMIS_PROTECTED_PATHS="$HOME/work,$HOME/important"

   # Never let the agent delete these   →  hard block (no approval)
   export AEGMIS_BLOCKED_PATHS="re:^$HOME$,$HOME/.ssh"
   ```
3. Reload it: `source ~/.config/goose/.env.intrupt` (or restart goose).

### Examples

| Goal | Entry |
|---|---|
| Approve before wiping the home dir itself | `AEGMIS_PROTECTED_PATHS=re:^$HOME$` |
| Approve deletes of `work` + `important` (and their subtrees) | `AEGMIS_PROTECTED_PATHS=re:^$HOME/(work\|important)(/\|$)` |
| Hard-block `~/.ssh` and everything under it | `AEGMIS_BLOCKED_PATHS=$HOME/.ssh` |
| Hard-block the home dir itself (its contents still run free) | `AEGMIS_BLOCKED_PATHS=re:^$HOME$` |
| Mix — approve `work`, hard-block `~/.ssh` | `AEGMIS_PROTECTED_PATHS=$HOME/work` · `AEGMIS_BLOCKED_PATHS=$HOME/.ssh` |

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
| `AEGMIS_CHANNEL` | no | `slack` | Where the approval request is delivered — `slack` or `email` |
| `AEGMIS_BYPASS_PATTERNS` | no | — | Comma-separated regex; matching shell commands skip approval |
| `AEGMIS_PROTECTED_PATHS` | no | `re:^$HOME$` (set by installer) | Comma-separated dir(s) to also gate `rm` on — each dir **and everything under it**, cwd-resolved. List **one or many** (e.g. `~/work,~/secrets`). Prefix an entry with **`re:`** for a regex tested against the resolved absolute path, e.g. `re:^$HOME$` (home dir only) or `re:^$HOME/(work\|important)(/\|$)` |
| `AEGMIS_BLOCKED_PATHS` | no | — | Same syntax as `AEGMIS_PROTECTED_PATHS`, but an `rm` hitting one is **denied locally with no approval round-trip** — never sent to a human. Use for paths that must *never* be deleted. **Local mode only** (`AEGMIS_FORWARD_ALL=false`). |

**Approval channel:** requests go to **Slack** by default. To deliver them over **email** instead, set `AEGMIS_CHANNEL=email` in your env file.

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
