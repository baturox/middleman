# middleman

[![Release](https://img.shields.io/github/v/release/baturox/middleman)](https://github.com/baturox/middleman/releases/latest)
[![CI](https://github.com/baturox/middleman/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/baturox/middleman/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**middleman lets Claude Code hand big, routine coding jobs to cheap models (DeepSeek, Qwen, GLM, Kimi on OpenRouter) without your secrets, company names or private paths ever reaching them.**

Claude is expensive and plans have usage limits. Models on OpenRouter cost 20–250× less per output
token and are good at routine work: test suites, boilerplate, docstrings, translations. Most teams
don't send them code because they don't know what happens to it. middleman is a small program that
runs on your machine and sits in between.

## What it does

When a job is handed to a cheap model, middleman:

1. **Reads only the files you name.** It never reads `.env` files, keys, `secrets/`, `.git` or `.ssh`.
2. **Cleans the job.** If it finds a secret (API key, token, password, private key, card or ID
   number), it stops and sends nothing. Otherwise it replaces company and product names, hosts,
   URLs, emails, IPs and file paths with consistent fake ones, then checks the outgoing text once
   more and blocks it if any real value is still there.
3. **Sends it, then undoes the swap.** It picks the cheapest suitable model, puts your real names
   back in the answer, writes the result to a file (an existing file is never overwritten: you get
   a `.middleman.new` copy and a `.patch`), flags risky code, and logs what it really cost.

What the cheap model sees:

| In your code | What is sent |
|---|---|
| `class AcmeInvoice:` | `class ZentroInvoice:` |
| a URL on your internal network | `https://svc1.example.net/p1` |
| a colleague's email | `user1@example.com` |
| `src/billing/acme_rules.py` | `src/f1.py` |
| `AWS_KEY = "AKIA…"` | nothing: the job is blocked |

## What it does not do

- **It hides who you are, not what the code does.** Logic, structure and any names not in your
  private list go to the model. Keep valuable code on Claude by declaring it confidential.
- **It doesn't hide your account.** The provider sees your OpenRouter account, IP and timing.
- **It doesn't trust the answer.** Output from a cheap model is untrusted: review it before you run it.
- **It isn't for small edits.** Handing off a one-line change costs more than it saves, so middleman refuses.

## Install

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/baturox/middleman/main/install.sh | sh
```

It downloads the release for your machine, checks its SHA-256 checksum (and its build provenance
if the GitHub CLI is logged in), and installs it to `~/.local/bin`.

<details>
<summary>Other ways to install</summary>

Download a build from [Releases](https://github.com/baturox/middleman/releases/latest): macOS
(Apple Silicon, Intel), Linux (x86_64, ARM64), Windows (x86_64). Or build it:

```sh
cargo install --git https://github.com/baturox/middleman --locked
```
</details>

## Set up

```sh
middleman init           # pick a provider (OpenRouter), log in or paste a key, choose when Claude may delegate
middleman setup claude   # connect it to Claude Code: shows each change first, keeps backups (--undo reverts)
middleman doctor         # checklist of what works
```

Your key is checked with a free request and stored in the macOS Keychain or the system keyring,
never in the config.

## Use it

Start a prompt with `cheap:` and say which file to work on:

```
cheap: write tests for src/date.py -> tests/test_date.py
```

The prompt never reaches Claude, so Claude spends nothing. middleman runs the job and shows:

```
🛡 middleman · cheap: done by a cheap model; Claude spent 0 tokens
  wrote    tests/test_date.py (84 lines)
  cost     $0.0006 · net saving ~$0.04
  risk     low
  next     review it yourself, or ask Claude: "review tests/test_date.py"
```

If the prompt is unclear, it shows the accepted syntax. Sensitive topics (auth, payments, customer
data) are refused.

Claude can also hand off jobs by itself through middleman's MCP tool. Each hand-off costs Claude
one extra turn, which re-reads the whole conversation, so it only pays off for large outputs or
short sessions. middleman refuses jobs below that break-even point, based on your session's real
context size.

### Let cheap models do the routine work

```
middleman claude                 # asks how to run; or: --mode smart | cheap | claude
```

| Mode | What happens |
|---|---|
| `smart` (default) | A local proxy sends hard prompts to Claude and routine ones to a cheap OpenRouter model. Near your 5-hour limit (90%) everything goes cheap. |
| `cheap` | Everything on the cheap model (`z-ai/glm-5.3`); your Claude plan is not used. |
| `claude` | Normal Claude Code. |

Switch while running with `middleman mode cheap`, or per prompt with `!cheap` / `!claude` at the start.
Needs an OpenRouter key (`middleman provider add openrouter`); change models with `--model` or
`[launch] model` in the config. To run on miav instead (`claude-opus-5.5`, `gpt-6.1-sol`):
`middleman provider add miav`, then `provider = "miav"` under `[launch]`. Cheap turns send whole files **uncleaned**, so only use this for code
you'd be fine publishing: middleman asks once per repo (or put `allow = true` under `[launch]` in
`.middleman.toml`). Cheap models are weaker at hard multi-step work, and a model switch starts a
fresh prompt cache.

`middleman bench` runs 5 small tasks through each mode with real Claude Code and prints cost and pass
rate per mode (`--modes cheap` never touches your Claude plan). It shows the worst-case spend first.

## Is it saving money?

```sh
middleman report --since 7d        # also --by model|task|day, --html for a dashboard
```

**Saved** is what Claude would have charged to write the output, minus:

- Claude's own cost for the hand-off (the tool call, the extra turn, reading the result);
- the cheap model's cost, as billed by OpenRouter.

Blocked jobs count their overhead too, and a loss is shown as a loss. `middleman report --reconcile`
checks the log against your OpenRouter account. On a Pro/Max subscription, savings mean more usage
before you hit your limits rather than a smaller bill.

`middleman savings` explains the total line by line (output avoided, cheap-model cost, hand-off
cost, blocked attempts, net). `middleman savings reset` starts counting from now (the log is kept;
`report --all` still shows everything). Test runs are never counted; `report --include-tests`
shows them. The status line shows savings only after the first real job has succeeded.

## Protect your company names

```sh
middleman dict suggest
```

It reads your repo locally (folder name, git remote, package and author names, hostnames in config)
and proposes names for your private list. Names on the list are replaced in every job. **Until your
names are on it, they are sent as written.** `middleman doctor` warns when the list is empty.

## Extras

### Where does my Claude money go?

`middleman usage --since 30d` shows your Claude Code spend by project, model and session, from
Claude Code's local logs (totals only; nothing is sent). `middleman tune` turns it into settings
changes with an estimated saving each, and `--apply` merges them into `settings.json` with a backup.

### Status line

```
Opus 5.5 high · ████░░░░░░ 38% 380k/1M │ 🛡✓ $9.95 left · saved $0.21 · total $1.84
```

Context used, OpenRouter credit left, and net saved today and in total. It shrinks to the most
important numbers on narrow terminals. Turn it off or on with `middleman statusline off` / `on`.

### Upgrading

```sh
middleman upgrade            # also --check, --rollback
```

It verifies the download, keeps the previous version, updates middleman's own Claude Code settings,
and the running MCP server switches to the new version by itself. `middleman update-settings auto`
installs patch releases in the background (the default is `notify`). On macOS, releases aren't
signed with a paid Apple Developer ID, so macOS asks once after each upgrade before middleman can use
its Keychain key: click **Always Allow**.

## Commands

| Command | What it does |
|---|---|
| `init` | Guided setup: provider, key, when Claude may delegate |
| `setup claude [--undo\|--refresh]` | Connect to Claude Code, undo it, or update it after an upgrade |
| `doctor` | Checklist of what works |
| `provider add\|list\|test\|rotate\|remove` | Manage provider keys (never shown) |
| `claude [--mode smart\|cheap\|claude]` | Claude Code with cheap models doing the routine work |
| `mode [smart\|cheap\|claude]` | Change the mode of a running session |
| `bench` | Measure what each mode costs and whether it passes small tasks |
| `login openrouter` | Get an OpenRouter key through the browser |
| `dict suggest` | Propose company and people names for your private list |
| `check <files>` | Dry run: show exactly what would be sent, without sending |
| `route "<prompt>"` | Show whether a prompt would be handed off, and why |
| `approve <id>` | Approve one job when Claude must ask first (run it yourself) |
| `report` | What was handed off, to which model, and the net saving |
| `watch` | Live feed of hand-offs |
| `usage` / `tune` | Your Claude Code spend, and settings that cut it |
| `models refresh` | Fetch current models and prices |
| `statusline on\|off` | Show or hide the status line |
| `upgrade [--check\|--rollback]` | Update middleman |
| `update-settings notify\|auto\|off` | How middleman keeps itself up to date |

<details>
<summary><b>Privacy details</b></summary>

| Risk | What middleman does | What remains |
|---|---|---|
| Secrets in code | Detects them and blocks the job | Unusual secret formats |
| Who you are | Replaces names on your list, hosts, URLs, emails, IPs, paths | Names not on your list |
| Sensitive files | Never reads `.env`, keys, `secrets/`, `.git`, `.ssh` | Add your own folders to the deny list |
| Business logic | Size limits, allowed task types, sensitivity levels | The logic itself can't be hidden |
| Bad answers | Untrusted; risky code is only staged, never run by middleman | You or Claude must review |
| Account, IP, timing | Not hidden | Use a separate account if it matters |

The tests behind this are described in [docs/LEAK-VALIDATION.md](docs/LEAK-VALIDATION.md).
</details>

<details>
<summary><b>Configuration</b></summary>

`~/.config/middleman/config.toml` (full example: [config/middleman.example.toml](config/middleman.example.toml)):

```toml
[providers.openrouter]
preset = "openrouter"
key_source = "keychain"
model = "qwen/qwen3.8-flash"

[routes.write_tests]
chain = ["auto:code:cheapest", "openrouter/deepseek/deepseek-v4.1-flash", "claude"]

[routing]
mode = "confirm"        # confirm: you approve each hand-off · auto · explicit: only `cheap:`

[budget]
per_call_usd = 0.05
daily_usd = 1.0
```

A `.middleman.toml` inside a repo can only make the rules stricter.
</details>

## Contributing

Issues and pull requests are welcome. Before opening one, run:

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Design notes are in [PLAN.md](PLAN.md).

## License

[MIT](LICENSE)
