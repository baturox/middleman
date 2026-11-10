# middleman

[![Release](https://img.shields.io/github/v/release/baturox/middleman)](https://github.com/baturox/middleman/releases/latest)
[![CI](https://github.com/baturox/middleman/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/baturox/middleman/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange)

**Cut your Claude Code bill: let cheap models (DeepSeek, Qwen, Kimi, GLM) do the grunt work, without
them seeing your secrets or knowing whose code it is.**

---

## What is middleman?

Claude is great but expensive. Chinese models on OpenRouter are often **20–250× cheaper** and good at
routine work such as writing tests, boilerplate and docs. Most companies won't send them their code,
though, because they don't know what happens to it.

middleman is a small program that runs **on your machine**, next to Claude Code. It does three things:

1. **📊 Shows where your Claude Code money goes.** It reads Claude Code's local logs and breaks the
   cost down by project, model, session and token type.
2. **🎯 Tells you what to change.** It turns that data into concrete settings with an estimated
   saving for each (for example, "run subagents on Sonnet: saves ~11%").
3. **🛡️ Hands big, boring jobs to cheap models, safely.** When Claude needs, say, a test suite, it
   can pass the job to middleman. middleman removes secrets, replaces your company's names, hosts and
   emails with fake ones, sends the job to a cheap model, puts the real names back, and writes the
   result to a file. Claude reviews the diff, then runs the tests.

The cheap provider only ever sees something like this:

| In your code | What the provider receives |
|---|---|
| `class AcmeInvoice:` | `class ZentroInvoice:` |
| `db.acme-internal.com:5432` | `svc2.example.net:5432` |
| `ali@acme.com` | `user3@example.com` |
| `/Users/ali/acme/src/billing.py` | `/workspace/app/src/billing.py` |
| `AWS_KEY = "AKIA…"` | **nothing: the request is blocked** |

## A real example

> **You:** write unit tests for `src/date_parser.py`

1. middleman's prompt hook sees a big, low-risk job and suggests delegating it.
2. Claude calls `delegate_task` with the file path. It doesn't paste the code, which keeps Claude's
   own token use small.
3. middleman reads the file, cleans it, and sends it to `deepseek/deepseek-v4.1-flash`.
4. The tests come back, a risk scan runs, the real names are restored, and the result is saved to
   `tests/test_date_parser.py`. If the output contains anything risky (new hosts or IP addresses,
   process/exec/eval/network calls, import-time side effects), it is only staged as
   `tests/test_date_parser.py.middleman.new` and Claude is told to read it first.
5. Claude reviews the diff (reading any flagged lines), then runs the tests and fixes anything that fails.

**Cost:** about **$0.003** with DeepSeek, against about **$0.04** if Claude (Opus) wrote the same
~2,000 tokens itself. The saving is logged, so you can check it later with `middleman report`.

If you ask for anything touching **auth, billing, customer data or secrets**, the hook tells Claude
to **keep it on Claude**, and middleman refuses it if Claude tries anyway.

## How it works

<p align="center">
  <img src="docs/architecture.svg" alt="middleman flow: Claude Code sends file paths; middleman reads the files, detects secrets, decides whether it is safe and worth it (if not, Claude does it itself), replaces names with fake ones, sends sanitised text to a cheap OpenRouter model, restores the names, writes the result to a file, logs the cost, and returns a summary to Claude" width="900">
</p>

<sub>Editable source: [`docs/architecture.drawio`](docs/architecture.drawio) (open it in draw.io)</sub>

- **Fails closed.** If anything is unclear (a possible secret, an unknown price, a broken config,
  a dictionary term hidden with look-alike letters or separators), nothing is sent and Claude does
  the job itself.
- **Two independent checks.** Detection runs on a normalized view of the text (Unicode NFKC,
  invisible characters removed, full case folding). Then the egress gate checks the final payload
  again, on its own: it re-runs every detector and searches the normalized payload for every
  dictionary term and every original value. Any hit blocks the request.
- **Detection is best-effort.** No scanner finds every secret or every way of writing a name. The
  private dictionary, the deny-listed paths and the rule *only delegate low-value code* remain
  essential.
- **Only when it pays off.** Each hand-off costs Claude a little overhead (about 830 output tokens'
  worth on Opus), so small tasks are refused and done by Claude.
- **Your names stay local.** The mapping from fake names back to real ones lives in memory only and
  is never written to disk.
- **Every call is logged**, including blocked ones: model, tokens, cost and net saving.

## Install

**macOS and Linux**, one line:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/baturox/middleman/main/install.sh | sh
```

This downloads the right binary from [Releases](https://github.com/baturox/middleman/releases/latest),
checks its SHA-256 (it refuses to install on a missing or wrong checksum) and installs it to
`~/.local/bin`. If the GitHub CLI is installed it also verifies the build-provenance attestation
(`MIDDLEMAN_REQUIRE_ATTESTATION=1` makes a failed check fatal). The macOS binary is not code-signed;
the installer removes the quarantine flag and says so.

Every release archive carries a [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations).
To check a download yourself:

```sh
gh attestation verify middleman-<version>-<target>.tar.gz --repo baturox/middleman
```

<details>
<summary>Other options: manual download, Windows, build from source</summary>

| Platform | Release file |
|---|---|
| macOS Apple Silicon | `middleman-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `middleman-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `middleman-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `middleman-<version>-aarch64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `middleman-<version>-x86_64-pc-windows-msvc.zip` |

```sh
tar -xzf middleman-*-aarch64-apple-darwin.tar.gz
install -m 0755 middleman-*/middleman ~/.local/bin/
xattr -d com.apple.quarantine ~/.local/bin/middleman 2>/dev/null   # macOS: allow the unsigned binary
```

From source (Rust stable):

```sh
cargo install --git https://github.com/baturox/middleman --locked
```

</details>

## Quick start

Run `middleman init`. It asks four things with arrow-key menus and checks your key before saving:

```text
  🛡  middleman setup                              step 1 of 4 · Where to install
✔ Install for… · All my projects (user)

  🛡  middleman setup                                      step 2 of 4 · Provider
? Pick a provider ›
❯ Recommended  OpenRouter        one key for DeepSeek, Qwen, Kimi, GLM and 300+ models
  Direct       DeepSeek          DeepSeek's own API, very cheap coding models · URL unverified
               …
  Local, free  Ollama            models on this computer, no key
  Other        Custom URL        any OpenAI-compatible endpoint
✔ Pick a provider · OpenRouter

  OpenRouter · get a key at https://openrouter.ai/settings/keys
✔ How do you want to connect OpenRouter? · Paste an API key
✔ Paste your OpenRouter API key (hidden) · ********
  ✗ OpenRouter rejected this key (HTTP 401).
    The key is wrong, incomplete or revoked. Copy it again from https://openrouter.ai/settings/keys.
✔ What now? · Paste a different key
✔ Paste your OpenRouter API key (hidden) · ********
  ✓ OpenRouter works: label middleman, limit $10.00 ($7.50 left), used $2.50
  ✓ Key stored in macOS Keychain (service middleman, account openrouter)
✔ Default model for coding jobs (optional) · Automatic
✔ Add another provider? · no

  🛡  middleman setup                                  step 3 of 4 · Routing mode
✔ When may Claude delegate? · Ask me each time (confirm)

  🛡  middleman setup                                          step 4 of 4 · Done
  Config         ~/.config/middleman/config.toml
  Mode           Ask me each time (confirm)
  Providers      ✓ OpenRouter  label middleman, $7.50 left · key in macOS Keychain
✔ Connect to Claude Code now? (runs `middleman setup claude`, shows the changes first) · yes
```

Restart Claude Code and the status line shows your model and context, then `🛡 ✓ openrouter`.

- **Routing modes:** *confirm* (the default) shows you what would be sent and waits for
  `middleman approve <id>` in your terminal; *auto* lets Claude delegate safe, big-enough jobs
  by itself (all logged); *explicit* only delegates prompts that start with `cheap:`.
- The key goes to your OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret
  Service), never into the config or your shell history. Run `init` again to keep, update or
  start fresh (the old config is backed up).
- `setup claude` (also offered at the end of `init`) registers the MCP server, allows its two
  tools, adds the prompt hook, the statusline and the CLAUDE.md block, and lists each change
  first. `--dry-run` only shows them, `--details` adds the exact keys, `--undo` puts the old
  files back.
- Scripts: `middleman init --yes` (OpenRouter, user scope, confirm mode), plus
  `--providers`, `--mode`, `--scope`, `--base-url` and `--key-stdin`. `middleman init --list`
  shows every provider and whether its key is set.
- Later: `middleman models refresh` fetches current prices, `middleman usage` and `middleman tune`
  show where your Claude Code money goes, and `middleman doctor` checks everything.

<details>
<summary>Keys: other providers, rotation, scripts</summary>

```sh
middleman provider add            # pick a provider, paste the key (hidden), it's checked with a free request
middleman provider list           # where each key is stored (never the key); --all lists every provider
middleman provider test openrouter
middleman provider rotate openrouter
middleman provider remove deepseek
middleman login openrouter --no-browser   # over SSH: open the link anywhere, paste the code back
pass show openrouter | middleman provider add openrouter --key-stdin   # scripts
```

Environment variables (`OPENROUTER_API_KEY`, ...) still work and win over a stored key. If no
keychain is available (e.g. a headless Linux box), the key goes to a private file
(`~/.config/middleman/keys/<provider>`, mode 0600) and middleman says so.

</details>

## How do I know it's working?

- **Status line**, at the bottom of Claude Code (see [The status line](#the-status-line)):
  `Opus 5.5 high │ ██░░░░░░░░ 18% 180k/1M │ ~$1.27 │ cache 47m left (1h) │ 🛡 ✓ $7.42 · 2 jobs · saved $0.21 today`.
  It shows `✗` and the reason when the config is broken, no key is found or the key is rejected.
- **Hook message**: when you send a prompt, a short line tells you what middleman told Claude,
  e.g. `🛡 middleman: suggested delegating this write_tests task (~3000 output tokens) to a cheap model`
  or `🛡 middleman: keep on Claude (sensitive: billing)`.
- **Tool result**: every `delegate_task` result starts with one line, such as
  `middleman: done via openrouter/deepseek/deepseek-v4.1-flash; wrote tests/test_dates.py (84 lines); cost $0.0028, net saving $0.0216.`
- **`middleman watch`** in another terminal prints each delegation as it happens: time, task,
  model, sensitivity, what was redacted, tokens, cost, net saving, and the reason when blocked.
- **`middleman report`** sums it all up afterwards.

Each log line records the Claude Code session id when it's known. The MCP server gets the id
Claude Code started it with, so after `/clear` its calls still carry the earlier id.

## The status line

`middleman setup claude` sets Claude Code's `statusLine` to `middleman statusline`. By default it
prints one line, shortened to fit the terminal (`COLUMNS`); `--lines 2` (or
`MIDDLEMAN_SL_LINES=2`) puts middleman's part on a second line:

```
Opus 5.5 high │ ██░░░░░░░░ 18% 180k/1M │ ~$1.27 │ cache 47m left (1h)
🛡 middleman ✓ openrouter $7.42 left · 2 jobs this session (1 blocked, 1 escalated) · 3 today · 2 agents · saved $0.06 session · $0.21 today · $1.84 total
```

The same data at 120 and 60 columns, on one line:

```
Opus 5.5 high │ ██░░░░░░░░ 18% 180k/1M │ ~$1.27 │ cache 47m left (1h) │ 🛡 ✓ $7.42 · 2 jobs · saved $0.21 today
Opus 5.5 high │ 18% │ ~$1.27 │ 🛡 ✓ saved $0.21
```

| Part | Meaning |
|---|---|
| `Opus 5.5 high` (`fast`) | Session model, effort level, fast mode |
| `██░░░░░░░░ 18% 180k/1M` | Context used: share of the window, tokens, window size. Yellow at 40% or 150k, red at 70% or 300k (then `/compact or /clear` appears) |
| `~$1.27` | Claude Code's estimate of this session's cost (yellow at $5, red at $10) |
| `cache 47m left (1h)` | Prompt cache: time until it goes cold, and its lifetime; `cache cold: next message re-caches 180k` when expired |
| `5h 72%` | Claude's 5-hour rate limit, when Claude Code reports it |
| `🛡 ✓ openrouter` / `✗ <reason>` | middleman can delegate (provider and key OK), or why not |
| `$7.42 left` | What the provider still lets you spend: the lower of the account balance and the key's limit. `(25m ago)` when the cached value is older than 10 minutes |
| `2 jobs this session (1 blocked, 1 escalated)` · `3 today` | Delegation requests from this session and today; blocked includes "do it yourself" |
| `2 agents` | Claude Code subagents this session started (Agent/Task tool uses in its transcript) |
| `saved $0.06 session · $0.21 today · $1.84 total` | **Net** saving (see below); negative values are shown as they are, in red |

Colour thresholds use the same environment variables as context-line:
`MIDDLEMAN_SL_WARN_PCT` (or `CONTEXT_LINE_WARN_PCT`, default
40), `_DANGER_PCT` (70), `_WARN_TOKENS` (150000), `_DANGER_TOKENS` (300000), `_COST_WARN` (5).
`NO_COLOR` turns colours off; `MIDDLEMAN_SL_TOKENS=1` adds Claude output tokens avoided today;
`MIDDLEMAN_SL_NO_REFRESH=1` stops the background limit refresh.

**Already have a status line** (for example context-line)? `setup claude` leaves it alone and says
how to combine them. Either let middleman print the whole thing (it includes context-line's
fields): `middleman setup claude --statusline combined` (two lines; `--undo` brings yours
back). Or keep yours and append middleman's part from your script with the same stdin:

```sh
input=$(cat)
printf '%s\n' "$input" | node ~/.claude/context-line/statusline.mjs
printf '%s\n' "$input" | middleman statusline --middleman-only
```

**How it stays fast and private.** The status line never touches the network and finishes in a
few milliseconds. Provider limits come from a cache (`~/.local/state/middleman/provider-limits.json`,
0600) written by `middleman provider refresh`, by the MCP server after each delegation, and, when
the cache is older than 10 minutes, by one background `provider refresh --quiet` the status line
starts (a lock file allows one at a time). Subagents are counted by reading only the bytes added to
the transcript since the last run (the offset and counts are cached per session); nothing from
the transcript is stored or printed. Ledger totals are kept the same way. Every printed field is
stripped of control, escape and bidi characters.

The status line also passes the session's **live context size, model and cache lifetime** to the
MCP server (`~/.local/state/middleman/sessions/<id>.json`, 0600), so the savings maths uses the
real numbers instead of assumptions.

## How savings are calculated

"Saved" is always the **net** saving, per request:

```
net = claude_equiv - overhead - cheap_cost

claude_equiv = N_claude x P_out
overhead     = call_tokens x P_out              Claude writes the tool call
             + context_tokens x P_cache_read    the extra turn re-reads the session context
             + result_tokens x P_cache_write    the tool result enters the cached context
cheap_cost   = what the provider billed, summed over every attempt (escalations included)
```

| Term | Source | Measured or estimated |
|---|---|---|
| `N_claude` | Characters of the restored output (the file content in file mode) ÷ Claude's tokenizer ratio: 3.5 chars/token for code, 4.2 for prose (`chars_per_token_code` / `_prose`) | Estimated from measured text. The cheap model's token count is not used: other tokenizer, and it includes reasoning tokens |
| `call_tokens` | Characters of the tool-call arguments Claude sent ÷ 3.5, + 30 for the tool_use framing | Estimated from measured text |
| `context_tokens` | The session's live context from the status line (input + cache read + cache write of the latest request); `assumed_context_tokens` (60k) when unknown or older than 30 minutes | Measured by Claude Code, or assumed (`context_source` says which) |
| `result_tokens` | Characters of the tool result Claude reads (summary line + JSON) ÷ 3.5 | Estimated from measured text |
| Prices | The session's model (opus / sonnet / haiku / fable, from the status line's `model.id`), else `[economics] claude_model`. Cache write = input × 1.25 (5-minute cache) or × 2 (1-hour cache) | Price table (`price_basis` says which) |
| `cheap_cost` | 1. `provider`: the billed cost in the response (OpenRouter `usage.cost`); 2. `balance`: balance before − after, only when no other middleman call was in flight; 3. `usage`: reported tokens × catalog price; 4. `estimate`: the worst case when a failed call may have been billed | Measured (1, 2) or estimated (3, 4); `cost_source` says which |

The tool result is priced at the **cache-write** price, not the plain input price: Claude Code
caches the conversation, so new content is written to the cache on the next request.

- **Blocked, do-it-yourself and dry-run calls** cost no cheap money, but Claude still paid for
  the tool call, the extra turn and the result: their overhead is logged, so they lower "saved".
  (Dry runs are only logged when Claude made them through the MCP tool.)
- **Each request has exactly one closing line** carrying the overhead; escalation attempts carry
  only their own cost. Every line satisfies `net = claude_equiv - overhead - cost` (enforced on
  write and read), so per-line, per-request, per-day, per-session and all-time sums agree;
  `report`, `middleman_status` and the status line all use the same aggregation.
- **What is not counted** (so "saved" is, if anything, low): had Claude written the file itself, it
  would also have paid a Write tool call and turn, and its own output would be re-read on every
  later turn; the tool result is likewise re-read on later turns.
- `middleman report --reconcile` compares the ledger's cost with the provider's own counters
  (OpenRouter `/key` usage for today and since the last snapshot; balance drops for `/balance`
  gateways) and prints any discrepancy.

With a large context the extra turn dominates: at 380k tokens of Opus context it alone costs
$0.076, so a delegation pays only above roughly 4,000 output tokens. The break-even gate uses the
live context too.

## Saving money: what actually matters

`middleman usage` on 30 days of heavy Claude Code use showed that **about 80% of the bill is Claude
re-reading the conversation on every turn**. Only about 19% is Claude writing code. So the biggest
savings come from settings, and `middleman tune` estimates each one from your own data:

| Change | Typical saving | Data leaves your machine? |
|---|---|---|
| Keep conversations under ~200K tokens (compact earlier, `/clear` between tasks) | ~16% | No |
| Run subagents on Sonnet 5.5 instead of Opus | ~11% | No |
| Use Sonnet 5.5 for routine sessions | ~8% | No |
| Turn off unused plugins and skills (sessions start at ~82K tokens) | ~5% | No |
| Hand big jobs to cheap models via middleman | grows with how much you delegate | Only sanitised text |

`middleman tune` prints the exact `settings.json` change. Run it with `--apply` to merge the change,
after a backup is taken.

> On a Claude **Pro/Max subscription** you don't pay per token, so these savings mean **more usage
> before you hit limits**. On **API billing** they are real dollars. Reports show both.

## The cheapest way: `cheap:` prompts

Type the job yourself, with `cheap:` in front:

```
cheap: write tests for src/date.py -> tests/test_date.py
cheap: add docstrings to src/util.ts:1-120
cheap: summarize docs/design.md
```

The prompt hook runs the delegation itself, through every protection above, and stops the
prompt there: **Claude never sees it, so Claude spends nothing**. You get a short report in
place of Claude's answer:

```
🛡 middleman · cheap: done by a cheap model; Claude spent 0 tokens
  model    openrouter/qwen/qwen3.8-flash
  wrote    tests/test_date.py (42 lines)
  cost     $0.00031 · net saving ~$0.0210
  risk     low
  next     review it yourself, or ask Claude: "review tests/test_date.py"
```

- Syntax: `cheap: <task> <file>[:start-end] [more files] [-> output]`. Tasks: tests,
  docstrings, summarize, translate, boilerplate, explain (English or Turkish keywords).
- Without `->`, the output goes next to your test layout (`tests/test_<name>.py`,
  `<name>.test.ts`, `<name>_test.go`, ...); docstrings are staged over the file itself
  (`.middleman.new` + `.middleman.patch`); summaries and explanations go to `.middleman/out/`.
- If the task or the file can't be read off the prompt, nothing is guessed: the prompt is
  stopped with the syntax. Prompts that touch sensitive topics (auth, billing, secrets,
  deploys, ...) are refused; ask Claude instead.
- Typing `cheap:` is your approval, also in `confirm` and `explicit` mode. The usage log marks
  these runs `"via":"hook"` with zero Claude-side cost, so the savings in `report` are real.
- The report is shown to you only. If you want Claude to look at the result, ask it to.

**When delegating from inside Claude still pays off.** When Claude calls the MCP tool itself,
the call and the extra turn cost Claude tokens: in a long session (~380K context) about
$0.076 of cache reads per delegation, so it only pays when the output is above roughly 4K
tokens. In short sessions, or for big outputs (a whole test suite, a long translation), it
still saves money, and middleman's break-even gate refuses the calls that would not.

## Choosing cheap models

Any OpenAI- or Anthropic-compatible provider works; adding one is a few lines of config. With
OpenRouter, one key gives you all the Chinese models:

| Model (OpenRouter ID) | $ / 1M in | $ / 1M out | Good for |
|---|---|---|---|
| `z-ai/glm-5.3-flash` | 0.04 | 0.078 | docstrings, summaries |
| `minimax/minimax-m3.1-flash` | 0.075 | 0.30 | boilerplate, translations |
| `qwen/qwen3.8-flash` | 0.15 | 0.47 | general coding |
| `deepseek/deepseek-v4.1-flash` | 0.30 | 1.20 | unit tests, boilerplate |
| `moonshotai/kimi-k3.1-pro` | 2.00 | 10.00 | harder jobs |
| *for comparison:* Claude Opus 5.5 | 4.00 | 20.00 | |

These are OpenRouter list prices on 2026-11-10. middleman always uses the live prices, and never uses
a model whose price it doesn't know.

`~/.config/middleman/config.toml`:

```toml
[providers.openrouter]
preset = "openrouter"
key_source = "keychain"                    # written by `middleman provider add`; OPENROUTER_API_KEY wins if set
model  = "qwen/qwen3.8-flash"

# Cheapest suitable model first, then DeepSeek, then give the job back to Claude.
[routes.write_tests]
chain = ["auto:code:cheapest", "openrouter/deepseek/deepseek-v4.1-flash", "claude"]

[routing]
mode = "auto"        # auto: Claude delegates when safe · confirm: ask first · explicit: only on "cheap:"
```

`confirm` and `explicit` guard against *accidental* delegation; they are advisory, not a security
boundary (the model sets `user_requested` itself). `confirm` is backed by a one-time token: the dry
run returns an `approval_id`, you approve it by running `middleman approve <id>` in your own terminal
(it asks you to type `yes`), and only then can the confirmed call send. Each token works once, for
that exact request, for 30 minutes.

> 💡 **Claude Haiku 5.5** ($0.10 / $0.50) costs about the same as these models and is first-party,
> so nothing needs redacting. Use it for anything sensitive that's still routine.

## Commands

| Command | What it does |
|---|---|
| `middleman usage` | Your Claude Code spend from local logs (totals only, never message text) |
| `middleman tune` | Recommended settings, with estimated savings |
| `middleman init` | Guided setup: scope, provider and key (checked live), routing mode (`--list`, `--yes`) |
| `middleman setup claude` | Connect to Claude Code (`--dry-run`, `--details`, `--undo`, `--scope project`, `--statusline combined`) |
| `middleman provider add/list/test/rotate/remove` | Manage provider keys in the OS keychain |
| `middleman provider refresh` | Fetch balances and key limits (free requests) for the status line |
| `middleman statusline` | The Claude Code status line (`--lines 2`, `--middleman-only`, `--columns`) |
| `middleman watch` | Live view of delegations in another terminal |
| `middleman report` | What was delegated, to which model, and the net saving (`--html` for a dashboard, `--reconcile` to check the cost against the provider's counters) |
| `middleman check <files>` | Dry run: shows exactly what *would* be sent, without sending it |
| `middleman route "<prompt>"` | Shows whether a prompt would be delegated, and why |
| `middleman doctor` | Health check: config, keys, keychain, providers, Claude Code wiring |
| `middleman dict suggest` | Find company, product and people names in this project (locally) and add the ones you pick to the private dictionary (`--yes`, `--min-confidence`, `--json`) |
| `middleman models refresh` | Fetch current models and prices from your providers |
| `middleman approve <id>` | Approve one `confirm`-mode delegation (run it yourself, in a terminal) |
| `middleman completions <shell>` | Shell completions for bash, zsh, fish, elvish, PowerShell |

<details>
<summary><b>Privacy details: what is and isn't hidden</b></summary>

| Risk | What middleman does | What remains |
|---|---|---|
| Secrets in code | Detects keys, tokens, passwords, PEM files, high-entropy strings, card/IBAN/ID numbers (also through zero-width characters, Unicode look-alike forms and `"AKIA" + "..."` splits), and **blocks** the request | Unusual secret formats; detection is best-effort |
| Who you are | Replaces your company/product/customer names (from your private list, matched case- and Unicode-insensitively), hosts, whole URLs (port and path too), emails, absolute paths and the requested files' names (sent as `src/f1.py`, restored in the answer); blocks names disguised with separators or Cyrillic/Greek look-alikes. Generic User-Agent, no tool headers | Names you didn't add to the list (`middleman dict suggest` helps) |
| Sensitive files | `.env`, keys, `secrets/`, `.git` (also the submodule / worktree `.git` file), `.gitmodules`, `.ssh` and friends are never read | Add your own folders to the deny list |
| Business logic | Size limits, task-type allow-list, per-provider sensitivity limits | **The code's logic itself can't be hidden.** Only delegate low-value code. |
| Bad answers | Treated as untrusted and scanned: new hosts/IPs, exec/eval/network calls or import-time side effects mark it high risk, and high-risk output is only staged as `.middleman.new`. Real names are never restored inside URLs or network/exec call arguments, and secret placeholders are never restored into files. Agent, editor, CI, git-hook and shell config files (`.claude/`, `.mcp.json`, `CLAUDE.md`, `.github/`, `.git/`, `conftest.py`, `.zshrc`, ...) can't be written, and symlinks are never followed. Never executed | Claude must review the diff before running anything |
| Account, IP, timing | Not hidden | Use a separate account or network if this matters |

Resellers and gateways count as untrusted, even when they serve a model called "Claude". Every provider
except first-party Anthropic gets the full treatment.

</details>

<details>
<summary><b>Usage log format</b></summary>

Every attempt, including blocked ones, is one JSON line in `~/.local/state/middleman/ledger.jsonl` (mode 0600):

```json
{"task_kind":"write_tests","provider":"openrouter","model":"deepseek/deepseek-v4.1-flash",
 "effective_sensitivity":"S1","status":"ok","closing":true,"redactions":{"dictionary":5,"email":1},
 "input_tokens":1240,"output_tokens":2050,"cost_usd":0.0028,"cost_source":"provider",
 "catalog_cost_usd":0.0029,"latency_ms":6100,"write_mode":"file","claude_model":"opus-5.5",
 "price_basis":"session","claude_output_tokens":2400,"call_tokens":150,"context_tokens":92000,
 "context_source":"session","result_tokens":610,"claude_equiv_usd":0.048,
 "claude_overhead_usd":0.0244,"net_savings_usd":0.0208,"validation":"passed"}
```

Escalation steps are separate lines (`status` `escalated` or `failed`, `closing: false`) sharing the
`request_id`; the closing line holds the outcome (`ok`, `blocked`, `do_it_yourself`, `error`,
`dry_run`) and the Claude-side terms. Lines written by older versions are read as before; their
savings figures are kept as they were recorded.

A separate audit log (`audit-YYYY-MM.jsonl`, same directory, 0600) keeps the cleaned text exactly as
it was sent, plus provider error bodies (with your key removed), so you can audit what left your
machine. Note that it **retains the sanitized payload**: protect or prune that directory accordingly.

</details>

<details>
<summary><b>Configuration reference</b></summary>

See [`config/middleman.example.toml`](config/middleman.example.toml) for every option.

- **Providers:** `preset` fills in the URL, key variable and trust level. Each provider's trust level
  (`untrusted`, `zdr`, `local`, `first_party`) caps how sensitive a job it can receive.
- **Keys** come from an environment variable, the OS keychain (`key_source = "keychain"`), a
  private file (`key_source = "file"`) or a `key_file`, in that order. They're never written into
  the config, logs, the usage log or output, and are wiped from memory after use.
- **Routes:** each task type has a chain of steps. A step is `auto:<code|chat>:<cheapest|balanced|best>`,
  `<provider>/<model>`, or `claude` (give the job back).
- **Budget:** per-call, daily and weekly caps, plus a minimum balance to keep. If the balance can't be
  read, the request is refused.
- **Per-project rules:** a `.middleman.toml` in a repo can only make the rules **stricter**.
- **File output:** existing files are staged (`.middleman.new` + `.middleman.patch`); a call's
  `overwrite: true` only takes effect with `[output] allow_overwrite = true` in your user config.
  `[paths] write_allow = ["tests/**"]` limits where file mode may write.

The prompt hook is added by `middleman setup claude`: a `UserPromptSubmit` command hook running
`middleman route --hook` (timeout 150 s). For ordinary prompts it's a local check (~20 ms) that
only adds advice for Claude; a `cheap:` prompt is run by the hook and never reaches Claude.

- **Private dictionary:** the only thing that hides names is your list. `middleman dict suggest`
  (also a step in `init`) proposes names from the root folder, the git remote, manifests,
  git authors, config hosts and recurring proper nouns, and adds the snake / kebab / spaced
  spellings, so `acme_billing` is replaced instead of blocking the request. `doctor` warns
  while the list is empty.
- **Project label:** the usage log stores a salted hash of the project folder, never its name.
  Put `label = "work-api"` in the project's `.middleman.toml` to see that name in
  `report --by project`.

</details>

## Roadmap

- [x] Safe delegation with reversible fake names
- [x] Any provider through config, live prices, fallback chains
- [x] Usage analysis, `tune` recommendations, savings reports
- [ ] Local proxy for live per-request logs and budget alerts
- [ ] Check that generated code compiles before accepting it
- [ ] Multi-step jobs (a whole sub-agent) on cheap models

## Contributing

Issues and PRs are welcome. Before opening a PR, run:

```sh
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked
```

Design notes are in [`PLAN.md`](PLAN.md).

## License

[MIT](LICENSE)
