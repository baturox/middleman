# middleman

A local, trusted stdio MCP server that lets Claude Code delegate small, self-contained tasks
(tests, docstrings, boilerplate, snippets, summaries) to cheap **untrusted** LLM providers after
sanitizing and pseudonymizing the input, and restoring identifiers in the answer.

> **Trust caveat.** Gateways such as yapayzekalab are untrusted resellers, even when they serve
> a model named "Claude". Every provider other than first-party Anthropic gets the full
> sanitization pipeline regardless of model name. Metadata (your account, IP, timing) is not
> hidden; use an unlinked account / egress if that matters.

## Does it actually save money?

Measured on this machine (30 days of Claude Code transcripts, `middleman usage --since 30d`):
≈ $5.2K API-equivalent, of which **output is only 19%**; cache reads 53% and cache writes 27%.
Third-party delegation can only replace output, so it is the *smallest* lever. Run
`middleman tune` first: capping context (~200K), Sonnet subagents and Sonnet for routine
sessions are worth hundreds of dollars a month; delegation is worth tens.

When you do delegate, it only pays if:

- **The result goes to disk, not back into Claude.** Code kinds default to `write_mode: "file"`:
  middleman writes the restored output to `output_path` (inside `paths.roots`, deny globs apply;
  an existing file is never overwritten unless `overwrite: true`, it is staged as
  `<path>.middleman.new` + `<path>.middleman.patch` instead) and returns only path, bytes,
  lines, sha256 and warnings. If Claude gets the text back and writes the file itself, it pays
  for all N output tokens again and the savings are gone. Verify by running tests/compiler.
- **The output is big enough.** Each delegation costs Claude a tool call (~200 output tokens),
  an extra turn that re-reads the session context as cache reads (60K × $0.20/1M ≈ $0.012 on
  Opus) and the tool result. Break-even on Opus 5.5 is ≈ 830 output tokens in file mode
  (≈ 1040 inline). `[economics] enforce_break_even = true` blocks smaller tasks with
  `do_it_yourself`, the hook only suggests delegation above break-even, and the tool
  description tells Claude so.

  net_savings = N·P_out − (call_tokens·P_out + context·P_cache_read + result_tokens·P_in) − cheap_cost

**Subscription vs API.** On a Claude Pro/Max subscription you don't pay per token: savings show
up as usage-limit headroom, not dollars. On API billing they are dollars. `middleman report`
shows both: Claude output tokens avoided and $ at API prices.

## Usage logs and reports

- **Ledger v2** (`~/.local/state/middleman/ledger.jsonl`, 0600): one line per delegation attempt
  (escalation steps share `request_id`, with `attempt`), blocked requests included (cost 0, with
  `block_reason_category`). Fields: `ts, request_id, attempt, project, task_kind, quality, mode,
  chain_step, provider, model, trust, effective_sensitivity, status
  (ok|blocked|error|escalated|do_it_yourself), block_reason_category, redactions, input_tokens,
  output_tokens, cost_usd, cost_source (balance|usage|estimate), latency_ms, write_mode,
  output_bytes, claude_model, claude_equiv_usd, claude_overhead_usd, net_savings_usd,
  validation`. Old v1 lines are still read.
- `middleman report [--since 7d|30d|all] [--by model|provider|task|day|project] [--json] [--html out.html]`
  — calls, ok%, escalation%, blocked, cheap spend, Claude-equivalent, overhead, **net savings**,
  tokens avoided, latency, top block reasons; `--html` writes a single-file dashboard (no JS,
  no external requests). `middleman_status` includes today's and 7-day net savings.
- `middleman usage [--since 30d] [--by model|day|project|session|agent] [--json] [--html out.html]`
  — all Claude Code traffic from local transcripts (`~/.claude/projects/**/*.jsonl`), deduped by
  message id, priced per model family (`[usage.prices]`), main vs subagent, cost buckets,
  context-size percentiles, top sessions, plus middleman's ledger. Aggregates only; message
  contents are never printed or stored.
- `middleman tune [--since 30d] [--json]` — quantified recommendations and the exact
  `settings.json` snippet (`CLAUDE_CODE_SUBAGENT_MODEL`, `ANTHROPIC_DEFAULT_HAIKU_MODEL`,
  `CLAUDE_CODE_AUTO_COMPACT_WINDOW` / `CLAUDE_AUTOCOMPACT_PCT_OVERRIDE`,
  `skillListingBudgetFraction`). Prints only; `--apply` merges it into `~/.claude/settings.json`
  with a backup — run that yourself.

## What happens on `delegate_task`

1. **intake** — middleman reads the files itself (configured roots only, symlinks resolved,
   built-in deny globs like `**/.env*`, `**/*.pem`, `**/secrets/**` always win, size caps,
   binary/non-UTF-8 rejected).
2. **detect** — provider keys, PEM, JWT, URL credentials, assignment heuristics, high entropy,
   email, phone, IBAN (mod-97), TCKN (checksum), cards (Luhn), URLs/hosts/IPs/home paths, and
   your private dictionary (case-insensitive, inside identifiers too).
3. **classify** — S0..S3 = max(declared, detected); complexity C0..C2.
4. **policy** — per-provider `max_sensitivity` / `task_kinds` / `max_complexity`; default deny.
   Hard secrets and PII block by default (S3 never leaves unless the provider is `local` /
   `first_party`).
5. **pseudonymize** — typed surrogates (`user3@example.com`, `svc2.example.net`,
   `198.51.100.n`, `/workspace/app/...`, case-preserving pseudo-words for dictionary terms).
   The vault lives in memory for one request.
6. **egress gate** — the only constructor of `Sanitized<OutboundRequest>`; re-scans the payload
   and asserts that no vault original and no API key is present. Providers accept nothing else.
7. **routing + budget** — the routing chain resolves to models from the live catalog
   (unknown price = ineligible); worst-case cost vs per-call/daily/weekly caps and the balance
   reserve; balance unreadable = refuse.
8. **provider** — `openai_compat` or `anthropic` wire format, non-streaming, hard timeout,
   no retries; escalation to the next chain step on error/timeout/empty/failed validation.
9. **response** — warn on unknown surrogates, new hosts, injection-like text, install commands;
   restore surrogates; in file mode write the (fence-stripped) result to disk and return a
   summary; in inline mode wrap it in `<untrusted_output>`.
10. **ledger + audit** — `~/.local/state/middleman/ledger.jsonl` and `audit-YYYY-MM.jsonl`
    (0600): the sanitized payload exactly as sent, SHA-256 of the original, counts, cost.

Anything uncertain before step 8 yields `status: "blocked"` and nothing is sent.

## Install

```sh
cargo build --release
middleman init            # interactive: scope (user|project), providers, routing mode
middleman models refresh  # fetch /models + prices from every enabled provider
middleman doctor          # green/red checklist
```

`middleman init --yes --scope user --providers yapayzekalab,openrouter --mode auto` is the
non-interactive form; `middleman init --list` shows presets and which key env vars exist
(values are never printed). `init` writes only middleman's own config; it **prints** the Claude
Code wiring and applies it only with `--apply`.

## Wiring into Claude Code

Register the MCP server (user scope, all projects):

```sh
claude mcp add middleman --scope user -- /path/to/middleman/target/release/middleman mcp --config ~/.config/middleman/config.toml
```

For one repository only, use `--scope project` (writes the repo's `.mcp.json`) and put a
tighten-only `.middleman.toml` in the repo.

Allow the tools (e.g. in `~/.claude/settings.json` → `permissions.allow`):
`mcp__middleman__delegate_task`, `mcp__middleman__middleman_status`.

Optional prompt hint hook (local, no network, always exits 0, ~20 ms). Merge into
`~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ { "type": "command", "timeout": 5,
        "command": "/path/to/middleman/target/release/middleman route --hook --config ~/.config/middleman/config.toml" } ] }
    ]
  }
}
```

Then paste the CLAUDE.md block from [`docs/CLAUDE-snippet.md`](docs/CLAUDE-snippet.md).

## Configuration

See [`config/middleman.example.toml`](config/middleman.example.toml). Highlights:

- **Providers are pure config.** `preset = "openrouter"` (or yapayzekalab, deepseek, moonshot/kimi,
  zhipu/glm, dashscope/qwen, groq, together, fireworks, mistral, gemini, xai, ollama, lmstudio,
  anthropic, custom) fills `api`, `base_url` (includes `/v1`), `key_env`, `trust`, `balance`.
  `trust` = `untrusted` (default max S1) | `zdr` (S2) | `local` / `first_party` (S3).
  Only the yapayzekalab base URL was live-verified; the others come from vendor docs and are
  marked unverified in `src/providers/presets.rs` — run `middleman doctor`.
- **Keys** come from `key_env`, else `key_file` + `key_var` (default: same name). Never inline.
- **Routing.** `[routes.<task_kind>] chain = ["auto:code:cheapest", "auto:code:balanced", "claude"]`.
  Steps: `auto:<tag>:<cheapest|balanced|best>`, `<provider>/<model id>`, `<provider>` (its
  `model`), `claude` (= `do_it_yourself`). `[routing] mode = "auto" | "confirm" | "explicit"`.
- **Model overrides** `[models."<provider>/<id>"] price_in, price_out, context, tags, enabled`.
  `:free` / `-free` models are excluded unless explicitly enabled (free upstreams often retain
  prompts).
- **Project overlay** `.middleman.toml` (nearest at or above the working directory) may only
  tighten: lower budgets/limits/`max_sensitivity`, add deny globs, disable providers, remove
  task kinds, stricter routing mode / redact modes. Loosening is a load error.

## CLI

| command | what |
|---|---|
| `middleman mcp` | MCP stdio server (stdout is JSON-RPC only; logs on stderr, `MIDDLEMAN_LOG=debug`) |
| `middleman check <files>` | offline dry run: exactly what would be sent, decision, plan |
| `middleman models [refresh] [--all]` | catalog with resolved prices/tags |
| `middleman balance` / `ledger` | provider balance; recent spend and window sums |
| `middleman probe [--model M] [--no-send]` | UA acceptance, both wire formats (2 × ~25 tokens), balance latency |
| `middleman route "<text>"` / `route --hook` | local prompt classifier / UserPromptSubmit hook |
| `middleman init` / `doctor` | setup and checklist |
| `middleman report` | delegation usage + savings (text / JSON / HTML) |
| `middleman usage` / `tune` | all Claude Code traffic from transcripts; first-party cost recommendations |

## Development

Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
Live smoke (synthetic fixture only, ≤ $0.01): `cargo test --test live_smoke -- --ignored --nocapture`.

## Probe findings (yapayzekalab, 2026-11-10)

- Both `/v1/chat/completions` and `/v1/messages` serve non-Claude models (tested with
  `gpt-5.6-luna`); the OpenAI format is configured.
- Non-browser and missing User-Agent are accepted (HTTP 200 on `/v1/models`).
- `/v1/balance` reflects a call immediately (6-decimal USD). Failed calls show a temporary
  $0.0001 hold that is refunded, so a balance delta read during a failure can over-count;
  successful calls reconcile exactly.
- The $0.01/1M "flash/hoshi" models timed out or returned 503; they are disabled in the user
  config. Cheapest reliable text model: `gpt-5.6-luna` ($0.25 / $0.25 per 1M).
