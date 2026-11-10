# PLAN: `middleman` — a Rust privacy-preserving delegation layer for Claude Code

_Plan authored by Fable 5.2 (2026-11-10)._

## 0. Decision and what it rests on

**Primary integration: Option B, a stdio MCP server**, built as one Rust binary that later also hosts an agentic runner (Option C) behind the same sanitization core. Option A (proxying the whole main session) is rejected.

| Option | Verdict | Reason |
|---|---|---|
| A: proxy the main session | Rejected | The proxy sees the full conversation. Routing any single request to a third party ships the whole context, and sanitizing a streaming, tool-using main session is the hardest version of the problem. |
| B: MCP `delegate_task` | **Primary (Phase 1-2)** | Data leaves only by an explicit, self-contained, size-bounded call. Default is "nothing leaves". Non-streaming, so reversible pseudonymization is simple and testable. |
| C: sandboxed `claude -p` runner | Phase 3 add-on | Needed for multi-step agentic work (what `dis_ajan.sh` does today). Reuses the Phase 1 core as an egress filter. |

Findings from the prior art (read-only; nothing was run against the live gateway):

- **yapayzekalab speaks both wire formats.** `dis_ajan.sh` uses Anthropic `/v1/messages` for Claude models; `metin_ajan.py` uses `/v1/chat/completions` for cheap models. Whether `/v1/messages` serves non-Claude models is unknown, so Phase 1 implements both (non-streaming) and a probe picks one. This also makes OpenRouter in Phase 2 mostly configuration.
- **Useful gateway endpoints** (from `kaynaklar.py`, `dis_ajan_dogrula.py`):
  - `GET /v1/balance` returns `balance_usd`, `balance_try`, `rate`, `payg_enabled`.
  - `GET /v1/models` returns `data[].pricing.input_per_1m_usd` / `output_per_1m_usd`, `tier`, `context_length`.
  - `POST /v1/messages/count_tokens` exists.
- **Auth:** `Authorization: Bearer` for the OpenAI-style endpoints; the Anthropic-style calls send both `x-api-key` and `Authorization: Bearer`.
- **User-Agent:** every existing script sets a browser-like one. The gateway may reject default client UAs; set an explicit generic UA and check it in the probe.
- **Existing budget policy to carry over** (`hibrit_motor.py`): $1 reserve, $1 daily cap, $4 weekly cap; real cost measured as balance before minus after; a step is skipped if the balance cannot be read.
- **Existing secret scan** (`metin_ajan.py` `gizli_tara`): returns labels only, never values; includes TCKN checksum and Luhn card checks. Port both.

**Trust caveat to put in the README:** yapayzekalab is itself an untrusted reseller, even when it serves a "Claude" model. Every provider other than first-party Anthropic gets the full sanitization pipeline, regardless of model name.

## 1. Architecture

```
 Claude Code (main agent, real Claude, sees everything)
        |  MCP stdio: tools/call delegate_task{task_kind, instructions, files[], inputs[], declared_sensitivity}
        v
+---------------------------- middleman (local, trusted) ----------------------------+
| 1 intake      read files itself (path allow/deny globs, line ranges, size caps)     |
| 2 detect      on raw + NFKC/invisible-stripped/case-folded views (spans mapped back):|
|               secrets (regex+entropy+checksums), PII, hosts/URLs/IPs/paths, dict;  |
|               dict also on a separator/look-alike skeleton => hit there = BLOCK    |
| 3 classify    sensitivity S0..S3 = max(declared, detected); complexity C0..C2       |
| 4 policy      (task_kind, S, C) -> Allow{provider,model} | Block{reason}            |
| 5 pseudonymize originals -> typed surrogates; Vault lives in memory per request     |
| 6 egress gate independent 2nd check: re-run detectors; normalize final payload and  |
|               search every dict term + every vault original; any hit => BLOCK      |
| 7 budget      estimate worst-case cost; per-call/daily/weekly caps; balance reserve |
| 8 provider    anthropic | openai_compat, non-streaming, hard timeout                |
| 9 response    risk scan (new hosts/IPs, exec/network, import-time calls) -> restore  |
|               (never inside URLs/sink args; no MM_SECRET in files); risky => stage |
| 10 ledger + audit (JSONL, 0600): the sanitized payload exactly as sent, cost, why   |
+--------------------------------------------------------------------------------------+
        |  HTTPS: sanitized text only                      ^ untrusted text
        v                                                  |
  yapayzekalab / OpenRouter / ... (untrusted) -------------+

 Any error or uncertainty at steps 1-7 => status:"blocked", nothing is sent,
 main agent is told to do the task itself.
```

Two design rules carry the security:

1. **Type-enforced egress.** `Provider::send` accepts only `Sanitized<OutboundRequest>`, whose constructor is private to the `egress` module. No code path can reach the network with raw text. The gate is a second, independent check on the normalized final payload (not a replay of the pseudonymizer's own findings).

Detection is best-effort: neither pass can find a secret format or a spelling of a name it does not describe. The private dictionary, the deny-listed paths and "only delegate low-value code" remain essential.
2. **Middleman reads the files, not Claude.** The main agent passes paths and line ranges. This saves Claude output tokens and makes path policy enforceable.

## 2. Crate layout

Single package (lib + bin).

```
Cargo.toml  rust-toolchain.toml  README.md  PLAN.md  .gitignore
config/middleman.example.toml      config/dictionary.example.txt
src/main.rs            clap CLI: mcp | check | models | balance | ledger | probe | (later) agent | proxy
src/lib.rs
src/config.rs          TOML -> typed Config; validates; resolves key from env or key_file+var
src/intake.rs          file loading, globset allow/deny, line ranges, size caps, binary rejection
src/detect/mod.rs      Finding{category, span, severity}; never carries the value in Debug/Display
src/detect/secrets.rs  provider-key regexes, PEM blocks, JWT, URL credentials, assignment heuristics
src/detect/entropy.rs  Shannon entropy over base64/hex-like tokens of 20+ chars
src/detect/pii.rs      email, phone, IBAN, TCKN (checksum), cards (Luhn)
src/detect/infra.rs    URLs, hostnames, IPv4/6, absolute paths, usernames in paths
src/detect/dictionary.rs  aho-corasick over the private term list, case-insensitive
src/pseudo.rs          Vault (bidirectional map), surrogate generators, apply(), restore()
src/classify.rs        rule-based Sensitivity + Complexity; trait Classifier for later LLM classifier
src/policy.rs          Decision engine from config rules; default deny
src/egress.rs          Sanitized<T>, final re-scan, the only constructor
src/providers/mod.rs   trait Provider { complete, balance, models }; registry
src/providers/anthropic.rs      /v1/messages
src/providers/openai_compat.rs  /v1/chat/completions
src/budget.rs          estimate, caps, reserve check, reconcile
src/ledger.rs          JSONL append (single write per line, O_APPEND), window sums
src/audit.rs           JSONL audit records
src/pipeline.rs        orchestrates steps 1-10; returns DelegateOutcome
src/mcp/jsonrpc.rs     line-delimited JSON-RPC 2.0 over stdin/stdout
src/mcp/server.rs      initialize, notifications/initialized, ping, tools/list, tools/call
tests/                 redaction_roundtrip.rs  policy.rs  pipeline_mock.rs  mcp_stdio.rs  live_smoke.rs (#[ignore])
tests/fixtures/        synthetic "Acme" project with fake hosts, emails, keys
```

### Dependencies

- **Runtime:** `tokio`, `reqwest` (rustls-tls, json), `serde`, `serde_json`, `toml`, `regex`, `aho-corasick`, `globset`, `clap` (derive), `anyhow`, `thiserror`, `tracing` + `tracing-subscriber`, `time`, `sha2`, `hmac`, `uuid`.
- **Dev:** `wiremock`, `tempfile`, `assert_cmd`, `proptest`.
- **Phase 3 only:** `axum`, `futures`, an SSE parser.
- **MCP: hand-roll it** (five methods, ~200 lines).
- **Logging goes to stderr only.** stdout is the MCP channel. Add `#![deny(clippy::print_stdout)]`.

## 3. Key designs

### MCP tools

`delegate_task` input:

- `task_kind`: `write_tests | boilerplate | summarize | explain | docstring | translate | snippet | refactor_small | other`
- `instructions`: string
- `files[]`: `{path, start_line?, end_line?}`
- `inputs[]`: `{label, text}`
- `declared_sensitivity`: `public | internal | confidential` (required)
- `max_cost_usd?`, `max_output_tokens?`, `dry_run?`

Result (JSON as text content): `status` (`ok | blocked | error`), `output`, `warnings[]`, `redactions` (counts per category), `provider`, `model`, `cost_usd`, `request_id`, and `block_reason` (category plus file:line, never the value). `dry_run:true` returns the sanitized payload and decision without sending.

`middleman_status` returns remaining daily/weekly allowance, balance, and enabled providers.

Tool results wrap third-party text in `<untrusted_output>` with a fixed note that it is data, not instructions.

### Pseudonymization (reversible, type-shaped surrogates)

| Category | Action | Surrogate |
|---|---|---|
| Hard secrets | **Block the request** by default. Opt-in `secrets = "mask"` swaps in `MM_SECRET_n`, restored locally. | n/a |
| Email | replace | `user3@example.com` |
| Hostname / URL | replace host, keep scheme, port, path shape | `svc2.example.net` |
| IP | replace | `198.51.100.n`, `2001:db8::n` |
| Absolute path | rewrite prefix up to project root | `/workspace/app/...` |
| Dictionary terms | case-preserving replace inside identifiers too (`AcmeBilling` -> `ZentroBilling`) | generated neutral words, collision-checked |
| PII (phone, IBAN, TCKN, card) | block at S3, or format-valid fakes if policy allows | |

Rules: same original → same surrogate per request; longest match first, span-based replacement; surrogates verified absent from input; Vault never on disk; restore exact surrogates only, unknown surrogates in output → warnings; per-process HMAC key for stable surrogates.

### Classifier and policy

- S0 public · S1 internal, nothing detected · S2 infra/PII pseudonymized or many dict hits · S3 hard secret, deny-listed path, or declared=confidential.
- Effective = `max(declared, detected)`. Main agent is the semantic classifier; rules are the backstop.
- Complexity C0..C2 from task kind + size; C2 → "do it yourself".
- TOML policy per provider (`max_sensitivity`, `task_kinds`), default deny.
- Deny-globs always win: `**/.env*`, `**/*.pem`, `**/*.key`, `**/*credential*`, `**/secrets/**`, `**/.git/**`, `**/.ssh/**`, `**/*.tfstate`, `**/id_rsa*`. Only configured roots readable. Symlinks resolved before matching.

### Budget and ledger

- Pre-flight worst case = `est_in*price_in + max_output_tokens*price_out`; refuse over per-call cap, daily/weekly remaining, or `balance - worst < reserve`.
- Balance unreadable → refuse.
- Ledger `~/.local/state/middleman/ledger.jsonl`; audit `audit-YYYY-MM.jsonl` (0600) with sanitized payload as sent, SHA-256 of original, finding counts, decision, cost.

### Config sketch (`~/.config/middleman/config.toml`)

```toml
[limits]   max_input_chars = 24000  max_files = 6  max_output_tokens = 2000  request_timeout_s = 120
[budget]   per_call_usd = 0.05  daily_usd = 1.0  weekly_usd = 4.0  reserve_usd = 1.0
[paths]    roots = ["/abs/project"]  deny = ["**/.env*", "**/*.pem", "..."]
[redact]   secrets = "block"  dictionary_file = "~/.config/middleman/dictionary.txt"
[providers.yzlab]
api = "openai"            # or "anthropic"; decided by `middleman probe`
base_url = "https://yapayzekalab.org"
key_env = "YZLAB_KEY"  key_file = "/path/to/.env.yzlab"
model = "<cheapest text model id from `middleman models`>"
max_sensitivity = "S1"  task_kinds = ["write_tests","boilerplate","summarize","docstring","snippet"]
```

Key wrapped in a `Secret` newtype; never in logs, errors, audit, or `.mcp.json`.

## 4. Threat model

| Leak vector | Mitigation | Residual |
|---|---|---|
| Secrets in snippet | Regex + entropy + checksums; block; deny-globs; egress re-scan | Novel low-entropy formats |
| Company identity via names, domains, paths, emails | Dictionary + infra pseudonymization; neutral system prompt | Terms missing from dictionary |
| Code semantics / business logic | Cannot be hidden; size caps, task-kind allow-list, S-level policy, deny-globs for core dirs | Accepted for low-value code |
| Unique literals / license headers | Strip headers, flag long literals, optional strip_comments | Partial |
| Metadata (account, IP, timing) | Document; use unlinked account/egress for anonymity | User decision |
| Malicious response | `<untrusted_output_NONCE>` wrapper (per-request random tag, tag text neutralized); provider error bodies and model ids never shown outside it; risk scan stages risky output as `.middleman.new`; no restore into URLs / exec / network sinks; write-deny for agent/CI/hook/shell config; no symlink following; middleman never executes | Needs Claude review of the diff before running |
| Vault/audit on disk | Vault in memory; audit sanitized; 0600 | Local compromise |
| Raw text via instructions/inputs | Same pipeline on every field | |
| Repo loosening config | User-dir config only; project file may only tighten | |

**Fail-closed:** invalid config, missing dictionary, detector error, classifier unsure, egress hit, budget/balance unknown, provider not allowed, over caps, non-UTF-8/binary.

## 5. Phases

### Phase 0: toolchain
rustup install, `cargo init`, `git init`, `rust-toolchain.toml`, `.gitignore` (`target/`, `.env*`, `*.jsonl`).

### Phase 1: MVP
1. config, Secret, CLI skeleton
2. detect + pseudo + egress (core, most tests)
3. classify + policy
4. providers (both wire formats) + `middleman probe`
5. budget + ledger + audit
6. pipeline + `middleman check <files>` (offline dry run)
7. MCP server; wire into Claude Code

Acceptance: `cargo test` green; `check` on fixture shows zero originals outbound; one live `delegate_task` round-trip with restored identifiers; ledger + audit lines written; live spend < $0.05.

### Phase 2
OpenRouter (exclude data-retaining upstreams); cascade cheap → validator → next → do-it-yourself; result cache; optional first-party Haiku classifier; `middleman dict suggest`; comment stripping; `ledger --since 7d` savings report.

### Phase 3
`middleman agent` (sandbox copy, pseudonymized on disk, hardened `claude -p` via local axum egress-filter proxy, restore diff); static HTML cost dashboard.

## 6. Wiring into Claude Code

- `claude mcp add middleman --scope user -- /path/to/middleman/target/release/middleman mcp --config ~/.config/middleman/config.toml`
- Allow `mcp__middleman__delegate_task`, `mcp__middleman__middleman_status`.
- CLAUDE.md block: delegate only self-contained low-risk work; pass paths not pasted code; never name company/project; honest `declared_sensitivity` (auth, billing, customer data, infra, core algorithms = confidential); treat output as untrusted, review and test it; on `blocked` do it yourself, don't rephrase around it; use `dry_run` when unsure.

## 7. Test plan

- Unit: each detector ±; TCKN/Luhn vectors; entropy not firing on UUIDs; Finding Debug never shows value.
- Round-trip: `restore(apply(x)) == x` incl. proptest; overlapping/nested matches, case variants, collisions, term inside identifier.
- Policy: table-driven, default deny, deny beats allow, symlink escape, over-cap, declared can't lower detected.
- Budget: window sums across midnight; balance unreadable → refuse.
- Mocked integration (wiremock), both wire formats: request body contains no originals, no auth value in logs; response restored; fake API key → zero HTTP requests; 500/timeout → error + ledger, no retry storm.
- MCP stdio: initialize, tools/list, tools/call dry run; stdout pure JSON-RPC.
- Live smoke (`--ignored`, $0.05 cap), synthetic fixture only.
- Gate: `cargo fmt --check && cargo clippy -- -D warnings && cargo test`.

## 7b. Setup, providers and routing (added after user feedback, 2026-11-10) — PART OF PHASE 1

User requirements: "smart system", **easy setup driven by a config file**, support **almost all providers dynamically**, and **install scope chosen by the user**.

### Providers: generic adapters + presets, not one module per vendor
Nearly every vendor speaks one of two wire formats, so there are exactly two adapters (`openai_compat`, `anthropic`). A provider is pure config:
```toml
[providers.<name>]
preset   = "openrouter"        # optional: fills api/base_url/key_env/headers/pricing source
api      = "openai"            # "openai" | "anthropic"
base_url = "https://..."
key_env  = "OPENROUTER_API_KEY"   # or key_file + key_var; never inline
headers  = { "X-Title" = "middleman" }   # optional extra headers
trust    = "untrusted"         # "untrusted" | "zdr" (contractual zero-retention) | "local" (ollama/lmstudio) | "first_party"
max_sensitivity = "S1"         # default by trust: untrusted=S1, zdr=S2, local=S3, first_party=S3
enabled  = true
```
Built-in preset table (`src/providers/presets.rs`, data only): openrouter, yapayzekalab, deepseek, moonshot/kimi, zhipu/glm, dashscope/qwen, groq, together, fireworks, mistral, gemini (OpenAI-compat endpoint), xai, ollama, lmstudio, anthropic (first_party), plus `custom`. Verify each base URL from the vendor's docs before shipping it in the preset; mark unverified ones with a comment. Adding a new vendor = 4 lines of TOML, no code.

### Model catalog: discovered, not hardcoded
- `middleman models refresh` calls each enabled provider's `GET /v1/models`; caches to `~/.cache/middleman/models.json` with TTL (24h).
- Pricing: use the provider's own pricing fields when present (OpenRouter `pricing.prompt/completion`, yapayzekalab `pricing.input_per_1m_usd`), else a bundled `prices.toml`, else a user override `[models."<provider>/<id>"] price_in/price_out/context/tags`. **Unknown price ⇒ model not eligible** (fail-closed on budget).
- Models get capability tags (`code`, `chat`, `reasoning`, `long_context`) from config/heuristics on id; user can override.

### Routing: middleman picks the model, Claude only hints
```toml
[routing]
mode = "auto"            # "auto" | "confirm" (dry_run first + one-time approval_id the user approves with `middleman approve <id>`) | "explicit" (only on "cheap:" prefix or /delegate; advisory)
default_quality = "cheap"

[routes.write_tests]  chain = ["auto:code:cheapest", "auto:code:balanced", "claude"]
[routes.summarize]    chain = ["auto:chat:cheapest", "claude"]
[routes.boilerplate]  chain = ["openrouter/deepseek/deepseek-chat", "claude"]   # explicit pins allowed
```
- `auto:<tag>:<cheapest|balanced|best>` resolves at call time from the catalog, filtered by: provider enabled, provider `max_sensitivity` ≥ effective S, model context ≥ needed, price known, budget allows.
- Escalate to the next chain step on: provider error/timeout, empty output, or failed cheap validation (Phase 1: non-empty + for code kinds output contains a code block; Phase 2: compile/test check).
- `"claude"` terminal step = return `status:"blocked", reason:"do_it_yourself"`.
- Tool input gets optional `quality` hint; result reports which chain step answered and the estimated "would have cost on Claude" for savings.

### Prompt understanding: UserPromptSubmit hook
- `middleman route --hook` reads Claude Code's UserPromptSubmit hook JSON from stdin, runs a **local, no-network** classifier (task-kind keywords EN+TR, sensitive-topic keywords: auth, login, password, billing, payment, customer, PII, infra, deploy, secret, prod…, dictionary hits, size), and prints hook JSON with `additionalContext` such as: "middleman: this looks delegable (kind=write_tests, est. S1). Use mcp__middleman__delegate_task." or "middleman: sensitive topic (billing) — keep on Claude." In `explicit` mode it only fires on the `cheap:` prefix. Must never block the prompt and must exit 0 fast (<50ms) even on error.
- `middleman route "<text>"` (no --hook) prints the human-readable decision for debugging.

### Easy setup: `middleman init` / `doctor`
- `middleman init` (interactive; `--yes` + flags for non-interactive): choose providers from presets (detect which key env vars already exist, never print values); choose **scope: user (all projects) or project (this repo's .mcp.json + .middleman.toml)**; choose routing mode; seed the private dictionary (offer `dict suggest` candidates); write config; then **print** the exact `claude mcp add ...` command and the hook JSON snippet, and only apply them to Claude Code settings if the user passes `--apply` (user runs that themselves).
- Project `.middleman.toml` may only tighten (lower max_sensitivity, add deny globs, disable providers, lower budgets) — enforced by a merge function with tests.
- `middleman doctor`: config valid, each provider reachable + key present, balance readable where supported, catalog fresh, MCP binary path correct, hook installed — green/red checklist.

## 7c. Does it actually save money? Economics + usage logs (added 2026-11-10)

### The cost model (what a delegation really costs)
Without delegation, Claude (main model, e.g. Opus 5.5 at $4 in / $20 out / $0.20 cache-read per 1M) writes N output tokens itself: **cost ≈ N × $20/1M**.

With delegation, Claude still pays:
1. the tool call it emits (~100-200 output tokens: paths + instructions),
2. **one extra turn**: Claude Code re-reads the whole session context as cache reads (50K ctx × $0.20/1M ≈ $0.01 per extra turn!),
3. the tool result as fresh input tokens,
4. **if the result comes back as text and Claude then writes it into a file, it re-emits all N tokens as output — savings ≈ 0 or negative.**
Plus the cheap model cost (tiny, e.g. gpt-5.6-luna $0.25/1M).

**Consequences (must implement):**
- **Write results to disk, not back into Claude's context.** `delegate_task` gets `output_path` (or `write_mode: "file" | "inline"`, default `file` for code kinds). The middleman writes the restored output to the target path (must be inside `paths.roots`, not deny-listed, refuse overwriting unless `overwrite: true` *and* the user config sets `[output] allow_overwrite = true`; for edits, and for any high-risk output, write a staged `<path>.middleman.new` + `<path>.middleman.patch`) and returns only a short summary: path, bytes, lines, sha, risk, warnings. Claude reviews the diff before executing anything and runs tests only after reading flagged lines. This is what turns $20/1M output into near-zero.
- **Break-even gate.** Delegation only pays when expected output N is large enough: net_savings = N·P_out_claude − (call_tokens·P_out_claude + ctx_tokens·P_cache_read + result_tokens·P_in_claude) − cheap_cost. Config `[economics] min_expected_output_tokens` (default ~800) and `assumed_context_tokens` (default 60000). The hook and the tool description only suggest delegation for tasks expected to produce lots of output (test suites, boilerplate, docs, translations, fixtures), never for one-liners.
- **Main-model price table** in config, default = Opus 5.5 ($4 / $20 / cache-read $0.20); presets for sonnet-5.5 ($2/$10/$0.10), fable-5.2 ($8/$40/$0.20), haiku-5.5 ($0.10/$0.50). Replace the stale $3/$15 default.
- **Subscription caveat (README):** on a Claude Pro/Max subscription you don't pay per token; savings show up as **usage-limit headroom**, not dollars. On API billing they are dollars. The report must show both "tokens of Claude output avoided" and "$ at API prices".

### Usage logs (ledger v2)
One JSONL line per delegation attempt (escalation steps are separate lines sharing `request_id`, with `attempt` index). Fields:
`ts, request_id, attempt, project (root name, hashed or label), task_kind, quality, mode, chain_step, provider, model, trust, effective_sensitivity, status (ok|blocked|error|escalated|do_it_yourself), block_reason_category, redactions{category:count}, input_tokens, output_tokens, cost_usd, cost_source (balance|usage|estimate), latency_ms, write_mode, output_bytes, claude_model, claude_equiv_usd (N×P_out), claude_overhead_usd (estimated per formula), net_savings_usd, validation (passed|failed|skipped)`.
Blocked requests are logged too (cost 0) so you can see what the middleman refused and why.

### Reports
- `middleman report [--since 7d|30d|all] [--by model|provider|task|day|project] [--json]`: table with calls, ok%, escalation %, blocked count, cheap spend, Claude-equivalent, overhead, **net savings**, avg latency, top block reasons.
- `middleman report --html out.html`: static single-file dashboard (no external deps) — spend vs saved over time, by model, by task kind.
- `middleman_status` MCP tool includes today's/this week's net savings so Claude (and you) can see it in-session.
- Optional: Claude Code **PostToolUse hook** on `mcp__middleman__delegate_task` that appends the result summary to the ledger (correlates with the session id), so the log also shows which Claude session triggered it.

## 7d. Re-prioritisation from measured usage (2026-11-10)

Measured from ~/.claude/projects transcripts (30 days, ~198 sessions, API-equivalent ≈ $6.2K): **output 18%, cache reads 54%, cache writes 28%**. Sessions start at ~81K tokens; median turn 247K, p90 640K; 83% of context tokens come from turns above 200K. Opus main ≈ $4.0K, Opus subagents ≈ $1.2K. ⇒ Third-party delegation (which only replaces output) is the *smallest* lever (~$100-150/mo at best). The big levers are first-party and leak-free:

| Lever | Est. saving / 30d | Risk |
|---|---|---|
| Cap context ~200K (`CLAUDE_CODE_AUTO_COMPACT_WINDOW` / `CLAUDE_AUTOCOMPACT_PCT_OVERRIDE`, /clear between tasks) — keeps 56% of context tokens | ~$1.0-1.4K | compaction loses detail |
| Subagents → Sonnet 5.5 (`CLAUDE_CODE_SUBAGENT_MODEL`, frontmatter for Explore/Plan-like custom agents) | ~$0.6K (Haiku 5.5: ~$1.1K) | quality on hard subtasks |
| Routine sessions on Sonnet 5.5 instead of Opus | ~$0.6K+ | quality |
| Trim 81K baseline by ~30K (disable unused plugins/skills per project, `skillListingBudgetFraction`, MCP tool search) | ~$0.35-0.45K | none |
| Third-party delegation (file mode) | ~$0.1-0.15K | data exposure |

### New modules (priority over Phase 2/3)
- **`middleman usage`** (Rust port of the analyzer): parse `~/.claude/projects/**/*.jsonl` locally; dedupe by message id; price by model family (configurable table); report by day / project / session / model / main-vs-subagent; cost buckets (input/output/cache-read/cache-write); context-size distribution; top 10 most expensive sessions with their peak context; merges middleman's own ledger so delegations show up next to Claude traffic. `--html` dashboard, `--json`. This is the "good usage logs" for *all* traffic, needs no proxy.
- **`middleman tune`**: reads the usage profile and prints concrete, quantified recommendations + the exact settings.json `env` snippet (subagent model, haiku/background model, auto-compact window, skill budget, per-project plugin disables). Prints only; applies with `--apply` (user runs it). Re-run after a week to measure the effect (before/after comparison from `usage`).
- **Later — `middleman proxy`** (ANTHROPIC_BASE_URL, local): passthrough to Anthropic that must forward OAuth + `anthropic-beta` unchanged (works with subscription login); live per-request logging, context-size alarms, budget caps; never mutates main-thread requests (caching/thinking integrity). Optional: route *subagent* conversations to cheap providers with redaction (Phase 3).

## 8. Open items (resolve in probe)
1. Which wire format serves cheap models on yapayzekalab; cheapest model id.
2. Whether non-browser UA accepted.
3. Whether `/v1/balance` updates fast enough for per-call reconciliation.

Reference prior art (read-only): youtube-batu/06-araclar/{dis_ajan.sh, kaynaklar.py, hibrit_motor.py, metin_ajan.py, dis_ajan_dogrula.py}
