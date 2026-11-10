# Leak validation

Date: 2026-11-10. Code: `main` at `853e21b`. Tests: `tests/leak_validation.rs`.

Question: does middleman leak company data or source code to the untrusted provider?

Short answer:

- **Names, hosts, emails, IPs, home paths and secrets did not leave** in any test, for any task
  kind, in either wire format, as long as the names are in the dictionary.
- **Source code does leave. That is the product.** Only the requested lines are sent, but those
  lines go out with their identifiers, comments and string literals intact.
- **Four real leaks were found**, all of metadata around the code (paths, URL paths, git
  submodule files). None exposes a dictionary name or a secret. **All four are fixed**, as are
  the User-Agent, cache-permission and ledger-project risks (see "Fixed since" below).
- The audit log of today's real runs is clean.

## How it was tested

No live provider calls. Every request went to a local wiremock server, and every URL, header
and body byte it received was checked.

A canary project is built in a temp dir. Its root is `<tmp>/zephyrine-corp/quasarledger`. It
contains:

- real source of this repo (`src/pipeline.rs`, `src/config.rs`, `src/egress.rs`);
- a synthetic Rust file dense with canaries: company `Zephyrine`, product `QuasarLedger`,
  user `mkaraca`, 4 internal hosts, 2 emails, 3 private IPv4, 1 IPv6, 2 home paths;
- a README, a config file, `.git/config`, `.git/HEAD`, `.gitmodules`, a submodule pointer,
  a neighbour file, and symlinks that point outside the root and onto `.git/config`.

The dictionary holds four terms: `Zephyrine`, `QuasarLedger`, `mkaraca`, `Karaca`.

A request is checked two ways. Literal canaries (hosts, IPs, emails, paths, marker strings of
files that were never requested) must not appear. Name canaries are compared on a skeleton
(case folded including Turkish `İ`/`ı`, all separators removed), which catches `ZEPHYRİNE`,
`zEpHyRiNe`, `quasar_ledger`, `Quasar Ledger`, `QUASAR-LEDGER` and names inside identifiers.

Run it:

```
cargo test --test leak_validation                 # 32 pass, including every fixed_* test
MM_LEAK_AUDIT_LOG=~/.local/state/middleman/audit-2026-11.jsonl \
MM_LEAK_AUDIT_NEEDLES=name,repo,host cargo test --test leak_validation real_audit -- --nocapture
```

## Results

PASS = holds, with a test. LEAK = something identifying is sent that should not be.
RISK = by design or low impact; you should know about it.

| # | Check | Result | Evidence (test) |
|---|-------|--------|-----------------|
| 1 | No canary in any request: 9 task kinds x 2 wire formats, including model-list and balance calls | PASS | `canary_never_leaves_for_any_task_kind_in_both_wire_formats`: 18 completion calls, 0 hits; 39 dictionary, 4 email, 4 host, 4 IPv4, 1 IPv6, 3 path replacements per request |
| 1 | Case variants, Turkish casing, names inside camel/snake identifiers | PASS | same test; each variant gets a surrogate |
| 1 | Split forms (`quasar_ledger`, `Quasar Ledger`, `Z e p h y r i n e`) | PASS | `split_and_spaced_forms_block_with_zero_requests`: refused, 0 requests |
| 1 | Names that are not in the dictionary | RISK | `control_names_missing_from_the_dictionary_are_sent_verbatim`: `ZephyrineClient`, `QuasarLedger`, `mkaraca` go out. The dictionary is the only protection for names |
| 1 | System prompt and envelope say nothing about machine, user, cwd, root, git remote, git user | PASS | `nothing_about_the_machine_user_cwd_or_git_remote_is_sent`; root becomes `/workspace/app` |
| 1 | Project root at the end of a sentence (`... is at <root>.`) | FIXED | `fixed_project_root_before_a_full_stop_is_replaced` (was: the full absolute path was sent) |
| 1 | Only requested files and line ranges are sent | PASS | `only_requested_files_and_line_ranges_are_sent`: slice is byte-exact; README, config, neighbour file, `.git`, `include_str!` target absent |
| 1 | Company name in a relative path (`zephyrine/billing.rs`) | PASS | `company_name_in_a_relative_path_is_pseudonymized` |
| 1 | Absolute path with the company name above the root | PASS | `absolute_path_is_sent_root_relative`: header is `src/f1.rs` |
| 1 | Directory and file names that are not dictionary terms | FIXED | `fixed_path_components_are_pseudonymized`, `fixed_paths_and_urls_are_restored_in_output`: sent as `d1/f1.rs` (conventional top dir and extension kept), restored in the answer (was: `internal-fraud-engine/risk_scoring_v3.rs` sent as is) |
| 1 | Absolute paths outside the roots | FIXED | `fixed_absolute_paths_outside_roots_are_replaced_whole`: the whole path, not only `/Users/<name>` |
| 2 | Fraction sent for a line range | PASS | `line_range_minimization_is_measured`: lines 57-128 of `src/pipeline.rs` = 2 434 of 53 821 bytes (4.5 %), plus a 105-byte envelope |
| 2 | `max_files` (6) and `max_input_chars` (24 000) | PASS | `max_files_and_max_input_chars_hold`, `lowered_max_input_chars_is_enforced_on_the_whole_payload`: whole `pipeline.rs` / `config.rs` refused, nothing truncated or partly sent |
| 2 | Symlink out of root, directory symlink, `..`, absolute outside path, symlink onto `.git/config`, `.git/*` | PASS | `symlinks_parent_paths_and_dot_git_cannot_be_pulled_in`: all refused; one bad file blocks the whole request |
| 2 | `mod` / `include_str!` targets | PASS | never followed; middleman reads only named files |
| 2 | `.gitmodules` and a submodule's `.git` pointer file | FIXED | `fixed_gitmodules_and_submodule_pointer_are_denied`: `**/.gitmodules`, `**/.git` on the read and write deny list |
| 3 | Headers | PASS | `default_headers_are_transport_and_auth_only`: only `host, accept, user-agent, content-type, content-length, authorization` (+ `x-api-key, anthropic-version`). No X-Title, no Referer, no cookies, no query string |
| 3 | `X-Title` | PASS | `x_title_is_sent_only_when_configured`: not in code or the example config; sent only if you configure it |
| 3 | User-Agent | FIXED | `fixed_default_user_agent_does_not_name_the_tool`: `Mozilla/5.0` |
| 3 | Fingerprint | RISK | `risk_request_shape_is_a_stable_fingerprint`: constant system prompt, envelope, JSON keys; same term gives the same surrogate for the life of one process |
| 4 | Today's real audit log | PASS | 13 records, 5 sent, 0 hits (details below) |
| 5 | Restored output delegated again (inline) | PASS | `restored_output_is_resanitized_when_delegated_again`: 2nd request has 0 canaries, 38+ fresh replacements |
| 5 | Restored output delegated again (file mode) | PASS | `file_mode_output_is_resanitized_when_sent_again` |
| 5 | Hostile answer puts a surrogate in a URL | PASS | `restore_never_fills_originals_into_urls_from_a_hostile_answer`: not restored, flagged high risk |
| 5 | Dry-run preview equals what is sent | PASS | `dry_run_preview_equals_what_is_sent` |
| 6 | State dir 0700, ledger and audit 0600, no originals | PASS | `state_files_are_private_and_hold_no_originals` |
| 6 | Ledger `project` | FIXED | same test: a salted hash `p-xxxxxxxx`; `report --by project` shows the overlay `label` when set |
| 6 | Report (text, HTML), watch, status line, `middleman_status` | PASS | `report_watch_statusline_and_status_show_no_originals` |
| 6 | Audit `block_reason` repeats a refused path | RISK (local) | `audit_block_reason_repeats_the_requested_path_locally` |
| 6 | Model catalog cache permissions | FIXED | `fixed_catalog_cache_is_private`: 0700 / 0600 |
| 7 | URL port, path, repo path, database name | FIXED | `fixed_url_path_port_and_database_name_are_replaced`: everything after `scheme://` becomes `svcN.example.net/pM`; restored when echoed after `scheme://` |
| 7 | Identifiers, comments, literals, structure | RISK (by design) | `risk_identifiers_comments_and_structure_are_sent_verbatim` |

## Fixed since

Each former `LEAK` / open-`RISK` test is gone; its `fixed_*` twin runs in the normal suite.

| Item | Test |
|------|------|
| Root followed by `.` | `fixed_project_root_before_a_full_stop_is_replaced` |
| Path components in `--- FILE` and mentions | `fixed_path_components_are_pseudonymized`, `fixed_paths_and_urls_are_restored_in_output` |
| `.gitmodules`, submodule `.git` file | `fixed_gitmodules_and_submodule_pointer_are_denied` |
| URL path / port / user / db name | `fixed_url_path_port_and_database_name_are_replaced` |
| Absolute paths outside roots | `fixed_absolute_paths_outside_roots_are_replaced_whole` |
| User-Agent names the tool; `X-Title` in the example config | `fixed_default_user_agent_does_not_name_the_tool` |
| Cache permissions | `fixed_catalog_cache_is_private` |
| Ledger `project` | `state_files_are_private_and_hold_no_originals` |

Still open: scp-style git URLs (`git@host:org/repo.git`) keep their path (the host is
replaced); deeper directories of a requested file are dropped from its surrogate, so a model
importing `pkg.sub.mod` sees `pkg.f1`; route strings (`/api/v1/...`) are not treated as paths.

## Metadata

**Headers.** Default: `User-Agent: Mozilla/5.0 (compatible; middleman/0.1)`, `Authorization`,
`Content-Type`, `Accept`. No `HTTP-Referer` anywhere in the code. `X-Title` is not a default;
it is sent only when the provider config sets it, as `config/middleman.example.toml` does.

**Is `X-Title = "middleman"` acceptable?** It reveals the tool, not the user or the company, and
the User-Agent already says the same. OpenRouter uses the header for app attribution. It adds
nothing you need. Recommendation: remove it from the example config and make the User-Agent
generic, so a request does not announce that its content is pseudonymized.

**Fingerprint.** Even with generic headers, middleman traffic is recognizable: the system
prompt is constant and mentions placeholders, the envelope is constant (`Task kind:`,
`--- FILE x (from line N) ---`, `--- END ---`), and surrogates have fixed shapes
(`svcN.example.net`, `userN@example.com`, `198.51.100.N`, `/workspace/app`, `MM_SECRET_N`).
Within one process the same name always maps to the same made-up word, so a provider can link
requests about the same unknown name. A new process gives new words.

**Cannot be hidden.** The provider account (API key, billing identity), the source IP, request
times, sizes and volume, and the models chosen.

## Audit log of today's real runs

File: `~/.local/state/middleman/audit-2026-11.jsonl` (0600, directory 0700). 13 records,
5 sent. Scanned for: the OS user name, `/Users/<name>` and `/home/<name>` paths, the git user
name, `youtube-batu`, the machine host name, `Desktop/Personal`, `.claude`, `worktrees`,
non-example emails, non-documentation IPs, key-shaped tokens.

- Sent payloads (lines 2, 3, 9, 10, 11): **0 hits**. The only URL host is `svc1.example.net`.
- File headers sent: `src/invoice.py` (lines 2-3), `e2e/app/inventory_core.py` (lines 9-11).
  These show the path leak above on harmless data.
- Identifiers sent verbatim in lines 9-11: `Sku`, `parse_sku`, `apply_discount`,
  `restock_needed`, `bucket_by_category` (synthetic).
- Line 1 contains the fixture names `Acme` / `Zorblax`. It is a dry run made without a
  dictionary (`sent=false`, no findings); nothing left the machine.
- Lines 9-10 store one provider error each: the `:batch` routing error text, no payload, no key.
  The same sanitized payload had been posted to that model first and was rejected.
- Ledger (0600): no payload fields. `project` values are root directory names.

## Residual risk

What a determined provider still learns from one request, measured on the canary run
(72 lines of real `src/pipeline.rs`, sent byte for byte):

- **17 project identifiers**: `DelegateRequest`, `InputText`, `FileRef`, `TaskKind`,
  `WriteMode`, `approval_id`, `declared_sensitivity`, `deny_unknown_fields`, `dry_run`,
  `expected_output_tokens`, `max_cost_usd`, `max_output_tokens`, `output_path`, `task_kind`,
  `to_string`, `user_requested`, `write_mode`.
- **9 comment lines and 3 string literals**, including design intent
  (`routing.mode = "confirm": set after the user approved the dry-run plan.`) and the product's
  own name (`` `middleman approve <id>` ``, `.middleman.new`), because that name is not in the
  dictionary.
- **Libraries and style**: `#[serde(default)]`, `Deserialize`, naming conventions, layout.
- **Structure around replaced names**: `pub struct <X>Client`, `<x>_tenant_id: u64`,
  `get_<y>_timeout`. The name is hidden; the role is not.
- **Words next to names**: `Mehmet` (first name, not in the dictionary), `/work/` below the
  home directory, URL paths, port numbers, a database name.
- **Across requests**: file paths, which lines of which file, how often, and linked surrogates.

Pseudonymization hides who you are. It does not hide what the code does. Code whose logic is
itself the secret must be declared `confidential`, which never leaves the machine.

## Recommendations, ranked by value for effort

1. **Fix the root boundary bug.** In `InfraScanner::scan`, treat `.` after the root as part of
   a longer name only when a word character follows. Tiny change, closes a real leak.
2. **Pseudonymize the path in `--- FILE`.** Send `file1.rs` (keep the extension) and map it
   back locally. Small change in `build_payload`; removes project layout from every request.
3. **Deny `.gitmodules` and a `.git` file on read.** Add `**/.gitmodules` and `**/.git` to
   `BUILTIN_DENY`. One line each.
4. **`middleman dict suggest`** (done). Mine the repo for proper nouns: root directory name, git
   remote org and repo, package names in manifests, hostnames in configs, git author names,
   capitalized words that are not English or library names. The dictionary is the single point
   of failure for names (see the control test), and today it is filled by hand. Also generate
   snake / kebab / spaced variants so they are rewritten instead of blocking the request.
5. **Replace the whole URL, not just the host.** Port, path, user and database name. Small.
6. **Generic User-Agent; drop `X-Title` from the example config.** Trivial.
7. **Comment and string-literal stripping**, as an option per task kind. `write_tests` and
   `boilerplate` rarely need comments; `docstring` and `explain` do. Medium effort, removes
   most free-text leakage.
8. **Replace the rest of an absolute path**, not only `/Users/<name>`. Small.
9. **Automatic identifier pseudonymization** for project-specific identifiers that are not in
   the dictionary (syntax-aware, consistent, keeps standard-library and dependency names).
   Highest protection against learning what the code is about, but the most work and it will
   cost answer quality. Start as opt-in.
10. **Per-request surrogate key** as an option, so requests cannot be linked by surrogate.
    Costs consistency across related requests.
11. **Cache dir 0700 / file 0600.** Trivial, for consistency.

## Notes

- A random-looking directory name in the root path (macOS temp dirs) can be taken for a
  high-entropy token. The request is then refused (fail closed), not leaked.
- `tests/mcp_stdio.rs` fails when the checkout sits under a `.claude/` directory (for example a
  Claude Code worktree): the write deny rule `**/.claude/**` matches the absolute path, so file
  mode is refused. It should pass in a normal checkout (not re-run there). Not a leak.
