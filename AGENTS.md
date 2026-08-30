# Working on judytin

Notes for anyone — person or agent — making changes here.

## This repository is public

Everything committed is world-visible, and git remembers. A secret pushed
and then deleted is still in the history; the only real remedy is rotating
the secret. So the check happens *before* `git add`, not after.

Never commit:

- **Resume keys, passwords, tickets, or session tokens.** On judymud the
  resume key *is* the character, and `#write` puts every variable —
  including `$resume` — into a plain file. That file does not belong in the
  repository.
- **Session logs** (`#log`), settings dumps (`#write`, `#class … write`),
  or `~/.judytinrc`. They record real play, which means real credentials.
- **Anything captured from a live game**: transcripts, character names you
  would rather not publish, host names of private servers.
- Local paths that identify you, and `~/.judytin_known_hosts` (it reveals
  which servers you play on).

Practical habits: stage explicit paths rather than `git add -A`; read
`git status` before every commit; and keep working files out of the repo
directory, or name them `*.local.tin`, which `.gitignore` covers. If
something sensitive does get committed, say so immediately rather than
quietly amending — if it was pushed, the credential must be rotated.

Test fixtures should use obviously fake values. `tests/` follows this
already: invented names, throwaway certificates generated at run time.

## judytin has no privileged relationship with judymud

judytin is judymud's companion client, and that is a matter of convenience
only. **It must never have an ability that any other client lacks.** It
reaches the game through the same published doors, with the same commands,
carrying no shared secret and no private protocol, and the server does not
know or care which client is connected — it performs no client
identification at all, and must not start.

Concretely, do not add:

- a hidden or undocumented command that only judytin knows to send;
- a shared key, token, or handshake between judytin and judymud;
- a client identifier that the server treats specially;
- anything that reads judymud's database, config, or internals directly.

The only judymud-specific things here are the default port numbers and
`judymud.tin`, a starter script built from output any client can see. Both
are things a third-party client author would write after reading judymud's
public protocol document, which is the standard to hold to: **if judytin
needs something new from the server, it belongs in the public protocol
first**, so every client gets it at the same time.

This is a security property as much as a fairness one. A privileged client
is a credential to steal and a back door to find, and it would make the
server's behaviour depend on something a hostile client can simply claim.

## Security invariants

Two, both explained where they live. Read them before touching parsing.

1. **Server text is data, never code** — see [`src/data.rs`](src/data.rs).
   Text from the server is escaped where it enters a script, every parser
   preserves that escaping, and it is resolved once at a sink. If you add a
   parser, it must preserve escapes; if you add a sink, it must unescape
   exactly once.
2. **Server-driven execution cannot touch the machine.** `#system`,
   `#run`, `#read`, `#write`, `#log` and `#textin` refuse when a trigger,
   event, or a timer they created caused the execution. So does `#session`
   when its destination is an `ssh://` one: the gate is on the act of
   spawning a process, not on which command spells it.

`tests/security.rs` is a suite of hostile servers, one per attack, several
of them regressions for bugs that were live. Run it after any change to
parsing, expansion, or the command table — and add a case when you find a
new attack shape.

## Build and test

```bash
cargo test        # unit, end-to-end, and the security suite
cargo clippy --all-targets
cargo build --release
```

The end-to-end and security tests spawn the real binary against mock
servers on ephemeral ports; they need no network and no running judymud.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:46cd31e7 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale. Codex 0.129.0+ can load Beads context automatically through native hooks; use `/hooks` to inspect or toggle them.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.
<!-- END BEADS CODEX SETUP -->
