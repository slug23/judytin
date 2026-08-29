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
   event, or a timer they created caused the execution.

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
