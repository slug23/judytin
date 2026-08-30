# judytin

A [TinTin++](https://tintin.mudhalla.net/)-style MUD client, built for
judymud but happy on any MUD. One small Rust binary, four dependencies
(crossterm, rustls, sha2, regex), and the tt++ scripting dialect your
muscle memory already knows.

## Quick start

Needs a Rust toolchain (1.88 or newer; [rustup](https://rustup.rs) is the
usual way). Then:

```
git clone https://github.com/slug23/judytin
cd judytin
cargo install --path .
```

That builds it and drops a `judytin` binary in `~/.cargo/bin`, which rustup
already put on your PATH — so from here on it is just `judytin`, from any
directory:

```
judytin                            # connects to 127.0.0.1:2323 (judymud)
judytin -r judymud.tin             # starter script (from the clone directory)
judytin some.mud.org 4000
judytin --tls mudhost              # telnet-over-TLS (port 2324)
judytin --ssh slug@mudhost         # ssh door (2322); your key is your character
```

`judymud.tin` stays in the clone, so `-r judymud.tin` finds it only from
there; give a full path, or copy its contents into `~/.judytinrc`, to have
it everywhere. `cargo uninstall judytin` removes the binary again. Add
`--locked` to the install if you want exactly the dependency versions this
was tested against, rather than the newest compatible ones.

If you would rather not install anything, `cargo build --release` leaves
the binary at `./target/release/judytin`, and `cargo run --release --`
followed by judytin's own arguments runs it in place — that bare `--` is
what keeps cargo from reading the flags as its own.

At the judymud door, type `guest <name>` to roll a character. With
`judymud.tin` loaded, the resume command the server gives you is captured
into `$resume` automatically — type `rk` to see it, `res` to send it after a
reconnect.

`judytin --help` lists the flags. `~/.judytinrc` is read at startup if it
exists. `--offline` starts without connecting; `--dumb` gives a plain
line-mode client (automatic when stdin/stdout is a pipe, which makes judytin
scriptable: `printf 'guest x\nlook\nquit\n' | judytin --dumb`).

That example works because judytin holds what you type until the server has
finished greeting you — otherwise a pipe delivers all three lines before the
login prompt has even arrived, and they get answered blind. The hold lasts
until the server pauses, or two seconds if it never speaks at all, and it
never delays judytin's own answer to a telnet option. When input runs out
while a session is still open, judytin says so rather than sitting there
looking hung.

A lone number is read as a port, not a host: `judytin 4000` is the local
default host on port 4000. Two arguments are still host then port.

## The tt++ dialect it speaks

Commands start with `#` and may be abbreviated (`#al`, `#act`, `#high`, ...).
`;` separates commands, `{}` groups arguments, `%1`–`%99` are
wildcards/arguments, `{regex}` embeds a real regular expression that captures
like a wildcard (`\{` is still a literal brace), `$name` inserts a variable
(`$name[key]` an entry in a keyed one, nesting as `$a[b][c]`, with the key
itself computed if you write `$hp[$who]`), `@func{args}` calls a
function, `#5 {commands}` repeats five times, `!` recalls history, Tab
completes words from recent output.

### Triggers

| command | what it does |
|---|---|
| `#alias {gb} {get bread;eat bread}` | shortcuts; `%1`... are arguments, bare args append |
| `#action {%1 has arrived} {wave %1}` | fire commands on server output |
| `#highlight {pattern} {light yellow}` | colorize (also `Orange`, `<faa>` cube codes, `b red`) |
| `#substitute {pattern} {text}` | rewrite matching text |
| `#gag {pattern}` | hide matching lines |
| `#variable {name} {value}` / `#local` | set `$name` (local = current trigger/function) |
| `#function {name} {...#return %1...}` | call as `@name{args}` anywhere |
| `#macro {f5} {get all;#showme looted}` | key bindings: f1-f12, ctrl-x / ^x, alt-x |
| `#event {SESSION CONNECTED} {...}` | also DISCONNECTED, RECEIVED LINE / PROMPT |
| `#tab {longmobname}` | add words to tab completion |

Each has an `#un...` remover; the bare command lists definitions.
Patterns know `^` and `$` anchors, `%d %w %s %S %D %W` character classes,
`%+ %? %. %*`, and `%i`/`%I` case-insensitive toggles.

### Flow control & math

```
#if {$hp < 100} {quaff heal} {#showme fine}
#if {"%1" == "{bli|bla}"} {...};#elseif {...} {...};#else {...}
#switch {1d4} {#case 1 cackle;#case 2 smile;#default giggle}
#loop {1} {3} {i} {get all $i.corpse}
#while {$mana < 50} {meditate;#math {mana} {$mana + 10}}
#foreach {bob;tim;kim} {name} {tell $name hello}
#math {heals} {$mana / 40}          #format {line} {%h} {The Title}
#5 {buy bread} {buy apple}          #break / #continue / #return {value}
```

Expressions are C-like: `+ - * / % **` (power), `//` (root), `d` (dice:
`3d6`), comparisons, `&& || ^^ !`, bitwise ops, `?:` ternary. `==` does
pattern matching on strings (`"{bli|bla}"`), `===` compares exactly.

### Timers, screen, organization

| command | what it does |
|---|---|
| `#ticker {name} {commands} {secs}` | repeat on a timer |
| `#delay {2} {commands}` | one-shot; also `#delay {name} {cmds} {secs}` |
| PgUp/PgDn, `#buffer {up\|down\|home\|end\|find {pat}}` | 10k-line scrollback (Esc returns to live) |
| `#grep {pattern}` | search the scrollback |
| `#history` / `!` `!!` `!text` `!3` | list / repeat commands |
| `#class {x} {open\|close\|clear\|kill\|list\|write {f}}` | group triggers, tear them down together |
| `#line {gag\|oneshot\|multishot {n}\|quiet\|verbatim}` | one-line modifiers |
| `#kill {action\|all\|...}`, `#info`, `#message {kind} {off}` | housekeeping |
| `#log {append\|overwrite} {file}` | plain-text session log |
| `#config speedwalk on` | then `3n2e` or `nesw` walks (`#config` lists options) |
| `#path` / `#pathdir` | record routes, `walk` / `run {delay}` / `zip` to a speedwalk |
| `#showme`, `#echo {fmt} {args}`, `#send`, `#cr`, `#bell`, `#split` | output & misc |
| `#textin {file}`, `#system {cmd}`, `#read` / `#write {file}` | files & shell |
| `#session`, `#zap {name}`, `#name {cmd}`, `#all {cmd}`, `$session` | several muds at once |

`#help` shows the in-client cheat sheet, `#commands` lists every command.
`ctrl-d` on an empty line quits, `ctrl-l` redraws, up/down browse history,
and emacs-style editing keys work (`ctrl-a/e/u/k/w`).

## Transports

Three ways to reach a MUD, indistinguishable above the socket:

- **Plain telnet** — the default, like it's 1993.
- **Telnet over TLS** — `--tls`, or `#ssl {name} {host} {port}` (tt++'s
  command). The server certificate is pinned on first connect into
  `~/.judytin_known_hosts` (trust-on-first-use, like ssh); a changed
  certificate refuses loudly. judymud's TLS door is on port 2324 and logs
  the same `sha256:` fingerprint judytin prints, so you can compare.
- **Anything as a pipe** — `#run {name} {command}` (also tt++'s command)
  speaks to a subprocess's stdin/stdout. `--ssh user@host[:port]` is sugar
  for `#run` with the system `ssh -T`, so your keys, agent, and known_hosts
  all behave like normal ssh. On judymud's ssh door (port 2322) the key
  *is* the identity: an unknown key rolls a guest character, the same key
  resumes it — no resume key to keep.

  The port defaults to 2322, judymud's ssh door, the same way the bare
  command defaults to 2323 and `--tls` to 2324; `--ssh me@host:22` still
  reaches an ordinary sshd.

  Trust works the way it does for TLS. judytin runs ssh with
  `BatchMode=yes`, because there is no terminal behind the pipe and a
  prompt would hang where nobody could answer it; `accept-new` alongside it
  means a host ssh has never met is recorded rather than refused, so a
  first `--ssh` simply connects. judytin says so when that happens — the
  first key is taken on faith and you should know the moment it was. A host
  whose key later *changes* is still refused, and judytin says something
  quite different there: it cannot tell a rebuilt server from someone
  standing in the middle, and appending the new key is the one thing not to
  do.

### More than one session

judytin holds several connections at once and sends what you type to one of
them.

```
#session {mud} {mudhost}            open one, named — port 2323 unless you say
#session {mud} {mudhost:4000}       ...or say it, either way round
#session {mud} {mudhost} {4000}     tt++'s three-argument form, still fine
#session {safe} {ssl://mudhost}     TLS, on 2324 unless you say otherwise
#session {far} {ssh://you@mudhost}  through the system ssh, on 2322
#session                            list them; * marks where typing goes
#session {mud}                      switch to it
#zap {mud}                          close it; bare #zap closes this one
```

One verb opens every transport, because which door a mud answers on is not
the sort of thing that should need a different command. `#ssl {name} {host}
{port}` and `#run {name} {command}` are tt++'s spellings and still work —
`#run` is also the way to a pipe that is not ssh.

Once two are open, the useful thing is talking to one you are not watching:

```
#mud look                           run one command over there, then come back
#all {say ready}                    run it in every session
$session                            the name of the session you are in
```

`#name` and `#all` run in the target session's own focus, so a command sent
there behaves exactly as if you had switched — its output is that session's,
its triggers reply to that mud — and when it is done the focus is where you
left it. `$session` is what a shared trigger uses to tell three characters
apart: `#action {What is your name} {$session}` logs all of them in, each
under its own.

Text from a session you are not watching arrives tagged with its name, so
two muds talking at once stay distinguishable and nothing is silently
dropped. Triggers fire for background sessions too, and reply to the session
whose line set them off rather than to whichever you happen to be looking
at. Each session keeps its own connection, telnet state, reconnect settings
and input queue; aliases, triggers and variables stay global, shared by all
of them.

Commands come first when judytin reads a `#word`, so a session named after
one — `#send`, `#end` — is reached by switching to it instead; judytin says
so when you open it. `ssh://` spawns a process, so like `#run` it is refused
when a trigger is what asked (see [Security](#security)).

With one session open judytin behaves exactly as it did before, including
`#zap` leaving it disconnected but remembered, so `#reconnect` still works.

### Coming back after a drop

`#reconnect` returns to the last session — whatever transport it was, without
retyping the `#session`, `#ssl` or `#run` line that made it.

`#config {reconnect} {on}` makes judytin do that by itself after a drop it
did not ask for, retrying at 1, 2, 4, 8, 16 then every 30 seconds for as long
as it takes. It is off by default for a reason worth knowing: **judytin cannot
tell the server dying from you typing the game's own quit command.** Both are
just a socket closing, and the quit command differs from MUD to MUD. `#zap` is
how you say you meant to leave — it stops any pending retry — and every
attempt reminds you of that.

One asymmetry, deliberate: a trigger may fire `#reconnect` for a socket
session, but not for a pipe. Returning to a pipe means spawning a process
again, and while the command line is yours and beyond the server's reach,
letting server text choose *when* it runs is the thing
[`tests/security.rs`](tests/security.rs) exists to prevent.

## What it does under the hood

- **Split screen** the way tt++ does it: a VT100 scroll region for output, a
  status bar, an input line. The terminal handles wrapping and ANSI color
  natively, so judymud's colors pass straight through.
- **Prompt patching**: judymud parks its prompt without a newline and later
  continues the line. judytin holds unterminated tails briefly
  (`#config {packet patch}`) so triggers, gags and highlights see complete
  lines, then patches the displayed line if the server appends to it.
- **Lazy substitution**, like tt++: braces protect bodies at definition
  time; `$vars` and `@funcs{}` resolve when a command actually runs — which
  is what makes `#while {$i < 5}` and `#alias {res} {$resume}` behave.
- **Telnet done quietly**: a proper IAC state machine that strips and
  refuses everything, accepts server-side ECHO (masking your input for
  password prompts on other MUDs), and never sends subnegotiations —
  judymud's parser would read those as commands.
- Triggers match against ANSI-stripped text; highlights are spliced back
  into the colored line at the right byte offsets.

Deliberate deviations from tt++: macro keys use friendly names (`f5`,
`ctrl-t`) instead of raw escape sequences; trailing pattern wildcards are
greedy (so `kill %1` captures the rest of the line instead of nothing);
aliases, triggers and variables are global rather than scoped per session.

`%t` renders in local time, read from the system's own zone database
(`/etc/localtime`, honouring `TZ`), with `%z` and `%Z` for the offset and
its name. If the machine cannot say, it falls back to UTC and `%Z` says
`UTC`, so a timestamp is never confidently wrong.

Lists are keyed variables whose keys are `1, 2, 3…`, and `#list` is the set
of operations over one:

| command | what it does |
|---|---|
| `#list {p} {create} {a} {b}` | build it from the given items |
| `#list {p} {add} {c}` / `{insert} {1} {c}` | append, or put at a position |
| `#list {p} {get} {-1} {var}` / `{set} {2} {x}` | read or replace an item |
| `#list {p} {size} {var}` / `{find} {pat} {var}` | count, or the index matching a pattern |
| `#list {p} {delete} {2} {3}` / `{clear}` | remove some, or all |
| `#list {p} {sort}` / `{reverse}` | reorder |
| `#list {p} {collapse} {, }` / `{explode} {, }` | between a list and a plain `$p` |

Indices count from `+1`, and `-1` is the last item, so `$p[-1]` is the tail.
`find` takes a judytin pattern rather than a second regex dialect — the same
thing `#action` takes, which since `{regex}` can hold a real expression.
Splitting in `explode` respects escaping, so a separator that arrived inside
server text cannot cut the text it belongs to.

Not implemented: `#chat`/`#port` inter-client networking, `&var[]` for size
(use `#list {p} {size} {n}`), and the rarer `#list` options — `shuffle`,
`filter`, `refine`, `indexate`, `numerate`, `tokenize`, `copy`, `order`,
`swap`, `simplify`.

There is no automapper and there will not be one: `#path` and `#pathdir`
already cover walking and reversing a route, which is the part that earns its
keep, and the rest is a research problem about naming a room from its prose.

MCCP compression is likewise not merely absent — judytin refuses the offer,
and the refusal is deliberate: a decompressor on a stranger's byte stream is
a zip bomb waiting to happen, and it would cost a dependency to gain nothing
against a server that sends no telnet negotiation at all.

## Security

A MUD client runs a scripting language over text a stranger sends you.
That is the whole threat model, and it is not hypothetical: the classic
attack is a server that makes your own trigger execute its text.

```
#action {%1 tells you %2} {tell %1 got it}      your trigger
Bob;#system rm -rf ~ tells you hi               what the server sends
```

judytin treats server text as **data, never code**. It is escaped the
moment it enters a script, every parser preserves that escaping rather than
acting on it, and the escape is removed only at the end of the line — where
the text is sent to the MUD, printed, or evaluated. So a capture can carry
`;`, `#`, `{`, `$`, `@` or a quote and none of them become syntax, however
many layers of alias, function, variable and `#delay` it passes through.
See [`src/data.rs`](src/data.rs) for the reasoning.

Behind that, a second line of defence: commands with effects outside the
game — `#system`, `#run`, `#read`, `#write`, `#log`, `#textin`, and
`#session` when its destination is an `ssh://` one — refuse to run when a
trigger or event caused them, even indirectly through a timer. The gate is on
the act, not the word: `#session {x} {ssh://host}` spawns a process exactly as
`#run` does, so it is refused exactly as `#run` is.
Type one yourself and it works normally. `#config {trigger shell} on` lifts
the restriction if you need it; only do that for a MUD you would trust with
your shell.

Also deliberate:

- **Only colour is relayed to your terminal.** Your terminal is an
  interpreter too. Clipboard writes (`OSC 52`), title reporting — which can
  echo attacker text back onto your input line — and cursor control are
  filtered out of server output; SGR colour passes through.
- **Line length and match effort are bounded**, so a server cannot exhaust
  memory with a line that never ends, or freeze the client with a padded
  one. The match budget charges for the length scanned, not per step, which
  matters now that `{regex}` groups scan a whole span at a time; the regex
  engine is the `regex` crate, chosen because it is linear in the subject and
  the subject is a stranger's line.
- **TLS pinning fails closed.** A changed certificate is refused, and so is
  a damaged entry in `~/.judytin_known_hosts` — rather than silently
  treating it as a first connection. Note this is trust-on-first-use, like
  ssh: the first connection is trusted blind, and hostnames are not checked
  against the certificate, so the pin is the whole identity.
- Session logs and the pin file are created `0600`, and nothing is echoed
  to screen or log while the server has taken ECHO for a password prompt.

Known and accepted: `#system` and `#run` execute shell commands *you* type,
`$variables` interpolate into them unquoted, and `#read` runs a script
file — so only load scripts you would run as programs. Trigger patterns
themselves are user-authored and trusted.

**judytin is not a privileged client.** It was built alongside judymud, but
it holds no shared secret, speaks no private protocol, and can do nothing
that any other client cannot. judymud performs no client identification at
all — it does not know judytin from `nc` — and the only judymud-specific
things here are default port numbers and a starter script assembled from
output every client can see. Anything judytin ever needs from the server
goes into judymud's public protocol first, so every client gets it at the
same time. A client with special powers is a credential worth stealing;
there is deliberately nothing here to steal.

Found something? Please open an issue.

## Development

```
cargo test    # unit tests, end-to-end tests, and tests/security.rs —
              # a suite of hostile MUD servers, each one a real attack
```

`tests/security.rs` is the interesting one: every test in it is a server
trying to execute code, crash the client, or steer a script, and several
are regressions for bugs that were live.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

judytin is an independent implementation of the TinTin++ command language,
written from its published manual. It shares no code with
[TinTin++](https://tintin.mudhalla.net/), which is GPL-3 and the work of
other people entirely.
