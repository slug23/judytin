# judytin

A [TinTin++](https://tintin.mudhalla.net/)-style MUD client, built for
[judymud](../judymud) but happy on any MUD. One small Rust binary, one
dependency (crossterm), and the tt++ scripting dialect your muscle memory
already knows.

## Quick start

```
cargo build --release
./target/release/judytin                  # connects to 127.0.0.1:2323 (judymud)
./target/release/judytin -r judymud.tin   # same, with the starter script
./target/release/judytin some.mud.org 4000
./target/release/judytin --tls mudhost    # telnet-over-TLS (port 2324)
./target/release/judytin --ssh grib@mudhost:2322   # your ssh key is your character
```

At the judymud door, type `guest <name>` to roll a character. With
`judymud.tin` loaded, the resume command the server gives you is captured
into `$resume` automatically — type `rk` to see it, `res` to send it after a
reconnect.

`judytin --help` lists the flags. `~/.judytinrc` is read at startup if it
exists. `--offline` starts without connecting; `--dumb` gives a plain
line-mode client (automatic when stdin/stdout is a pipe, which makes judytin
scriptable: `printf 'guest x\nlook\nquit\n' | judytin --dumb`).

## The tt++ dialect it speaks

Commands start with `#` and may be abbreviated (`#al`, `#act`, `#high`, ...).
`;` separates commands, `{}` groups arguments, `%1`–`%99` are
wildcards/arguments, `$name` inserts a variable, `@func{args}` calls a
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
`ctrl-t`) instead of raw escape sequences; `%t` time formatting is UTC;
trailing pattern wildcards are greedy (so `kill %1` captures the rest of
the line instead of nothing). Not implemented: `#map` automapper, `#chat`
/`#port` inter-client networking, multiple simultaneous sessions, MCCP
compression, PCRE embedding in patterns.

## Development

```
cargo test    # unit tests + end-to-end tests against a mock MUD server
```
