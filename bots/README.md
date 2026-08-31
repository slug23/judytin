# bots — a crew of four, in one judytin

Four characters of four classes, logged in at once from a single client,
grouped, and grinding. It is a working bot and it is also the test: every
gap it ran into became a judytin fix or a filed issue.

```bash
cargo build --release
./bots/newcrew.sh                                   # once: makes the roster
./target/release/judytin -r bots/crew.tin --offline
```

Then two words:

```
crewgo      # log all four in, each bound to its class file
crewhunt    # walk to the training ground and start
```

`crewgo` is the only one you need — grouping, buffing and wimpy all happen on
arrival. `crewhunt` walks the leader out and starts the tickers.

Useful once it is running:

| | |
|---|---|
| `crewvitals` | hit points, mana and current attack for all four |
| `crewscore` | each character's `score` |
| `huntstop` / `huntstart` | pause and resume the fighting |
| `#magxxxx look` | send one command to one character |
| `#all {look}` | send one command to all of them |
| `crewoff` | unload the whole bot, leaving the client to play by hand |

`./bots/newcrew.sh` writes `bots/crew.local.tin` — the roster and the logins.
It refuses to overwrite an existing crew.

### Running it a second time

A crew is created once. Run it again and the door says *"That name is already
someone's."* — the characters exist now, and `guest` is the wrong verb for
them. Two ways on:

- `rm bots/crew.local.tin && ./bots/newcrew.sh` for four fresh characters, or
- keep the old ones: take the `resume <name> <key>` line judymud printed at
  first login and make it that character's login —
  `#variable {login[warabcd]} {resume warabcd <key>}`

**judytin cannot save the key for you, and should not be able to.** The key
arrives as server text, so a trigger that reads it is server-driven, and
`#write` is refused for exactly that execution — a MUD must never be able to
make the client write a file. Saving a credential is a job for a person, on
purpose. `crew.local.tin` is `0600` and git-ignored because it holds them: on
judymud a resume key *is* the character.

## How it is put together

| file | what it owns |
|---|---|
| `crew.tin` | opens the sessions, binds a class file to each, group and hunt aliases |
| `core.tin` | everything shared: login, vitals, combat, learning, reporting |
| `warrior.tin` `cleric.tin` `mage.tin` `thief.tin` | one class each — keyed variables only |

The whole design rests on one property of judytin: **a trigger runs in the
focus of the session whose line set it off.** So there is one `#action` for
the vitals line, not four, and `$session` inside it names whichever character
produced that line. Per-character state is keyed on it — `$hp[$session]`,
`$atk[$session]` — because actions, functions, aliases and tickers are global
to the client while connections are not.

That is also the rule for class files: **they set keyed variables and nothing
else.** An `#action` or `#function` defined in `mage.tin` would be keyed by
its name and would belong to all four characters, silently replacing
`core.tin`'s. Anything class-dependent lives in `core.tin` and branches on
`$role[$session]`.

A class file is bound to a character by *when* it is read, not by anything in
it — `#session mag ...` moves the focus, and the `#read` straight after lands
on the mage. The pair has to stay together; that is the whole mechanism.

## It teaches itself what it can cast

A level-1 cleric has `cure light` and nothing else worth casting: `cause
light` is level 2, `armor` is level 3. Rather than carry a level table that
goes stale the next time the game is balanced, the crew finds out by trying.
The refusal is free — no mana, no round — and it names both the spell and the
level it needs:

```
You are not yet learned enough for cause light (level 2).
```

So a caster reaches for its spell, is told no, falls back to swinging at
things, and reaches for it again the moment it gains a level.

## It is covered by the test suite

`tests/e2e.rs::the_shipped_bot_files_load_and_their_triggers_fire` reads
`core.tin` for real, against a mock that speaks enough judymud to answer: a
door, a login confirmation, a vitals line, and a "not yet learned enough"
refusal. It asserts the crew logs in, parses its hit points into per-session
state, opens its gate, tries its spell and falls back to melee — and that no
file calls a function that is not defined.

That last one is the point. This bot only tests judytin if it still runs, and
a rewrite once dropped a single `#function` definition; every gate that
called it silently became false and the crew sent nothing at all for two
five-minute runs. The test fails in four seconds if that happens again —
verified by deleting the definition and watching it fail.

## Credentials

`crew.local.tin` holds the roster and the logins. It is **not** in the
repository and must not be: on judymud a resume key *is* the character, and
this repository is public. `*.local.tin` is git-ignored, and the file is
written `0600`.

judytin cannot write that file itself, and should not be able to. `#write` is
refused when a trigger caused it, so a trigger that has seen a resume key
cannot put it on disk. That is the second security invariant doing its job,
not a gap — capturing keys is a job for something outside the client.

## Why `--offline`, and why the script opens its own sessions

Starting with a connection on the command line races the door. The script and
the socket are separate channels and nothing orders them, so a login
`#action` can register *after* the prompt it was written for has already gone
by, and the character sits at "By what name do you wish to be known?" while
the rest of the script runs into the void. Opening from inside the script
means every trigger is in place before a socket exists. See judytin-iz5.

## It assembles itself, and waits to be told it worked

The crew groups on arrival, not on a stopwatch. A first version said "group
at eighteen seconds", the server happened to be restarting at eighteen
seconds, and four characters spent three minutes fighting alone and sharing
nothing. Reacting to being in the world instead means a restart costs a few
seconds.

Grouping then took a second try. The obvious form — arrive, send `follow`,
ask the leader to `group` you in the next breath — has a race in it that is
invisible from inside one client: those two commands travel on two different
sockets, and the group regularly arrived first. judymud said *"the cleric is not
following you."* six times in one run and the crew never formed.

The fix is to stop guessing and wait for the server to confirm:

```
#action {%1 starts following you} {#if {"$isleader[$session]" != ""} {group %1}}
```

That line only exists once the thing it depends on has happened, so there is
nothing left to race. It fires in the leader's focus because it is the
leader's line — which is what makes "am I the leader?" answerable at all.

One trap worth knowing, since the crew depends on it: **`$session` inside
`#other {command}` is the *target* session**, because the focus has already
moved by the time the body is substituted. To carry the originating
character's name across the switch, capture it first with `#local {me}
{$session}` — locals live on the client and survive the move.

## Reconnecting

`#config {reconnect} {on}` in `crew.tin`, plus `SESSION CONNECTED` in
`core.tin` re-sending the login. judymud restarts often while it is being
worked on; the crew backs off 1s, 2s, 4s, 8s, 16s and comes back by itself.

The login trigger answers **once** per connection. If a server rejects the
answer and asks again, answering again is a loop that runs across the network
where judytin's depth limits cannot see it — judytin-s66, which once managed
350,000 round trips in forty seconds. `$sent[$session]` is the guard, and it
has already caught a real re-prompt: a character name left over from an
earlier run.

## What building this found

Six judytin bugs and gaps, each fixed with tests. None were found by reading
the code; all six were found by trying to write a bot with it.

- **a keyed variable write did not expand its name.** `#variable
  {hp[$session]} {27}` stored under the literal name `hp[$session]` while
  reads expanded — so all four characters shared one variable and the cleric
  decided whether to heal from the mage's hit points. The exact thing
  `$session` exists to prevent
- **stdin EOF quit if the *focused* session was down**, even with three others
  connected. A `#session` that failed to connect — the normal case during a
  MUD restart — took the whole crew with it
- **`#prompt`.** Actions never see the prompt, and the prompt is where judymud
  puts the gold. There was no way to match it at all
- **a prompt trigger fired on a parked colour sequence** with no text behind
  it, handing a bot an empty capture every time the MUD changed colour
- **`#$var {command}`** could not address a session through a variable, so a
  generated roster could not be driven at all. The expansion names a session
  and is never offered to the command table: variables can hold server text,
  and server text must never become a command
- **`$connected`** did not exist, so a broadcast shouted at sessions that were
  down — about sixty refusals every six seconds during a restart, burying the
  reconnect messages
- **`#variable {x} {}`** could not set a variable to nothing, and for a script
  "this class has no healing spell" is a fact rather than an absence
- **a call to a function that did not exist was silent.** `@nosuchfn{}`
  substituted to the literal text `@nosuchfn{}`, so `#if {@playing{} == 1}`
  compared a string to `1`, was false forever, and the branch simply never
  ran. A rewrite here dropped one `#function` definition and the crew logged
  in, grouped, stood in a room filling with things to kill, and sent not one
  attack — twice, for ten minutes, with nothing in 1,800 lines of transcript
  pointing at it. It now says so once per name. Safe to say out loud because
  `@` is escaped in server text, so a MUD can never provoke the message
- **a prompt already shown was glued onto the next line**, so every pattern
  anchored at the start of a line silently captured the status prompt too.
  `{%1 starts following you}` gave `30/30hp 12/12m 0g> Bob`, the crew sent
  `group` with that, and judymud said "They are not here." for three minutes
  while the screen looked perfectly normal. This one affects every MUD with a
  prompt, which is all of them
- **the reconnect backoff was credited on connecting**, so a server that
  accepts and then turns you away — judymud's own door limit, *"That is enough
  for now. The door is shut"* — reset the escalation every time and got
  knocked on once a second indefinitely. judymud was defending itself
  correctly and judytin would not take the hint

Also fixed a flaky test found on the way past: one existing test opened its
second session on a `#delay` that fired at the same moment the first was
dropped, and failed about a third of the time on unmodified code. A six-run
sample said "base 5/6 pass, mine 1/6" and looked exactly like a regression I
had caused; sixteen runs each said 11/16 and 10/16. Small samples of a coin
flip are worth nothing, and the answer was to take the race out of the test
rather than to explain it.

Five more, fixed afterwards in the same way — by hitting them here first:

- **a trigger answering a re-prompt looped against the server forever.** A
  login trigger answers, the server rejects the answer and asks again, and
  nothing stops the cycle: roughly 350,000 round trips in forty seconds, at
  someone else's machine. Now bounded at 100 trigger-caused lines a second,
  with one message saying what is happening. Player-driven bursts are never
  counted
- **a `;` inside `#nop` ended the comment and ran the rest of the line** — so
  a comment went to the MUD. Four lines of this project's own prose leaked
  that way, one of them *after* the pattern was known, because the failure is
  silent. `#nop` now takes its whole line
- **a piped login script raced the door.** Startup opened the socket and only
  then began reading stdin, so the greeting had a head start on the trigger
  written to catch it. It now reads the script first and queues what the
  script sends until the connection is up
- **a prompt sharing a packet with its message** could still poison a capture.
  A `#prompt` pattern is the script saying what its prompt looks like, and
  judytin now takes it at its word and cuts there
- **no `%*` list expansion**, so `#foreach {$prey[%*]}` silently looped once
  over the literal string. `$name[%*]` is every item now

Nothing is left open against judytin from building this.
