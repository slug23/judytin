#!/bin/sh
# newcrew.sh — create a roster of four fresh guests for bots/crew.tin.
#
# Writes bots/crew.local.tin, which is git-ignored and mode 0600 because it
# will hold resume keys. On judymud a resume key *is* the character: anyone
# who reads one owns that character. Never print this file, never commit it,
# and if a key does get out, abandon the character rather than hoping.
#
# Run once. After that the same four characters are resumed and their
# experience accumulates.
set -eu
here=$(dirname "$0")
out="$here/crew.local.tin"

if [ -e "$out" ]; then
  echo "$out already exists — delete it first to start a new crew." >&2
  exit 1
fi

# Four letters of entropy, so a second crew does not collide with the first.
s=$(LC_ALL=C tr -dc 'a-z' < /dev/urandom | head -c 4)

umask 077
{
  echo "#nop generated roster — never commit this, it will hold resume keys"
  echo "#list {roster} {create} {war$s}{cle$s}{mag$s}{thi$s}"
  for pair in "war warrior" "cle cleric" "mag mage" "thi thief"; do
    short=${pair% *}
    class=${pair#* }
    echo "#variable {class[$short$s]} {$class}"
    echo "#variable {login[$short$s]} {guest $short$s $class}"
  done
} > "$out"
chmod 600 "$out"

echo "crew '$s' created in $out"
echo "now: ./target/release/judytin -r bots/crew.tin --offline"
