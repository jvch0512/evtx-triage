#!/bin/sh
cd "$(dirname "$0")/.." || exit 2
BIN=bin/evtx-triage
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
exp() { name=$1; want=$2; shift 2; "$BIN" "$@" >/dev/null 2>&1; got=$?; [ "$got" = "$want" ] && ok "$name" || bad "$name (got $got, want $want)"; }
exp "default exit 0" 0 examples
exp "fail-on medium" 1 examples --fail-on medium
exp "fail-on high" 1 examples --fail-on high
exp "fail-on critical" 1 examples --fail-on critical
exp "quiet file passes" 0 examples/logs/flat-array.json --fail-on high
exp "missing path" 2 "$T/none"
exp "bad flag" 2 --bogus
exp "no args" 2
exp "bad fail-on" 2 examples --fail-on low
exp "two paths" 2 examples examples
N=$("$BIN" examples --tsv | head -1)
[ "$N" = "# 3 files, 14 findings" ] && ok "tsv header" || bad "tsv header ($N)"
"$BIN" examples --tsv | sed -n 2p | awk -F'\t' 'NF==4{exit 0} {exit 1}' && ok "tsv columns" || bad "tsv columns"
"$BIN" examples | head -1 | grep -q '^3 files, 14 findings$' && ok "human header" || bad "human header"
printf '{"EventID":1102}\n' > "$T/one.jsonl"
"$BIN" "$T/one.jsonl" --tsv | grep -q "EVT001	one.jsonl:1	" && ok "single file label" || bad "single file label"
head -c 2000 /dev/urandom > "$T/bin.json"
"$BIN" "$T/bin.json" >/dev/null 2>&1; [ $? -le 1 ] && ok "binary input survives" || bad "binary input"
exit $fail
