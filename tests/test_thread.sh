#!/bin/bash

cd "$(dirname -- "$0")"

site1="https://example.org"
site2="https://one.one.one.one"
string1="Example Domain"
string2="makes your Internet faster"

tcap="$(mktemp --suffix .pcap)"
keylogfile="$(mktemp)"
tobj="$(mktemp -d)"
tshark -Q -w "$tcap" & tpid=$!
sleep 3

../tlsdump -w "$keylogfile" -- ../test_multiprocess --thread "$site1" "$site2" > /dev/null
cat "$keylogfile"

sleep 3
kill "$tpid"

echo "=== tshark decoded ==="
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" 2>/dev/null
echo "=== HTTP objects ==="
tshark --export-objects http,"$tobj" -o tls.keylog_file:"$keylogfile" -r "$tcap" > /dev/null 2>&1
cat "$tobj"/* 2>/dev/null
echo ""
echo "=== end ==="

failed=0
for string in "$string1" "$string2"; do
	if grep -rq "$string" "$tobj" 2>/dev/null; then
		echo "FOUND: $string"
	elif tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" \
		-Y "http contains \"$string\"" 2>/dev/null | grep -q .; then
		echo "FOUND: $string"
	else
		echo "NOT FOUND: $string"
		failed=$((failed + 1))
	fi
done

test "$failed" = "0" && {
	echo "Test succeeded"
	exit 0
} || {
	echo "Test failed: $failed string(s) not found in decrypted traffic"
	exit 1
}
