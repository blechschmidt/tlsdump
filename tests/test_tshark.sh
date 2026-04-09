#!/bin/bash

cd "$(dirname -- "$0")"

# HTTPS site that is fetched.
site="https://example.com"
# String that must be found on the site for the test to be successful.
string="documentation examples"

tcap="$(mktemp --suffix .pcap)"
keylogfile="$(mktemp)"
tobj="$(mktemp -d)"
tshark -Q -w "$tcap" & tpid=$!
sleep 3 # Give tshark some time to set up its capture socket etc.

# Use --no-compressed and explicit Accept-Encoding to ensure uncompressed content on the wire.
../tlsdump -w "$keylogfile" -- curl -k -H "Accept-Encoding: identity" --tlsv1.2 --tls-max 1.2 --http1.1 "$site" > /dev/null
cat "$keylogfile"

sleep 3 # Give tshark some time to capture the rest
kill "$tpid"

echo "=== tshark decoded ==="
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" 2>/dev/null
echo "=== HTTP objects ==="
tshark --export-objects http,"$tobj" -o tls.keylog_file:"$keylogfile" -r "$tcap" > /dev/null 2>&1
cat "$tobj"/* 2>/dev/null
echo ""
echo "=== end ==="

grep -rq "$string" "$tobj" && {
	echo "Test succeeded"
	exit 0
}

tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" \
	-Y "http contains \"$string\"" 2>/dev/null | grep -q . && {
	echo "Test succeeded"
	exit 0
}

echo "Test failed"
exit 1
