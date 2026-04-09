#!/bin/bash

cd "$(dirname -- "$0")"

# HTTPS site that is fetched.
site="https://example.com"
# String that must be found on the site for the test to be successful.
string="documentation examples"

tcap="$(mktemp --suffix .pcap)"
keylogfile="$(mktemp)"
tshark -Q -w "$tcap" & tpid=$!
sleep 3 # Give tshark some time to set up its capture socket etc.

../tlsdump -w "$keylogfile" -- curl -k --raw --http1.1 "$site" > /dev/null
cat "$keylogfile"

sleep 3 # Give tshark some time to capture the rest
kill "$tpid"

echo "=== HTTP streams ==="
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" -q -z follow,tls,ascii,0 2>/dev/null
echo "=== end ==="

# Verify that tshark can decrypt the TLS 1.3 traffic and find the page content.
# The "http contains" display filter searches within the decoded HTTP protocol
# layer and works portably across tshark versions (unlike --export-objects or
# -z follow which may not support TLS 1.3 with only traffic secrets).
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" \
	-Y "http contains \"$string\"" 2>/dev/null | grep -q .

test "$?" = "0" && {
	echo "Test succeeded"
	exit 0
} || {
	echo "Test failed"
	exit 1
}
