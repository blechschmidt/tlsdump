#!/bin/bash

cd "$(dirname -- "$0")"

site="https://example.com"
string="This domain is for use in documentation examples without needing permission."

dumpdir="$(mktemp -d)"
tcap="$(mktemp --suffix .pcap)"
keylogfile="$(mktemp)"
tobj="$(mktemp -d)"

# Stage 1: Capture (fast - no memory search)
tshark -Q -w "$tcap" & tpid=$!
sleep 3
../tlsdump --defer "$dumpdir" -- curl -k -H "Accept-Encoding: identity" --http1.1 "$site" > /dev/null
sleep 3
kill "$tpid"

echo "=== Dump files ==="
ls -la "$dumpdir"

# Stage 2: Extract (offline key search)
../tlsdump --extract "$dumpdir" -w "$keylogfile"

echo "=== Extracted keylog ==="
cat "$keylogfile"

# Verify decryption with tshark
tshark --export-objects http,"$tobj" -o tls.keylog_file:"$keylogfile" -r "$tcap" > /dev/null 2>&1
if grep -rq "$string" "$tobj" 2>/dev/null; then
	echo "Test succeeded"
	exit 0
fi
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" \
	-Y "http contains \"$string\"" 2>/dev/null | grep -q . && {
	echo "Test succeeded"
	exit 0
}

echo "Test failed"
exit 1
