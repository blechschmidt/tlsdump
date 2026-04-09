#!/bin/bash

cd "$(dirname -- "$0")"

# HTTPS site that is fetched.
site="https://example.com"

tcap="$(mktemp --suffix .pcap)"
keylogfile="$(mktemp)"
tshark -Q -w "$tcap" & tpid=$!
sleep 3 # Give tshark some time to set up its capture socket etc.

../tlsdump -w "$keylogfile" -- curl -k --http1.1 "$site" > /dev/null
cat "$keylogfile"

sleep 3 # Give tshark some time to capture the rest
kill "$tpid"

# Show tshark version and decoded output for debugging CI failures.
echo "=== tshark version ==="
tshark --version 2>/dev/null | head -1
echo "=== tshark decoded output (without keys) ==="
tshark -r "$tcap" 2>/dev/null | head -30
echo "=== tshark decoded output (with keys) ==="
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" 2>/dev/null | head -30
echo "=== end ==="

# Verify that tshark can decrypt the TLS 1.3 traffic. Try multiple methods
# for compatibility across tshark versions.
# Method 1: Check for HTTP protocol detection after decryption.
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" -Y "http" 2>/dev/null | grep -q "HTTP" && {
	echo "Test succeeded"
	exit 0
}
# Method 2: Check if decryption reduces the number of opaque "Application Data"
# records (decrypted ones become their inner protocol).
without=$(tshark -r "$tcap" 2>/dev/null | grep -c "Application Data")
with=$(tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" 2>/dev/null | grep -c "Application Data")
test "$with" -lt "$without" && {
	echo "Test succeeded (decryption verified: Application Data count $without -> $with)"
	exit 0
}

echo "Test failed"
exit 1
