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

# Verify that tshark can decrypt the TLS 1.3 traffic and sees HTTP inside.
# Using a display filter is more portable across tshark versions than
# --export-objects or -z follow (which need ALPN from the encrypted handshake).
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" -Y "http" 2>/dev/null | grep -q "HTTP"

test "$?" = "0" && {
	echo "Test succeeded"
	exit 0
} || {
	echo "Test failed"
	exit 1
}
