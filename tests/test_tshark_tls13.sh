#!/bin/bash

cd "$(dirname -- "$0")"

# HTTPS site that is fetched.
site="https://example.com"
# String that must be found on the site for the test to be successful.
string="This domain is for use in documentation examples without needing permission."

tcap="$(mktemp --suffix .pcap)"
keylogfile="$(mktemp)"
tshark -Q -w "$tcap" & tpid=$!
sleep 3 # Give tshark some time to set up its capture socket etc.

../tlsdump -w "$keylogfile" -- curl -k --http1.1 "$site" > /dev/null
cat "$keylogfile"

sleep 3 # Give tshark some time to capture the rest
kill "$tpid"

# Use follow stream to verify decrypted content. This is more robust than
# --export-objects which requires ALPN detection from the encrypted handshake.
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" -q -z follow,tls,ascii,0 2>/dev/null | grep -q "$string"

test "$?" = "0" && {
	echo "Test succeeded"
	exit 0
} || {
	echo "Test failed"
	exit 1
}
