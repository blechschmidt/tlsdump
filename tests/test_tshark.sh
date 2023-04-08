#!/bin/bash

cd "$(dirname -- "$0")"

# HTTPS site that is fetched. 
site="https://example.com"
# String that must be found on the site for the test to be successful.
string="This domain is for use in illustrative examples in documents."

tcap="$(mktemp --suffix .pcap)"
keylogfile="$(mktemp)"
tobj="$(mktemp -d)"
tshark -Q -w "$tcap" & tpid=$!
sleep 3 # Give tshark some time to set up its capture socket etc.

# Testing the test
# SSLKEYLOGFILE="$keylogfile" curl --tlsv1.2 --tls-max 1.2 --http1.1 "$site" > /dev/null
../tlsdump -w "$keylogfile" -- curl --tlsv1.2 --tls-max 1.2 --http1.1 "$site" > /dev/null
cat "$keylogfile"

sleep 3 # Give tshark some time to capture the rest
kill "$tpid"
tshark --export-objects http,"$tobj" -o tls.keylog_file:"$keylogfile" -r "$tcap" > /dev/null
grep -r "$string" "$tobj" > /dev/null

test "$?" = "0" && {
	echo "Test succeeded"
	exit 0
} || {
	echo "Test failed"
	exit 1
}
