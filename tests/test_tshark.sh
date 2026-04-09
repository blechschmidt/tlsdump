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

../tlsdump -w "$keylogfile" -- curl -k --raw --tlsv1.2 --tls-max 1.2 --http1.1 "$site" > /dev/null
cat "$keylogfile"

sleep 3 # Give tshark some time to capture the rest
kill "$tpid"

echo "=== HTTP streams ==="
tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" -q -z follow,tls,ascii,0 2>/dev/null
echo "=== end ==="

tshark -o tls.keylog_file:"$keylogfile" -r "$tcap" \
	-Y "http contains \"$string\"" 2>/dev/null | grep -q .

test "$?" = "0" && {
	echo "Test succeeded"
	exit 0
} || {
	echo "Test failed"
	exit 1
}
