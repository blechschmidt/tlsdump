#!/bin/bash

cd "$(dirname -- "$0")"

# HTTPS site that is fetched.
site="https://example.com"

curl_keylogfile="$(mktemp)"
tlsdump_keylogfile="$(mktemp)"

# Testing the test
SSLKEYLOGFILE="$curl_keylogfile" ../tlsdump -w "$tlsdump_keylogfile" -- curl --tlsv1.2 --tls-max 1.2 --http1.1 "$site" > /dev/null
echo "=== CURL KEYLOG ==="
cat "$curl_keylogfile"

echo "=== TLSDUMP KEYLOG ==="
cat "$tlsdump_keylogfile"

diff "$curl_keylogfile" "$tlsdump_keylogfile"

test "$?" = "0" && {
	echo "Test succeeded"
	exit 0
} || {
	echo "Test failed"
	exit 1
}
