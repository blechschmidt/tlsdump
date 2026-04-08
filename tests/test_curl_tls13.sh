#!/bin/bash

cd "$(dirname -- "$0")"

# HTTPS site that is fetched.
site="https://example.com"

curl_keylogfile="$(mktemp)"
tlsdump_keylogfile="$(mktemp)"

SSLKEYLOGFILE="$curl_keylogfile" ../tlsdump -w "$tlsdump_keylogfile" -- curl -k --http1.1 "$site" > /dev/null
echo "=== CURL KEYLOG ==="
cat "$curl_keylogfile"

echo "=== TLSDUMP KEYLOG ==="
cat "$tlsdump_keylogfile"

# For TLS 1.3, we expect CLIENT_TRAFFIC_SECRET_0 and SERVER_TRAFFIC_SECRET_0
# Handshake secrets may not be found because the TLS library zeroes them after key rotation.
curl_client_traffic=$(grep CLIENT_TRAFFIC_SECRET_0 "$curl_keylogfile" | awk '{print $3}')
tlsdump_client_traffic=$(grep CLIENT_TRAFFIC_SECRET_0 "$tlsdump_keylogfile" | awk '{print $3}')

curl_server_traffic=$(grep SERVER_TRAFFIC_SECRET_0 "$curl_keylogfile" | awk '{print $3}')
tlsdump_server_traffic=$(grep SERVER_TRAFFIC_SECRET_0 "$tlsdump_keylogfile" | awk '{print $3}')

if [ -z "$tlsdump_client_traffic" ] || [ -z "$tlsdump_server_traffic" ]; then
	echo "Test failed: TLS 1.3 traffic secrets not found by tlsdump"
	exit 1
fi

if [ "$curl_client_traffic" = "$tlsdump_client_traffic" ] && [ "$curl_server_traffic" = "$tlsdump_server_traffic" ]; then
	echo "Test succeeded: TLS 1.3 traffic secrets match"
	exit 0
else
	echo "Test failed: TLS 1.3 traffic secrets do not match"
	exit 1
fi
