#!/bin/bash

cd "$(dirname -- "$0")"

site="https://example.com"
keylogfile="$(mktemp)"

../tlsdump -w "$keylogfile" -- ../test_multiprocess --fork "$site" > /dev/null

echo "=== tlsdump keylog ==="
cat "$keylogfile"

# Count unique client randoms to verify we captured distinct connections.
unique_connections=$(awk '{print $2}' "$keylogfile" | sort -u | wc -l)
echo "Unique connections: $unique_connections"

test "$unique_connections" -ge 2 && {
	echo "Test succeeded"
	exit 0
} || {
	echo "Test failed: expected at least 2 connections, got $unique_connections"
	exit 1
}
