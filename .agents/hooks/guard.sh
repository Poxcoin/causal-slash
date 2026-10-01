#!/usr/bin/env bash
# Antigravity Autonomous Security Guard
IN=$(cat)

# Block destructive commands and credential leakage
if echo "$IN" | grep -Eqi 'rm -rf /|\.env|push --force|--force push|private[_-]?key|DROP TABLE|mkfs'; then
  echo '{"decision":"deny","reason":"[SECURITY GUARD] Blocked dangerous command pattern or secret leakage."}'
else
  echo '{"decision":"allow"}'
fi
exit 0
