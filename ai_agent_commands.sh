#!/bin/bash
# ai_agent_commands.sh - Example script to request code improvement suggestions from an AI service

set -euo pipefail

: "${OPENAI_API_KEY:?Environment variable OPENAI_API_KEY must be set}" >/dev/null

PROMPT_FILE=${1:-prompt.txt}

if [ ! -f "$PROMPT_FILE" ]; then
    echo "Prompt file $PROMPT_FILE not found" >&2
    exit 1
fi

curl -s https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d @"$PROMPT_FILE"
