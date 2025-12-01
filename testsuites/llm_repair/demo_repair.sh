#!/bin/bash

# Quick LLM Repair Demo - Syntax checking only
# Usage: ./demo_repair.sh <file.cc> [max_retries]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ $# -lt 1 ]; then
    echo "Usage: $0 <file.cc> [max_retries]"
    echo "Example: $0 missing_semicolon.cc 3"
    exit 1
fi

cd /PromptFuzz

INPUT_FILE="$1"
MAX_RETRIES="${2:-3}"

# Resolve full path
if [ -f "testsuites/llm_repair/$INPUT_FILE" ]; then
    SOURCE_FILE="testsuites/llm_repair/$INPUT_FILE"
elif [ -f "$INPUT_FILE" ]; then
    SOURCE_FILE="$INPUT_FILE"
else
    echo -e "${RED}File not found: $INPUT_FILE${NC}"
    exit 1
fi

# Work in /tmp
WORK_DIR="/tmp/llm_demo_$$"
mkdir -p "$WORK_DIR"
trap "rm -rf $WORK_DIR" EXIT

WORK_FILE="$WORK_DIR/$(basename $SOURCE_FILE)"
cp "$SOURCE_FILE" "$WORK_FILE"

# Get include path for cJSON
INCLUDE_PATH="-I$(pwd)/output/cJSON/build/include"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}LLM Repair Demo${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "File: ${YELLOW}$SOURCE_FILE${NC}"
echo -e "Max retries: ${YELLOW}$MAX_RETRIES${NC}"
echo ""

echo -e "${CYAN}--- Original Code ---${NC}"
cat "$WORK_FILE"
echo ""

# Function to check syntax
check_syntax() {
    clang++ -fsyntax-only $INCLUDE_PATH "$1" 2>&1
}

# Initial syntax check
echo -e "${CYAN}--- Initial Syntax Check ---${NC}"
SYNTAX_ERROR=$(check_syntax "$WORK_FILE") || true

if [ -z "$SYNTAX_ERROR" ]; then
    echo -e "${GREEN}✓ No syntax errors!${NC}"
    exit 0
fi

echo -e "${RED}Syntax errors found:${NC}"
echo "$SYNTAX_ERROR" | head -10
echo ""

# Check for API key
if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${RED}No API key set. Set OPENAI_API_KEY or ANTHROPIC_API_KEY${NC}"
    exit 1
fi

# Repair loop
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_RETRIES ]; do
    ATTEMPT=$((ATTEMPT + 1))
    echo -e "${YELLOW}🔧 Attempting LLM repair (attempt $ATTEMPT/$MAX_RETRIES)...${NC}"
    
    # Read current code
    CURRENT_CODE=$(cat "$WORK_FILE")
    
    # Truncate error if too long
    TRUNCATED_ERROR=$(echo "$SYNTAX_ERROR" | head -20)
    
    # Build prompt
    PROMPT="The following C++ fuzzer code has a syntax error. Please fix it and return ONLY the corrected code without any explanation, comments, or markdown formatting.

Syntax Error:
$TRUNCATED_ERROR

Code to fix:
$CURRENT_CODE

Return ONLY the complete fixed C++ code."

    # Call API
    if [ -n "$ANTHROPIC_API_KEY" ]; then
        echo "   Using Claude API..."
        RESPONSE=$(curl -s --max-time 60 https://api.anthropic.com/v1/messages \
            -H "Content-Type: application/json" \
            -H "x-api-key: $ANTHROPIC_API_KEY" \
            -H "anthropic-version: 2023-06-01" \
            -d "$(jq -n --arg prompt "$PROMPT" '{
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": $prompt}]
            }')")
        
        # Extract code from response
        FIXED_CODE=$(echo "$RESPONSE" | jq -r '.content[0].text // empty')
    else
        echo "   Using OpenAI API..."
        RESPONSE=$(curl -s --max-time 60 https://api.openai.com/v1/chat/completions \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            -d "$(jq -n --arg prompt "$PROMPT" '{
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": $prompt}],
                "temperature": 0.3
            }')")
        
        # Extract code from response
        FIXED_CODE=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty')
    fi
    
    # Check for API error
    if [ -z "$FIXED_CODE" ]; then
        echo -e "${RED}   API returned empty response${NC}"
        echo "   Response: $RESPONSE"
        continue
    fi
    
    # Remove markdown code blocks if present
    FIXED_CODE=$(echo "$FIXED_CODE" | sed -n '/^```/,/^```/{/^```/d;p}' | head -n -0)
    if [ -z "$FIXED_CODE" ]; then
        # No code blocks, use as-is
        FIXED_CODE=$(echo "$RESPONSE" | jq -r '.content[0].text // .choices[0].message.content // empty')
        # Try to strip ```cpp or ``` markers
        FIXED_CODE=$(echo "$FIXED_CODE" | sed 's/^```cpp//;s/^```c++//;s/^```//;s/```$//')
    fi
    
    # Write fixed code
    echo "$FIXED_CODE" > "$WORK_FILE"
    
    echo -e "   ${GREEN}LLM provided fix ($(wc -c < "$WORK_FILE") bytes)${NC}"
    
    # Check syntax again
    echo -e "${CYAN}--- Checking fixed code ---${NC}"
    SYNTAX_ERROR=$(check_syntax "$WORK_FILE") || true
    
    if [ -z "$SYNTAX_ERROR" ]; then
        echo -e "${GREEN}✓ Syntax FIXED after $ATTEMPT attempt(s)!${NC}"
        echo ""
        echo -e "${CYAN}--- Fixed Code ---${NC}"
        cat "$WORK_FILE"
        exit 0
    else
        echo -e "${RED}Still has errors:${NC}"
        echo "$SYNTAX_ERROR" | head -5
        echo ""
    fi
done

echo -e "${RED}✗ Failed to fix after $MAX_RETRIES attempts${NC}"
exit 1
