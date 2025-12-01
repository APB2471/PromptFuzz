#!/bin/bash

# DON'T use set -e because we expect some commands to fail

cd /PromptFuzz

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TEST_DIR="testsuites/llm_repair"
LIBRARY="cJSON"

# Check for API key
if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${RED}ERROR: No API key set. Set OPENAI_API_KEY or ANTHROPIC_API_KEY${NC}"
    exit 1
fi

echo "=========================================="
echo "LLM Repair Test Suite"
echo "=========================================="
echo ""

# Test files and expected results
declare -A TEST_FILES
TEST_FILES["missing_semicolon.cc"]="should_fix"
TEST_FILES["missing_brace.cc"]="should_fix"
TEST_FILES["typo_keyword.cc"]="should_fix"
TEST_FILES["wrong_signature.cc"]="should_fix"
TEST_FILES["unmatched_parens.cc"]="should_fix"
TEST_FILES["missing_type.cc"]="should_fix"
TEST_FILES["multiple_errors.cc"]="should_fix"
TEST_FILES["valid_program.cc"]="already_valid"

PASSED=0
FAILED=0

echo "=== Phase 1: Testing WITHOUT Repair (baseline) ==="
echo ""

for file in "${!TEST_FILES[@]}"; do
    echo -n "Testing $file (no repair): "
    
    # Copy file to work directory to avoid modifying original
    cp "$TEST_DIR/$file" "/tmp/test_$file"
    
    # Use || true to prevent script from exiting on failure
    if cargo run -q --bin harness -- $LIBRARY check "/tmp/test_$file" --max-retries 0 2>/dev/null; then
        if [ "${TEST_FILES[$file]}" == "already_valid" ]; then
            echo -e "${GREEN}PASS${NC} (valid, as expected)"
            ((PASSED++))
        else
            echo -e "${YELLOW}UNEXPECTED${NC} (passed without repair)"
        fi
    else
        if [ "${TEST_FILES[$file]}" == "should_fix" ]; then
            echo -e "${GREEN}PASS${NC} (failed, as expected)"
            ((PASSED++))
        else
            echo -e "${RED}FAIL${NC} (should have passed)"
            ((FAILED++))
        fi
    fi
    
    rm -f "/tmp/test_$file"
done

echo ""
echo "Phase 1 complete: $PASSED passed, $FAILED failed"
echo ""

echo "=== Phase 2: Testing WITH Repair (3 retries) ==="
echo ""

REPAIR_PASSED=0
REPAIR_FAILED=0

for file in "${!TEST_FILES[@]}"; do
    echo "Testing $file (with repair):"
    
    # Copy file to work directory
    cp "$TEST_DIR/$file" "/tmp/test_$file"
    
    # Run repair and capture output (use || true to continue on failure)
    RUST_LOG=info cargo run -q --bin harness -- $LIBRARY check "/tmp/test_$file" --max-retries 3 2>&1 | tee /tmp/repair_log.txt || true
    
    # Check if repair was mentioned in logs
    if grep -q "Syntax FIXED\|LLM repair\|Attempting LLM" /tmp/repair_log.txt 2>/dev/null; then
        echo -e "  ${YELLOW}REPAIR ATTEMPTED${NC}"
        grep -E "FIXED|repair|Attempting" /tmp/repair_log.txt | head -3 | sed 's/^/    /'
    fi
    
    # Check final result (use || true)
    if cargo run -q --bin harness -- $LIBRARY check "/tmp/test_$file" --max-retries 0 2>/dev/null; then
        echo -e "  Result: ${GREEN}PASS${NC} (syntax check passed)"
        ((REPAIR_PASSED++))
        
        # Show the fixed code if it was repaired
        if [ "${TEST_FILES[$file]}" == "should_fix" ]; then
            echo "  Fixed code preview:"
            head -20 "/tmp/test_$file" | sed 's/^/    /'
        fi
    else
        if [ "${TEST_FILES[$file]}" == "should_fix" ]; then
            echo -e "  Result: ${RED}FAIL${NC} (repair unsuccessful)"
            ((REPAIR_FAILED++))
        else
            echo -e "  Result: ${GREEN}PASS${NC} (already valid)"
            ((REPAIR_PASSED++))
        fi
    fi
    
    rm -f "/tmp/test_$file"
    echo ""
done

TOTAL_PASSED=$((PASSED + REPAIR_PASSED))
TOTAL_FAILED=$((FAILED + REPAIR_FAILED))

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Phase 1 (baseline): $PASSED passed, $FAILED failed"
echo "Phase 2 (repair):   $REPAIR_PASSED passed, $REPAIR_FAILED failed"
echo ""
echo -e "Total Passed: ${GREEN}$TOTAL_PASSED${NC}"
echo -e "Total Failed: ${RED}$TOTAL_FAILED${NC}"
echo ""

if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
