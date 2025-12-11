#!/bin/bash

# Set colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[0;31m'
MAGENTA='\033[1;35m'
NC='\033[0m' # No Color


# Check if file path was provided
if [ $# -eq 0 ]; then
    TARGET_FILE="$DEFAULT_FILE"
    echo -e "${RED}No file path provided.${NC}"
    exit 1
else
    TARGET_FILE="$1"
    echo -e "${CYAN}Using provided file path: ${YELLOW}$TARGET_FILE${NC}"
fi

# Verify the file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo -e "${RED}Error: File ${YELLOW}$TARGET_FILE${RED} does not exist${NC}"
    exit 1
fi

# Get the start address of main (formatted as 8-digit hex)
echo -e "${CYAN}Running: ${YELLOW}r2 -qc 'aaaa; s main; s' $TARGET_FILE 2>/dev/null${NC}"
RAW_START_ADDR=$(r2 -qc 'aaaa; s main; s' "$TARGET_FILE" 2>/dev/null)
SNIFFER_START_ADDR=$(printf "0x%08x" "$RAW_START_ADDR")  # Force 8-digit hex format
echo -e "${CYAN}Main function start address: ${YELLOW}$SNIFFER_START_ADDR${NC}"

# Get the size of main (formatted as 8-digit hex)
echo -e "${CYAN}Running: ${YELLOW}r2 -qc 'aaaa; afi main~size[1]' $TARGET_FILE 2>/dev/null${NC}"
RAW_FUN_SIZE=$(r2 -qc 'aaaa; afi main~size[1]' "$TARGET_FILE" 2>/dev/null)
SNIFFER_FUN_SIZE=$(printf "0x%08x" "$RAW_FUN_SIZE")  # Force 8-digit hex format
echo -e "${CYAN}Main function size: ${YELLOW}$SNIFFER_FUN_SIZE${CYAN} bytes${NC}"

# Calculate end address (formatted as 8-digit hex)
SNIFFER_END_ADDR=$(printf "0x%08x" $((RAW_START_ADDR + RAW_FUN_SIZE)))
echo -e "${CYAN}Calculated main function end address: ${YELLOW}$SNIFFER_END_ADDR${NC}"

# Export the environment variables
export SNIFFER_START_ADDR
export SNIFFER_END_ADDR
export SNIFFER_FUN_SIZE

LAST_FOLDER=$(basename $(dirname "$TARGET_FILE"))
if [ "$LAST_FOLDER" = "Attack" ]; then
    SNIFFER_FOLLOW_FUNS=1
    export SNIFFER_FOLLOW_FUNS
    SNIFFER_BANNED_ADDRS="0x101ec, 0x10208"
    export SNIFFER_BANNED_ADDRS
fi

echo -e "${CYAN}Environment variables set:${NC}"
echo -e "${MAGENTA}SNIFFER_START_ADDR${NC}=${YELLOW}$SNIFFER_START_ADDR${NC}"
echo -e "${MAGENTA}SNIFFER_END_ADDR${NC}=${YELLOW}$SNIFFER_END_ADDR${NC}"
echo -e "${MAGENTA}SNIFFER_FUN_SIZE${NC}=${YELLOW}$SNIFFER_FUN_SIZE${NC}"