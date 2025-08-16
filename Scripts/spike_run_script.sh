#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default executable (matches previous script's output)
DEFAULT_EXE="/opt/tmp/hello"

# Argument handling
if [ $# -eq 0 ]; then
    EXE_PATH="$DEFAULT_EXE"
    echo -e "${YELLOW}No executable provided, using default: ${GREEN}$EXE_PATH${NC}" >&2
else
    EXE_PATH="$1"
fi

# Verify the file exists and is executable
if [ ! -f "$EXE_PATH" ]; then
    echo -e "${RED}Error: File ${YELLOW}$EXE_PATH${RED} does not exist${NC}" >&2
    exit 1
elif [ ! -x "$EXE_PATH" ]; then
    echo -e "${RED}Error: File ${YELLOW}$EXE_PATH${RED} is not executable${NC}" >&2
    exit 1
fi

# Run spike
echo -e "${CYAN}Executing: ${YELLOW}spike --isa=RV32IMAFDC pk \"$EXE_PATH\"${NC}" >&2
spike --isa=RV32IMAFDC pk "$EXE_PATH"

# Check exit status
if [ $? -eq 0 ]; then
    echo -e "${CYAN}Execution completed successfully${NC}" >&2
else
    echo -e "${RED}Execution failed${NC}" >&2
    exit 1
fi