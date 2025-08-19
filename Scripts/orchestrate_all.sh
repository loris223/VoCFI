#!/bin/bash

# Improved color definitions
RED='\033[0;31m'          # Errors
GREEN='\033[0;32m'        # Success
YELLOW='\033[1;33m'       # Commands/Paths
CYAN='\033[1;36m'         # Info/Headers
MAGENTA='\033[1;35m'      # Special notices
BLUE='\033[0;34m'
NC='\033[0m'              # No Color


CONFIGURATION_MODE=false
DISPLAY_SOURCE_CODE=true
SHOW_BINARY=false


print_top_sign(){
    local header_text="$1"
    echo -e "${GREEN}"
    printf '=%.0s' {1..60}  # Top border
    echo -e "\n=============== $header_text ==============="
    printf '=%.0s' {1..60}  # Bottom border
    echo -e "${NC}\n"
}

print_bottom_sign(){
    local bottom_text="$1"
    echo -e "\n${GREEN}"
    printf '=%.0s' {1..60}  # Closing border
    echo -e " End of $bottom_text ${NC}"
}

check_riscv_env_var(){
    if [ -z "${RISCV+x}" ]; then
        echo -e "${RED}Error: RISCV environment variable is not set."
        exit 1
    else
        echo -e "${CYAN}RISCV is set to: ${YELLOW}$RISCV"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIGURATION_MODE=true
                shift
                ;;
            --display-source)
                DISPLAY_SOURCE_CODE=true
                shift
                ;;
            --show-binary)
                SHOW_BINARY=true
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                exit 1
                ;;
        esac
    done
}

load_config() {
    if [ -f "$CONFIG_FILE_PATH" ]; then
        source "$CONFIG_FILE_PATH"
        echo -e "${CYAN}Loaded config from ${YELLOW}$CONFIG_FILE_PATH${NC}"
    else
        echo -e "${YELLOW}No config found, set config${NC}"
        exit 1
    fi
}

# RISCV environment variable should be set
# All paths used are based on #RISCV
check_riscv_env_var
CONFIG_FILE_PATH="$RISCV/VoCFI/Conf/vocfi_conf"

# Parse arguments
parse_args $@

# Based on arguments call configuration script
if [ "$CONFIGURATION_MODE" = true ]; then
    "$RISCV/VoCFI/Scripts/conf_script.sh"
fi

# Now load configuration
if [ -f "$CONFIG_FILE_PATH" ]; then
    load_config
else
# If one can't access the file then call configuration
    "$RISCV/VoCFI/Scripts/conf_script.sh"
    load_config
fi

# Now we have all information to proceed.
# We should have:
# $PROGRAM_PATH


# First display source if set
if [ "$DISPLAY_SOURCE_CODE" = true ]; then
    print_top_sign "SOURCE CODE"
    
    cat "$PROGRAM_PATH"
    
    print_bottom_sign "SOURCE CODE"
fi

# Now we go to compilation
COMPILATION_SCRIPT_PATH="$RISCV/VoCFI/Scripts/compilation_script.sh"
COMPILATION_TEXT="COMPILING SOURCE CODE"
print_top_sign "$COMPILATION_TEXT"
echo -e "${CYAN}Compiling ${YELLOW}$PROGRAM_PATH${NC}" >&2
COMPILED_BIN=$("$COMPILATION_SCRIPT_PATH" "$PROGRAM_PATH")
if [ $? -ne 0 ]; then
    echo -e "${RED}Compilation failed! Aborting.${NC}" >&2
    exit 1
fi
print_bottom_sign "$COMPILATION_TEXT"
# echo -e "${GREEN}Compilation successful: ${YELLOW}$COMPILED_BIN${NC}" >&2

# Show compiled binary
# Probably just start radare2 in a seprate terminal
# Nah just display command if one wants to check it
#if [ "$SHOW_BINARY" = true ]; then
echo -e "${CYAN}If you want to inspect executable in radare2(toggle view with p):${NC}" >&2
echo -e "${MAGENTA}r2 -c 'aaa; s main; V;' $COMPILED_BIN${NC}" >&2
echo -e "${CYAN}If you want to see  radare2 control flow graph:${NC}" >&2
echo -e "${MAGENTA}r2 -c 'aaa; s main; agf;' $COMPILED_BIN${NC}" >&2
#fi


# Static Analyzer
STATIC_ANALYZER_PATH="$RISCV/VoCFI/StaticAnalyzer/analyzer.py"
STATIC_ANALYZER_TEXT="STATIC ANALYZER"
print_top_sign "$STATIC_ANALYZER_TEXT"
if [ -f "$STATIC_ANALYZER_PATH" ]; then
    echo -e "${CYAN}Running analyzer on ${YELLOW}$COMPILED_BIN${CYAN}...${NC}"
    python3 "$STATIC_ANALYZER_PATH" "$COMPILED_BIN"
else
    echo -e "${RED}Error: analyzer.py not found!${NC}"
    exit 1
fi

print_bottom_sign "$STATIC_ANALYZER_TEXT"


# Extract addresses script
EXTRACTION_SCRIPT_PATH="$RISCV/VoCFI/Scripts/extract_addresses.sh"
EXTRACTION_TEXT="EXTRACTING FUNCTION ADDRESSES"
print_top_sign "$EXTRACTION_TEXT"
#echo -e "${BLUE}=== Extracting function addresses ===${NC}" >&2
source "$EXTRACTION_SCRIPT_PATH" "$COMPILED_BIN" || {
    echo -e "${RED}Address extraction failed! Aborting.${NC}" >&2
    exit 1
}
print_bottom_sign "$EXTRACTION_TEXT"


# Spike run script
SPIKE_SCRIPT_PATH="$RISCV/VoCFI/Scripts/spike_run_script.sh"
SPIKE_TEXT="SPIKE"
print_top_sign "$SPIKE_TEXT"
#echo -e "${BLUE}=== Running with Spike ===${NC}" >&2
"$SPIKE_SCRIPT_PATH" "$COMPILED_BIN" || {
    echo -e "${RED}Execution failed!${NC}" >&2
    exit 1
}
print_bottom_sign "$SPIKE_TEXT"
