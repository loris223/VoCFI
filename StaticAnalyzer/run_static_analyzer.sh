#!/bin/bash

# Exit immediately if any command fails
set -e

# Configuration file path
CONFIG_FILE="$HOME/.riscv_compiler_config"

# Directory
PROGRAMS_DIRECTORY="../SamplePrograms"

# Improved color definitions
RED='\033[0;31m'          # Errors
GREEN='\033[0;32m'        # Success
YELLOW='\033[1;33m'       # Commands/Paths
CYAN='\033[1;36m'         # Info/Headers
MAGENTA='\033[0;35m'      # Special notices
NC='\033[0m'              # No Color

# Values obtained from config file
DEFAULT_PROGRAM=""
DEFAULT_MODE=0  # 1=compile only, 2=compile and link

# Values obtained from user interface
CHOOSEN_PROGRAM=""
CHOOSEN_MODE=0

# Values used internally
SELECTED_PROGRAM=""
SELECTED_DIR=""
SELECTED_MODE=0

# Script mode
QUICK_MODE=false
CONFIG_MODE=false



########### PRINTS ###########
##############################
list_programs() {
    echo -e "${CYAN}Available programs:${NC}"
    for i in "${!programs[@]}"; do
        echo -e "${YELLOW}$((i+1)). ${programs[i]}${NC}"
    done
}
list_modes(){
    # Normal compilation mode selection
    echo -e "${CYAN}Choose compilation mode:${NC}"
    echo -e "${YELLOW}1. Compile only (object file)${NC}"
    echo -e "${YELLOW}2. Compile and link (executable)${NC}"
}

##############################
##############################




########## USER INPUT ########
##############################
choose_program(){
    list_programs
    read -p "$(echo -e "${CYAN}Select a program (number): ${NC}")" choice
    SELECTED_PROGRAM="${programs[$((choice-1))]}"
    SELECTED_DIR="${PROGRAMS_DIRECTORY}/$selected_program"
}
choose_mode(){
    list_modes
    read -p "$(echo -e "${CYAN}Enter choice (1 or 2): ${NC}")" SELECTED_MODE
}
##############################
##############################





######## CONFIGURATION #######
##############################
# Load or initialize config
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        echo -e "${MAGENTA}Loaded config from $CONFIG_FILE${NC}"
    else
        echo -e "${YELLOW}No config found, set config${NC}"
        exit 1
    fi
}

# Save config
save_config() {
    cat > "$CONFIG_FILE" <<EOL
DEFAULT_PROGRAM="$SELECTED_PROGRAM"
DEFAULT_MODE=$SELECTED_MODE
EOL
    echo -e "${GREEN}Configuration saved${NC}"
}

# Reset config
reset_config() {
    rm -f "$CONFIG_FILE"
    echo -e "${GREEN}Configuration reset${NC}"
    exit 0
}

configuration_mode() {
    choose_program
    choose_mode
    save_config
}

check_config_params(){
    if [[ ! " ${programs[@]} " =~ " ${DEFAULT_PROGRAM} " ]]; then
        echo -e "${RED}Error: Default program '$DEFAULT_PROGRAM' not found!${NC}"
        exit 1
    fi
}
##############################
##############################





########### ARGS #############
##############################
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -q|--quick)
                QUICK_MODE=true
                shift
                ;;
            -c|--config)
                CONFIG_MODE=true
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                exit 1
                ;;
        esac
    done
}

detect_main_file(){
    # Detect main file (C or C++)
    main_file=""
    if [ -f "$program_dir/main.c" ]; then
        main_file="$program_dir/main.c"
        compiler="riscv32-unknown-elf-gcc"
        echo -e "${MAGENTA}Detected C program.${NC}"
    elif [ -f "$program_dir/main.cpp" ]; then
        main_file="$program_dir/main.cpp"
        compiler="riscv32-unknown-elf-g++"
        echo -e "${MAGENTA}Detected C++ program.${NC}"
    else
        echo -e "${RED}Error: No main.c or main.cpp found in '$selected_program'!${NC}"
        exit 1
    fi
}
##############################
##############################






########## CHECKS ############
##############################
check_if_folder_exists(){
    if [ ! -d $PROGRAMS_DIRECTORY ]; then
        echo -e "${RED}Error: '${PROGRAMS_DIRECTORY}' directory not found!${NC}"
        exit 1
    fi
}

folder_empty(){
    if [ ${#programs[@]} -eq 0 ]; then
        echo -e "${RED}Error: No programs found in ${PROGRAMS_DIRECTORY}!${NC}"
        exit 1
    fi
}
##############################
##############################




########### EXECUTE ##########
##############################
execute_(){
    case $SELECTED_MODE in
        1)
            echo -e "${CYAN}Compiling $main_file...${NC}"
            $compiler -c "$main_file" -o "$output_name.o"
            echo -e "${GREEN}Success! Object file: ${YELLOW}$output_name.o${NC}"
            target="$output_name.o"
            ;;
        2)
            echo -e "${CYAN}Compiling and linking $main_file...${NC}"
            $compiler "$main_file" -o "$output_name"
            echo -e "${GREEN}Success! Executable: ${YELLOW}$output_name${NC}"
            target="$output_name"
            ;;
        *)
            echo -e "${RED}Error: Invalid mode selected!${NC}"
            exit 1
            ;;
    esac
}
##############################
##############################


# Parse arguments
parse_args $@

# Check if SamplePrograms folder exists
check_if_folder_exists

# Get all programs
programs=( $(ls ../SamplePrograms) )

# Check if folder is empty
folder_empty

if [ "$CONFIG_MODE" = true ]; then
    configuration_mode
    exit 0
elif [ "$QUICK_MODE" = true ]; then
    load_config
    check_config_params
    # Set variables for execution
    SELECTED_PROGRAM=$DEFAULT_PROGRAM
    SELECTED_MODE=$DEFAULT_MODE
    program_dir="${PROGRAMS_DIRECTORY}/$SELECTED_PROGRAM"
    output_name="${program_dir}/${SELECTED_PROGRAM}"
    detect_main_file
    execute_

else
    choose_program
    choose_mode
    program_dir="${PROGRAMS_DIRECTORY}/$SELECTED_PROGRAM"
    output_name="${program_dir}/${SELECTED_PROGRAM}"
    detect_main_file
    execute_
fi









# Run Python analyzer
if [ -f "analyzer.py" ]; then
    echo -e "${CYAN}Running analyzer on ${YELLOW}$target${CYAN}...${NC}"
    python3 analyzer.py "$target"
else
    echo -e "${RED}Error: analyzer.py not found!${NC}"
    exit 1
fi

