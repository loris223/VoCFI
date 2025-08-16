#!/bin/bash

# Exit immediately if any command fails
set -e

# Improved color definitions
RED='\033[0;31m'          # Errors
GREEN='\033[0;32m'        # Success
YELLOW='\033[1;33m'       # Commands/Paths
CYAN='\033[1;36m'         # Info/Headers
MAGENTA='\033[0;35m'      # Special notices
NC='\033[0m'              # No Color


########## CHECKS ############
##############################
check_riscv_env_var(){
    if [ -z "${RISCV+x}" ]; then
        echo "Error: RISCV environment variable is not set."
        exit 1
    fi
}

check_if_folder_exists() {
    local dir_to_check="$1"  # Get the directory from the first argument

    if [ ! -d "$dir_to_check" ]; then
        echo -e "${RED}Error: Directory '$dir_to_check' not found!${NC}" >&2
        exit 1
    fi
}

folder_empty(){
    local dir_path="$1"  # Get directory path from first argument

    # Check if directory is empty
    if [ -z "$(ls -A "$dir_path")" ]; then
        echo -e "${RED}Error: Directory '$dir_path' is empty!${NC}" >&2
        exit 1
    fi
}

##############################
##############################

########### PRINTS ###########
##############################
list_programs() {
    echo -e "${CYAN}Available programs:${NC}"
    for i in "${!PROGRAMS[@]}"; do
        echo -e "${YELLOW}$((i+1)). ${PROGRAMS[i]}${NC}"
    done
}
##############################
##############################


########## USER INPUT ########
##############################
choose_program(){
    list_programs
    read -p "$(echo -e "${CYAN}Select a program (number): ${NC}")" choice
    SELECTION="${PROGRAMS[$((choice-1))]}"
    SELECTED_DIR="${SAMPLE_PROGRAMS_PATH}/$SELECTION"
}
##############################
##############################


######## CONFIGURATION #######
##############################
save_config() {
    cat > "$CONFIG_FILE_PATH" <<EOL
PROGRAM_PATH="$SELECTED_FILE"
EOL
    echo -e "${GREEN}Configuration saved${NC}"
}

detect_main_file(){
    # Detect main file (C or C++)
    SELECTED_FILE=""
    #COMPILER=""
    if [ -f "$SELECTED_DIR/main.c" ]; then
        SELECTED_FILE="$SELECTED_DIR/main.c"
        #COMPILER="riscv32-unknown-elf-gcc"
        echo -e "${MAGENTA}Detected C program.${NC}"
    elif [ -f "$SELECTED_DIR/main.cpp" ]; then
        SELECTED_FILE="$SELECTED_DIR/main.cpp"
        #COMPILER="riscv32-unknown-elf-g++"
        echo -e "${MAGENTA}Detected C++ program.${NC}"
    else
        echo -e "${RED}Error: No main.c or main.cpp found in '$SELECTED_DIR'!${NC}"
        exit 1
    fi
}


configuration_mode() {
    choose_program
    detect_main_file
    save_config
}
##############################
##############################


check_riscv_env_var



CONFIG_FILE_PATH="$RISCV/VoCFI/Conf/vocfi_conf"
check_if_folder_exists $(dirname "$CONFIG_FILE_PATH")

SAMPLE_PROGRAMS_PATH="$RISCV/VoCFI/SamplePrograms"
check_if_folder_exists "$SAMPLE_PROGRAMS_PATH"
folder_empty "$SAMPLE_PROGRAMS_PATH"

PROGRAMS=( $(ls "$SAMPLE_PROGRAMS_PATH"))


# Now that we have done the checks we can actually make configuration
# for our second script
configuration_mode

