#!/bin/bash

# Compile the program
riscv32-unknown-elf-gcc hello.c -o hello

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "Compilation successful, running the program..."
    # Run the executable
    spike --isa=RV32IMAFDC pk hello
else
    echo "Compilation failed, not running the program."
    exit 1
fi