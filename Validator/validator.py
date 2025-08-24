"""
TODO
This is the final file that should be ran. It
should get the output of analyzer and output
of Spike. It should compare those two outputs
and decide its correctnes
"""

import os

def validate_sniffer_output():
    # Get the RISCV environment variable
    riscv_path = os.getenv('RISCV')
    if not riscv_path:
        print("Error: RISCV environment variable is not set")
        return False
    
    # Read the analyzer output (allowed hashes)
    analyzer_file = os.path.join(riscv_path, 'analyzer_output')
    try:
        with open(analyzer_file, 'r') as f:
            analyzer_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {analyzer_file} not found")
        return False
    
    # Read the sniffer output (hashes to validate)
    sniffer_file = os.path.join(riscv_path, 'sniffer_output')
    try:
        with open(sniffer_file, 'r') as f:
            sniffer_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {sniffer_file} not found")
        return False
    
    # Extract all valid hashes from analyzer_output
    valid_loop_hashes = set()
    valid_path_hashes = set()
    change = False
    for line in analyzer_lines:
        line = line.strip()
        if line == 'LOOPS':
            continue
        elif line == 'PATHS':
            change = True
            continue
        if not change:
            valid_loop_hashes.add(line)
        else:
            valid_path_hashes.add(line)
    
    #print(valid_loop_hashes)
    #print(valid_path_hashes)
    
    # Validate each hash in sniffer_output
    valid = True
    change = False
    for i, line in enumerate(sniffer_lines, 1):
        line = line.strip()
        if line.isdigit():
            continue
        if line == 'LOOPS':
            continue
        if line == 'PATH':
            change = True
            continue

        if change and line not in valid_path_hashes:
            print(line)
            valid = False

        if not change and line not in valid_loop_hashes:
            print(line)
            valid = False
    
    if valid:
        print("SUCCESS: All hashes in sniffer_output are valid!")
        return True
    else:
        print("FAILURE: sniffer_output contains invalid hashes!")
        return False

if __name__ == "__main__":
    validate_sniffer_output()