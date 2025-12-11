"""
TODO
This is the final file that should be ran. It
should get the output of analyzer and output
of Spike. It should compare those two outputs
and decide its correctnes
"""

import os
import sys


class loop_info:
    def __init__(self, entry_hash, path, iterations):
        self.entry_hash = entry_hash
        self.path = path
        self.iterations = iterations
    
class loop_info_2:
    def __init__(self):
        self.entries = set()
        self.paths = set()


# Get the RISCV environment variable
riscv_path = os.getenv('RISCV')

def check_path():
    global riscv_path
    if not riscv_path:
        print("Error: RISCV environment variable is not set")
        sys.exit()
        


def read_sniffer_output():
    # Read the sniffer output (hashes to validate)
    sniffer_file = os.path.join(riscv_path, 'sniffer_output')
    try:
        with open(sniffer_file, 'r') as f:
            sniffer_lines = f.readlines()
            return sniffer_lines
    except FileNotFoundError:
        print(f"Error: {sniffer_file} not found")
        return False



def read_analyzer_output():
    # Read the analyzer output (allowed hashes)
    analyzer_file = os.path.join(riscv_path, 'analyzer_output')
    try:
        with open(analyzer_file, 'r') as f:
            analyzer_lines = f.readlines()
            return analyzer_lines
    except FileNotFoundError:
        print(f"Error: {analyzer_file} not found")
        return False
    

def parse_analyzer_output(analyzer_lines):
    # Extract all valid hashes from analyzer_output
    loops = []
    valid_loop_hashes = set()
    valid_path_hashes = set()

    i = 0
    # Read first line
    if analyzer_lines[i] != "LOOPS\n":
        print("There is a problem with analyzer output!")
        sys.exit()
    i = i + 1

    # Read all loops
    while i < len(analyzer_lines):
        if analyzer_lines[i] != "LOOP\n":
            break
        i = i + 1

        # add loop
        l = loop_info_2()
        loops.append(l)

        # Read entries
        if analyzer_lines[i] != "ENTRIES\n":
            print("There is a problem with analyzer entries!")
        i = i + 1
        
        while analyzer_lines[i] != "PATHS\n":
            l.entries.add(analyzer_lines[i].strip())
            i = i + 1
        
        # Read paths
        if analyzer_lines[i] != "PATHS\n":
            print("There is a problem with analyzer paths!")
        i = i + 1

        while analyzer_lines[i] != "\n":
            l.paths.add(analyzer_lines[i].strip())
            i = i + 1
        i = i + 1
    

    if analyzer_lines[i] == "MAIN PATHS\n":
        i = i + 1
        while i < len(analyzer_lines):
            valid_path_hashes.add(analyzer_lines[i].strip())
            i = i + 1

    return valid_path_hashes, loops


def parse_sniffer_output(sniffer_lines):
    loop_infos = []
    i = 1 # leave out "LOOPS" string

    # read all loops info
    while i < len(sniffer_lines):
        # Stop when encoutering string PATH
        if sniffer_lines[i] == "PATH\n":
            break

        if sniffer_lines[i] == "\n":
            i = i + 1
            continue

        # Read entry hash
        entry_hash = sniffer_lines[i].strip()
        i = i + 1

        # Read loop paths
        while sniffer_lines[i] != "\n":
            # loop info
            l = loop_info(entry_hash, sniffer_lines[i].strip(), int(sniffer_lines[i+1].strip()))
            # add loop
            loop_infos.append(l)
            i = i + 2

        
    return sniffer_lines[-1].strip(), loop_infos
        



def validate_sniffer_output():
    
    analyzer_lines = read_analyzer_output()
    sniffer_lines = read_sniffer_output()

    if (not analyzer_lines) and (not sniffer_lines):
        sys.exit()
    
    valid_path_hashes, loops = parse_analyzer_output(analyzer_lines)
    main_path_hash, loop_infos = parse_sniffer_output(sniffer_lines)

    #print(main_path_hash)
    #print(valid_path_hashes)

    valid = True
    if main_path_hash not in valid_path_hashes:
        valid = False
        print("FAILURE: Main path hash in sniffer_output is not valid!")
    else:
        print("SUCCESS: Main path hash in sniffer_output is valid")
    
    valid = True
    for l in loop_infos:
        valid_tmp = False
        for l2 in loops:
            if l.path in l2.paths and l.entry_hash in l2.entries:
                valid_tmp = True
        if not valid_tmp:
            valid = False

    if valid:
        print("SUCCESS: All loop hashes in sniffer_output are valid!")
        return True
    else:
        print("FAILURE: sniffer_output contains invalid loop hashes!")
        return False

if __name__ == "__main__":
    validate_sniffer_output()
    #print("TODO")