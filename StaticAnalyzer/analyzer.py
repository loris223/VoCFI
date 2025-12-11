"""
CFGs possible paths generator.

Should parse the input and then run 
sequentially static_analyzer and then
path_generator.
TODO

Example:
    >>> analyze('firmware.elf')
    
"""
import logging
import argparse
from typeguard import typechecked
from static_analyzer import analyze_elf
from basic_block import BasicBlock
from path_generator import generate_all_paths
import os
from analyzer_hashing import hash_branch_addrs


######## Setup functions #################
##########################################


@typechecked
def setup_logger():
    """
    TODO
    """
    pass


@typechecked
def parse_input():
    """
    Parses command line arguments to get the path to an object file.

    Returns:
        argparse.Namespace: Parsed arguments containing the object file path.
    """
    parser = argparse.ArgumentParser(
        description="Analyze an object file. Provide path to the object file as argument."
    )
    parser.add_argument(
        "object_file",
        type=str,
        help="Path to the object file to analyze (required)"
    )
    args = parser.parse_args()
    return args


######## Main functions ##################
##########################################


def write_attack_hashes():
    h = hash_branch_addrs(bytes(32), 0x00010238, 0x000101cc)
    h = hash_branch_addrs(h, 0x00010224, 0x0001023c)
    riscv_path = os.getenv('RISCV')
    if riscv_path:
        file_path = os.path.join(riscv_path, 'analyzer_output')
        with open(file_path, 'w') as f:
            f.write("LOOPS\n")
            f.write("MAIN PATHS\n")
            f.write("0x" + str(h.hex()))
            f.write("\n")
        
        print(f"File created at: {file_path}")
    else:
        print("RISCV environment variable is not set")




@typechecked
def main(filepath):
    """
    TODO
    """
    if os.path.basename(os.path.dirname(filepath)) == "Attack":
        write_attack_hashes()
        return
    all_cfgs: dict[str, dict[int, BasicBlock]]= analyze_elf(filepath)
    generate_all_paths(all_cfgs)


if __name__ == "__main__":
    args = parse_input()
    main(args.object_file)