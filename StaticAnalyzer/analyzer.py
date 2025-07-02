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


@typechecked
def main(filepath):
    """
    TODO
    """
    all_cfgs: dict[str, dict[int, BasicBlock]]= analyze_elf(filepath)
    generate_all_paths(all_cfgs)


if __name__ == "__main__":
    args = parse_input()
    main(args.object_file)