import lief
import sys
from typeguard import typechecked

GENERIC_ERROR_CODE: int = 1




######## Binary related functions ########
##########################################


@typechecked
def read_elf(filepath: str) -> lief.ELF.Binary:
    """
    Reads elf file using lief library.
    Halts script if it can not parse file.
    """
    binary = lief.parse(filepath)
    if not binary:
        print(f"Could not parse {filepath} as a supported executable format.")
        sys.exit(GENERIC_ERROR_CODE)
    return binary


@typechecked
def check_arch(binary: lief.ELF.Binary):
    """
    We are working only with RISC-V architecture
    so it just halts if the provided ELF file
    is something else.
    """
    if binary.header.machine_type != lief.ELF.ARCH.RISCV:
        print(f"The provided file is not of RISCV architecture.")
        sys.exit(GENERIC_ERROR_CODE)


@typechecked
def get_binary(filepath: str) -> lief.ELF.Binary:
    """
    It parses binary, checks for right architecture
    and returns binary.
    """
    # parse the provided file with lief
    binary: lief.ELF.Binary = read_elf(filepath)

    # check for right architecture
    check_arch(binary)

    return binary