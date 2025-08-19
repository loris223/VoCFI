import lief
import sys
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OP_IMM
from basic_block import BasicBlock
from typeguard import typechecked
import capstone
from capstone.riscv import RISCV_INS_BEQ, RISCV_INS_BNE, RISCV_INS_BLT, \
    RISCV_INS_BGE, RISCV_INS_BLTU, RISCV_INS_BGEU, RISCV_INS_JAL, \
    RISCV_INS_JALR
import argparse
from control_flow_type import ControlFlowType
import file_functions

GENERIC_ERROR_CODE: int = 1
header_file_type: int = 0
functions_to_analyze: list[str] = []
functions_to_analyze.append("main")
args = None


######## Section related functions #######
##########################################


@typechecked
def get_start_va(section: lief.ELF.Section) -> int:
    return section.virtual_address


@typechecked
def get_end_va(section: lief.ELF.Section) -> int:
    return section.virtual_address + section.size


@typechecked
def is_offset_within_section(section: lief.ELF.Section, offset: int) -> bool:
    if 0 <= offset <= section.size:
        return True
    else:
        return False


@typechecked
def is_function_within_section(section: lief.ELF.Section, symbol: lief.ELF.Symbol) -> bool:
    """
    There is no compare method for section object so
    we are checking from two properties (name, va).
    
    Args:
        section (lief.ELF.Section): The section object which is checked
        symbol (lief.ELF.Symbol): The symbol object which is checked

    Returns:
        equal (bool): True if the symbol is within section

    Raises:
        /

    Example:
        >>> is_function_within_section(section, symbol)
        True
    """
    section_1 = section
    section_2: lief.ELF.Section = symbol.section
    # 1. Check for names
    # 2. Check for virtual address
    if section_1.name == section_2.name and \
        section_1.virtual_address == section_2.virtual_address:
        return True
    else:
        return False


@typechecked
def extract_function_symbols_from_section(binary: lief.ELF.Binary ,section: lief.ELF.Section) -> list[lief.ELF.Symbol]:
    """
    Find all elf function symbols of section.

    Args:
        binary (lief.ELF.Binary): Binary object of the file
        section (lief.ELF.Section): Section object

    Returns:
         function_symbols (list[lief.ELF.Symbol]): all function symbols within function

    Raises:
        /

    Example:
        >>> extract_function_symbols_from_section(binary, section)
        [main, func1, ...]
    """
    # get all function symbols and filter them if they are not
    # functions or they are not within provided section
    function_symbols: list[lief.ELF.Symbol]  = [s for s in binary.symbols \
                         if s.is_function and is_function_within_section(section, s)]
    
    # Sort symbols by address 
    function_symbols = sorted(function_symbols, key=lambda s: s.value)

    
    # If function symbols is empty
    if not function_symbols:
        print("No function symbols found within section.")
        sys.exit(1)
    
    return function_symbols


######## Function related functions ######
##########################################


@typechecked
def is_a_function(symbol: lief.ELF.Symbol) -> bool:
    """
    Checks if symbol is a function.
    """
    if(symbol.is_function):
        return True
    else:
        return False


@typechecked
def get_function_size(symbol: lief.ELF.Symbol) -> int:
    """
    Checks if symbol is a function and returns size of it.
    """
    # Check if symbol is a function
    if not is_a_function(symbol):
        print(f"The function {symbol.name} is not a function!")
        return -1
    size = symbol.size
    if size <= 0:
        print(f"The function {symbol.name} has size of 0 or lower!")
        # TODO 
        # If this ever happens one should check why this occurs
        # understand problem and provide other solution
        # It should not happen
    return size


@typechecked
def get_function_start_address(symbol: lief.ELF.Symbol) -> int:
    """
    It uses value property of Symbol object to determine address
    of function. But the value of Symbol object
    depends on type of file that is was provided. Therefore
    header_file_type should be set. From the documentation of 
    Symbol the following interpretation of values are defined:
    1. In relocatable files, this property contains the alignment constraints of the symbol for which the section index is SHN_COMMON.
    2. In relocatable files, can also contain a section’s offset for a defined symbol. That is, value is an offset from the beginning of the section associated with this symbol.
    3. In executable and libraries, this property contains a virtual address.
    This is actually quite important function for our purposes.
    
    Args:
        symbol (lief.ELF.Symbol): The symbol object for which offsets are determined.

    Returns:
        start_address: Start virtual address of a function

    Raises:
        ValueError

    Example:
        >>> get_function_start_address(symbol)
        32
    """
    start_address: int = 0

    # Case 1: Executable or shared library (use virtual address)
    if header_file_type in [lief.Header.OBJECT_TYPES.EXECUTABLE, lief.Header.OBJECT_TYPES.LIBRARY]:
        start_address = symbol.value
    # Case 2: Relocatable object (offset within section)
    elif header_file_type == lief.Header.OBJECT_TYPES.OBJECT:
        if symbol.shndx == lief.ELF.SYMBOL_SECTION_INDEX.SHN_COMMON:
            raise ValueError(f"Symbol {symbol.name} is in SHN_COMMON (alignment={symbol.value})")
        start_address = symbol.value + get_start_va(symbol.section)
    # Unsupported ELF type (e.g., ET_CORE)
    else:
        raise ValueError(f"Unsupported ELF type: {header_file_type}")
    
    return start_address


@typechecked
def get_function_offsets(symbol: lief.ELF.Symbol) -> tuple[int, int]:
    """
    It uses value property of Symbol object to determine offset
    of function in its section. But the value of Symbol object
    depends on type of file that is was provided. Therefore
    header_file_type should be set. From the documentation of 
    Symbol the following interpretation of values are defined:
    1. In relocatable files, this property contains the alignment constraints of the symbol for which the section index is SHN_COMMON.
    2. In relocatable files, can also contain a section’s offset for a defined symbol. That is, value is an offset from the beginning of the section associated with this symbol.
    3. In executable and libraries, this property contains a virtual address.
    This is actually quite important function for our purposes.
    
    Args:
        symbol (lief.ELF.Symbol): The symbol object for which offsets are determined.

    Returns:
        start_offset: Offset of a start of function within the section
        end_offset: Offset of a end of function within the section 

    Raises:
        ValueError

    Example:
        >>> get_function_offsets(symbol)
        (0, 32)
    """
    start_offset: int = 0
    end_offset: int = 0

    # Case 1: Executable or shared library (use virtual address)
    if header_file_type in [lief.Header.OBJECT_TYPES.EXECUTABLE, lief.Header.OBJECT_TYPES.LIBRARY]:
        start_offset = symbol.value - get_start_va(symbol.section)
    # Case 2: Relocatable object (offset within section)
    elif header_file_type == lief.Header.OBJECT_TYPES.OBJECT:
        if symbol.shndx == lief.ELF.SYMBOL_SECTION_INDEX.SHN_COMMON:
            raise ValueError(f"Symbol {symbol.name} is in SHN_COMMON (alignment={symbol.value})")
        start_offset = symbol.value
    # Unsupported ELF type (e.g., ET_CORE)
    else:
        raise ValueError(f"Unsupported ELF type: {header_file_type}")
    
    end_offset = start_offset + get_function_size(symbol)
    return start_offset, end_offset


@typechecked
def get_function_code_slice(symbol: lief.ELF.Symbol) -> bytes:
    """Returns the code bytes for a function.
    
    Args:
        section (lief.ELF.Section): The section which is used - it is text section in our code
        func_symbol (lief.ELF.Symbol): This is the function symbol

    Returns:
        bytes: Returns raw bytes of the function

    Raises:
        /

    Example:
        >>> get_function_code_slice(text_section, main)
        b'\x13\x01\...'
    """

    # Get section from symbol
    section: lief.ELF.Section = symbol.section
    
    # Obtain function offsets
    start_offset: int 
    end_offset: int
    start_offset, end_offset = get_function_offsets(symbol)

    # Check for bad offsets
    if not is_offset_within_section(section, start_offset) or end_offset <= start_offset \
        or not is_offset_within_section(section, end_offset):
        print(f"Warning: Invalid offsets for function {symbol.name}. Skipping.")
        return bytes()

    return bytes(section.content)[start_offset:end_offset]


######## Basic block related functions ###
##########################################


@typechecked
def identify_leaders(instructions: list[capstone.CsInsn]) -> list[int]:
    """
    So identification of leaders goes as following. First insn
    is a leader. Then leaders are also after branch or jump instruction
    and if we can determine where the instruction will jump and that insn
    is within the function we consider also that insn as a leader.
    # TODO
    Calls out of functions should be handled
    """
    if instructions is None:
        return None

    # First insn is a leader
    leaders: set = {instructions[0].address}

    for i, insn in enumerate(instructions):
        # Check if instrcution changes control flow
        cf_insn: bool = is_control_flow_insn(insn)
        if cf_insn:
            # Next instruction is a leader
            if i + 1 < len(instructions):
                leaders.add(instructions[i+1].address)
            
            # Try to determine destination address
            dst_addr: int = get_dst_addr(insn)
            if dst_addr != -1:
                # We need to check if the address is within function
                if instructions[0].address <= dst_addr <= instructions[-1].address:
                    leaders.add(dst_addr)
                else:
                    # TODO
                    # This should be handled
                    pass

    
    # Sort leaders
    sorted_leaders: list[int] = sorted(list(leaders))
    return sorted_leaders


@typechecked
def form_basic_blocks(instructions: list[capstone.CsInsn], sorted_leaders: list[int]) -> dict[int, BasicBlock]:
    """
    From the instructions of a function and its leaders
    it constructs basic block of a function.
    Loop through instructions and when new leader appears
    create new basic block.
    """
    
    basic_blocks: dict[int, BasicBlock] = {} 
    current_bb = None
    leader_idx = 0

    # Go through instructions of function
    for insn in instructions:
        # Create new basic block
        if leader_idx < len(sorted_leaders) and insn.address == sorted_leaders[leader_idx]:
            current_bb = BasicBlock(insn.address)
            basic_blocks[insn.address] = current_bb
            leader_idx += 1
        
        # Add instruction to bb
        current_bb.add_instruction(insn)
    
    return basic_blocks


@typechecked
def create_adjacency_list(basic_block: BasicBlock) -> \
    tuple[list[tuple[int, str]], ControlFlowType]:
    """
    Gets basic block and then it creates
    adjacency list for that bb.
    """
    adj: list[tuple[int, str]] = []

    # get last instruction
    last_insn: capstone.CsInsn = basic_block.instructions[-1]
    next_insn_addr = last_insn.address + last_insn.size

    cft: ControlFlowType = ControlFlowType(last_insn.id)

    if last_insn.id in {
        RISCV_INS_BEQ, RISCV_INS_BNE, RISCV_INS_BLT,
        RISCV_INS_BGE, RISCV_INS_BLTU, RISCV_INS_BGEU
    }:
        # Condition not positive
        adj.append((next_insn_addr, "Condition not taken."))
        # Condition positive
        adj.append((get_dst_addr(last_insn), "Condition taken."))
        # CFT
        cft.set_condition_taken_addr(get_dst_addr(last_insn), "Condition taken.")
        cft.set_condition_not_taken_addr(next_insn_addr, "Condition not taken.")
    elif last_insn.id == RISCV_INS_JAL:
        # Unconditional jump
        adj.append((get_dst_addr(last_insn), "Unconditional jump."))
        # CFT
        cft.set_destination_addr(get_dst_addr(last_insn), "Unconditional jump.")
    elif last_insn.id == RISCV_INS_JALR:
        # Indirect jump
        adj.append((-1, "Indirect jump."))
        cft.set_destination_addr(-1, "Unconditional jump.")
    else:
        # There is no condition and the flow just goes to the next 
        # instruction
        adj.append((next_insn_addr, "Next instruction."))
        cft.set_destination_addr(next_insn_addr, "Next instruction.")

    return adj, cft


@typechecked
def create_adjacency_dict(basic_blocks: dict[int, BasicBlock]) -> dict[int, list[tuple[int, str]]]:
    """
    It accepts dictionary of basic blocks
    and then it creates adjacency list for
    every basic block in dict.
    """
    # Adjacency list: {from_bb_addr: [(to_bb_addr, type), ...]}
    adj: dict[int, list[tuple[int, str]]] = {bb_addr: [] for bb_addr in basic_blocks} 

    # Go through all basic blocks of function
    for bb_addr, bb in basic_blocks.items():
        adj_tmp: list[tuple[int, str]]
        cft: ControlFlowType
        adj_tmp, cft = create_adjacency_list(bb)
        adj[bb_addr] = adj_tmp
        bb.cft = cft
        
    return adj


@typechecked
def assign_adj_to_bb(basic_blocks: dict[int, BasicBlock],\
                      adj: dict[int, list[tuple[int, str]]]) -> None:
    """
    It assigns adjacency list to each BB object.
    """
    for bb_addr, bb in basic_blocks.items():
        bb.successors = adj[bb_addr]


@typechecked
def extract_cfg_of_function(symbol: lief.ELF.Symbol)\
      -> tuple[dict[int, BasicBlock], dict[int, list[tuple[int, str]]]]:
    """
    It extracts basic blocks and adjacency list
    between them. It could be thought as cfg.
    """
    # Get raw bytes of function
    func_bytes: bytes = get_function_code_slice(symbol)

    if len(func_bytes) == 0:
        return dict(), dict()

    # Dissassemble them
    instructions: list[capstone.CsInsn] = \
        disassemble_code(func_bytes, get_function_start_address(symbol))
    
    # Find leaders
    sorted_leaders: list[int] = identify_leaders(instructions)

    # Construct basic blocks
    basic_blocks: dict[int, BasicBlock] = form_basic_blocks(instructions, sorted_leaders)

    # Create adjacency list
    adj: dict[int, list[tuple[int, str]]] = create_adjacency_dict(basic_blocks)

    # Assign adjacency list to basic blocks
    assign_adj_to_bb(basic_blocks, adj)

    
    # Link blocks between themselves
    for addr, bb in basic_blocks.items():
        for trg_addr, _ in bb.successors:
            if trg_addr in basic_blocks:
                bb.successors_2.append(basic_blocks[trg_addr])
            else:
                pass#bb.successors_2.append(None)


    return basic_blocks, adj


@typechecked
def extract_all_cfgs(function_symbols: list[lief.ELF.Symbol]) -> dict[str, dict[int, BasicBlock]]:
    """
    Accepts function symbols. Loops through them and
    extracts cfg for each of the provided function symbol.
    # TODO prints should be done with logger
    returns dictionary of basic blocks
    """
    func_basic_blocks: dict[str, dict[int, BasicBlock]] = {}

    # Loop through function symbols
    for i, func_sym in enumerate(function_symbols):
        print(f"\n--------------------- Analyzing Function: {func_sym.name} @ 0x{func_sym.value:x} ---------------------")
        print(f"Attempting to disassemble 0x{get_function_size(func_sym):x}\
               bytes from 0x{get_function_start_address(func_sym):x}")
        basic_blocks: dict[int, BasicBlock]
        adj: dict[int, list[tuple[int, str]]]
        basic_blocks, adj = extract_cfg_of_function(func_sym)

        if not basic_blocks:
            print("No basic blocks generated for this function.")
            continue

        print("\n+++++\nBASIC BLOCKS:")
        for bb_addr, bb in sorted(basic_blocks.items()):
            print(f"  {bb}")
            for insn_idx, insn in enumerate(bb.instructions):
                print(f"    0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
            print(f"    Successors: {[(hex(addr), desc) for addr, desc in adj.get(bb_addr, [])]}")

        print_adj(adj)
        print(f"\n-------------------------------------------------------------")


        # Add it
        func_basic_blocks[func_sym.name] = basic_blocks


    return func_basic_blocks


@typechecked
def link_blocks(dict_of_bb: dict[int, BasicBlock]) -> None:
    """
    TODO 
    """


######## Print related functions #########
##########################################


@typechecked
def print_adj(adj: dict[int, list[tuple[int, str]]]) -> None:
    """
    TODO
    """
    print("\n+++++\nEDGES (Adjacency List):")
    for from_bb, to_bbs in sorted(adj.items()):
        print(f"  From BB @ 0x{from_bb:x}:")
        for to_bb_addr, edge_type in to_bbs:
            to_bb_str = f"BB @ 0x{to_bb_addr:x}"
            print(f"    -> {to_bb_str} ({edge_type})")


######## Capstone related functions ######
##########################################


@typechecked
def is_dst_addr_staticaly_determined(insn: capstone.CsInsn) -> bool:
    """
    Gets the instruction and provides info if the 
    instruction's destination address can be statically
    determined.

    Returns True for:
    - Direct jumps (JAL with constant target)
    - Conditional branches (BEQ/BNE/etc with constant offset)
    Returns False for:
    - Indirect jumps (JALR)
    - Non-control-flow instructions
    """
    # Check for direct jumps and branches
    if insn.id in {
        RISCV_INS_BEQ, RISCV_INS_BNE, RISCV_INS_BLT,
        RISCV_INS_BGE, RISCV_INS_BLTU, RISCV_INS_BGEU,
        RISCV_INS_JAL
    }:
        return True
    else:
        return False


@typechecked
def get_dst_addr(insn: capstone.CsInsn) -> int:
    """
    Returns the destination address if it can be statically determined.
    Returns -1 for:
    - Indirect jumps (JALR)
    - Non-control-flow instructions
    - Instructions without static targets
    """
    # Check for right insn
    if not is_dst_addr_staticaly_determined(insn):
        return -1
    elif insn.operands and len(insn.operands) > 0:
        op = insn.operands[-1]  # Last operand is typically the target
        if op.type == CS_OP_IMM:
            return insn.address + op.value.imm
    else:
        # 
        return -1


@typechecked
def is_control_flow_insn(insn: capstone.CsInsn):
    """
    Returns True is the provided instruction
    changes control flow. 
    We have not covered Compressed instructions
    and exception returns.
    """
    CONTROL_FLOW_INSTRUCTIONS = {
        RISCV_INS_BEQ, RISCV_INS_BNE, RISCV_INS_BLT,
        RISCV_INS_BGE, RISCV_INS_BLTU, RISCV_INS_BGEU,
        RISCV_INS_JAL, RISCV_INS_JALR
    }
    return insn.id in CONTROL_FLOW_INSTRUCTIONS


@typechecked
def disassemble_code(code: bytes, base_addr: int) -> list[capstone.CsInsn]:
    """
    Accepts raw bytes of function and its base address
    then dissassembles it.
    """
    md: capstone.Cs = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    md.detail = True
    return list(md.disasm(code, base_addr))


######## Setup functions #################
##########################################


@typechecked
def setup_env(binary: lief.ELF.Binary) -> None:
    """
    Sets up global variables. Just one for now
    header_file_type.
    """
    global header_file_type
    header_file_type = binary.header.file_type


@typechecked
def filter_function_symbols(function_symbols: list[lief.ELF.Symbol]) -> list[lief.ELF.Symbol]:
    """
    Gets the function symbols list which is then compared
    to global functions_to_analyze list (this should be set in advance)
    and removes all function symbols that are not present
    in global variable.
    """
    new_function_symbols: list[lief.ELF.Symbol] = []
    global functions_to_analyze
    for func_sym in function_symbols:
        if func_sym.name in functions_to_analyze:
            new_function_symbols.append(func_sym)
    
    return new_function_symbols


@typechecked
def parse_input():
    """
    TODO
    """
    # global args
    global functions_to_analyze
    parser = argparse.ArgumentParser(description="TODO")
    # Positional arguments
    parser.add_argument('filepath', type=str, help="Path to the ELF file")
    # Optional arguments
    parser.add_argument('--functions', '-f', type=str, help='Comma-separated list of functions names')
    args = parser.parse_args()
    if args.functions:
        for fun in args.functions.split(','):
            functions_to_analyze.append(fun)
    return args.filepath


######## Main functions ##################
##########################################


@typechecked
def analyze_elf(filepath: str, all_functions: bool = True, section_name: str = ".text"):
    # Get binary
    binary: lief.ELF.Binary = file_functions.get_binary(filepath)

    # Set up some global variables
    setup_env(binary)

    # Find relevant function symbols
    function_symbols: list[lief.ELF.Symbol] = \
        extract_function_symbols_from_section(binary, binary.get_section(".text"))

    # Filter those function symbols to our needs
    function_symbols = filter_function_symbols(function_symbols)

    # With binary and function symbols get all cfgs by function
    all_cfgs: dict[str, dict[int, BasicBlock]] = extract_all_cfgs(function_symbols)
    return all_cfgs


if __name__ == "__main__":
    filepath = parse_input()
    analyze_elf(filepath)

# TODO
# 1.
# Detecting loops should be done in the following way:
# since subroutine
# calls use instructions that update the link-register, we con-
# sider the target of each non-linking backwards branch as
# a loop entry node. 

"""
2.
For now jalr instruction is considered that it can not be determined.
However there are cases where one can recognize compiler patterns
e.g. auipc t1, offset + jalr ra, t1, offset which can be decoded 
statically. 
"""
"""
3. Pseudo instruction "ret" could probably be determined statically.

"""