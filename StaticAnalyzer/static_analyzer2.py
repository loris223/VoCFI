import lief
import sys
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCV64, \
    CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET, CS_OP_IMM, CS_OP_REG
from capstone.riscv import RISCV_REG_X0, RISCV_OP_REG
from typeguard import typechecked
import capstone

header_file_type = 0

class BasicBlock:
    def __init__(self, start_address):
        self.start_address = start_address
        self.instructions = []
        self.end_address = start_address # Is updated with add_instrcution
        self.successors = [] # List of (target_address, edge_type)

    def add_instruction(self, insn):
        self.instructions.append(insn)
        self.end_address = insn.address + insn.size -1 # Inclusive end address

    def __repr__(self):
        return f"BB @ 0x{self.start_address:x} (size: {len(self.instructions)} insns, ends @ 0x{self.end_address:x})"

@typechecked
def get_start_va(section: lief.ELF.Section) -> int:
    return section.virtual_address


@typechecked
def get_end_va(section: lief.ELF.Section) -> int:
    return section.virtual_address + section.size


@typechecked
def is_address_within_section(section: lief.ELF.Section, addr: int) -> bool:
    start_va = get_start_va(section)
    end_va = get_end_va(section)
    # TODO
    # Is end_va equal to the last instruction of section or does it point to 
    # first instruction of next section?
    # I think is the former but needs to be checked 
    if start_va <= addr <= end_va:
        return True
    else:
        return False


@typechecked
def is_a_function(symbol: lief.ELF.Symbol) -> bool:
    if(symbol.is_function):
        return True
    else:
        return False


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
def get_function_size(symbol: lief.ELF.Symbol) -> int:
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
def is_function_within_section(section: lief.ELF.Section, symbol: lief.ELF.Symbol) -> bool:
    if not is_a_function(symbol):
        print(f"Not a function!")
        return False
    

@typechecked
def is_offset_within_section(section: lief.ELF.Section, offset: int) -> bool:
    if 0 <= offset <= section.size:
        return True
    else:
        return False


@typechecked
def is_function_within_section(section: lief.ELF.Section, symbol: lief.ELF.Symbol) -> bool:
    """
    Remember this is morally wrong way of checking!
    Will do better next time. Or this time if it will pose problems.
    
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
    if section.name == symbol.section.name:
        return True
    else:
        return False


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
def get_function_code_slice(section: lief.ELF.Section, symbol: lief.ELF.Symbol) -> bytes:
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

    section_start_va: int = get_start_va(section)           # get section's start address
    section_end_va: int = get_end_va(section)               # get section's end address
    section_raw_content: bytes = bytes(section.content)     # get memoryview of section -> it should be direct bytes 

    # Ensure the function symbol is within the provided section
    if not is_function_within_section(section, symbol):
        print(f"Warning: Function {symbol.name} (0x{get_function_start_address(symbol):x})\
               seems outside .text (0x{section_start_va:x} - 0x{section_end_va:x}). Skipping.")
        sys.exit(1)

    # Obtain function offsets
    start_offset: int 
    end_offset: int
    start_offset, end_offset = get_function_offsets(symbol)

    # Check for bad offsets
    if not is_offset_within_section(section, start_offset) or end_offset <= start_offset \
        or not is_offset_within_section(section, end_offset):
        print(f"Warning: Invalid offsets for function {symbol.name}. Skipping.")
        sys.exit(1)

    return section_raw_content[start_offset:end_offset]

@typechecked
def identify_leaders(instructions: list[capstone.CsInsn]):
    # 1. Identify Leaders
    leaders: set = {instructions[0].address} # First instruction is a leader
    for i, insn in enumerate(instructions): # Enumerate through instructions
        # Target of a jump or call is a leader
        if insn.groups and (CS_GRP_JUMP in insn.groups or CS_GRP_CALL in insn.groups):
            for op in insn.operands:
                if op.type == CS_OP_IMM: # Direct jump/call target
                    target_addr = op.value.imm
                    # Check if target is within the function's disassembled range
                    if any(prev_insn.address == target_addr for prev_insn in instructions):
                         leaders.add(target_addr)

        # Instruction following a jump, call, or ret is a leader (if it exists)
        # CS_GRP_IRET is actually for interrupt return
        # If we do that we should do also CS_GRP_INT which is interrupt call
        if insn.groups and (CS_GRP_JUMP in insn.groups or CS_GRP_CALL in insn.groups or CS_GRP_RET in insn.groups or CS_GRP_IRET in insn.groups):
            if i + 1 < len(instructions):
                leaders.add(instructions[i+1].address)
    
    # sort leaders (by address)
    sorted_leaders = sorted(list(leaders))
    return sorted_leaders


def form_basic_blocks(instructions, sorted_leaders):
    # 2. Form Basic Blocks
    # This dictionary is created in a way that the key
    # is actually an address where BB lies.
    basic_blocks = {} 
    current_bb = None
    leader_idx = 0

    # Go through instructions of function
    for insn in instructions:

        # Create new basic block
        if leader_idx < len(sorted_leaders) and insn.address == sorted_leaders[leader_idx]:
            current_bb = BasicBlock(insn.address)
            basic_blocks[insn.address] = current_bb
            leader_idx += 1
        
        # Add instructions to current basic block
        if current_bb: # Should always be true after the first leader
            current_bb.add_instruction(insn)

            # If this instruction is a control transfer or the next one is a leader
            is_control_transfer = insn.groups and (CS_GRP_JUMP in insn.groups or CS_GRP_CALL in insn.groups or CS_GRP_RET in insn.groups or CS_GRP_IRET in insn.groups)
            next_is_leader = (leader_idx < len(sorted_leaders) and insn.address + insn.size == sorted_leaders[leader_idx])
            
            if is_control_transfer or next_is_leader:
                if is_control_transfer and (insn.address + insn.size) in basic_blocks and (insn.address + insn.size) not in sorted_leaders:
                    # This case can happen if a block ends with a control flow,
                    # and the next instruction wasn't explicitly marked as a leader,
                    # but should be (e.g. fall-through of a conditional jump).
                    # This ensures the next sequential instruction starts a new block if it's not already a leader.
                    # A more robust leader identification would handle this better.
                    # For now, we assume leaders are correctly identified.
                    pass # This situation implies the next block starts at sorted_leaders[leader_idx]
    
    return basic_blocks


def identify_edges(basic_blocks):
    # 3. Identify Edges
    # Here we are assuming that key of BB is start address
    adj = {bb_addr: [] for bb_addr in basic_blocks} # Adjacency list: {from_bb_addr: [(to_bb_addr, type), ...]}

    # Go through all basic blocks of function
    for bb_addr, bb in basic_blocks.items():

        # if BB is empty
        if not bb.instructions:
            continue
        
        # get last instruction
        last_insn = bb.instructions[-1]
        # next_insn_addr is actually first address of next BB
        # if there exists at this address (maybe can be return statement)
        next_insn_addr = last_insn.address + last_insn.size

        is_unconditional_jump = False
        # last_insn.groups just checks if the capstone detail is enabled
        is_ret_or_iret = last_insn.groups and (CS_GRP_RET in last_insn.groups or CS_GRP_IRET in last_insn.groups)

        #CS_GRP_JUMP    = 1  # all jump instructions (conditional+direct+indirect jumps)
        if last_insn.groups and CS_GRP_JUMP in last_insn.groups:
            # Check if it's unconditional (e.g. jmp vs jz)
            # Capstone doesn't directly give "unconditional" for all jump types,
            # so we check common unconditional jump mnemonics.
            # More robustly, one would check instruction semantics.
            if last_insn.mnemonic == 'jal':
                # Check if the first operand (destination register rd) is x0
                if len(last_insn.operands) > 0 and \
                   last_insn.operands[0].type == CS_OP_REG and \
                   last_insn.operands[0].reg == RISCV_REG_X0:
                    is_unconditional_jump = True

            target_op = None
            for op in last_insn.operands:
                if op.type == CS_OP_IMM:
                    target_op = op.value.imm
                    break
            
            if target_op is not None and target_op in basic_blocks:
                adj[bb_addr].append((target_op, "jump_cond_taken" if not is_unconditional_jump else "jump_uncond"))
            elif target_op is not None:
                 adj[bb_addr].append((target_op, "jump_external_or_unresolved")) # Target outside current blocks

            # If it's a conditional jump, there's also a fall-through path
            if not is_unconditional_jump and not is_ret_or_iret and next_insn_addr in basic_blocks:
                adj[bb_addr].append((next_insn_addr, "fallthrough_cond_nottaken"))

        if last_insn.groups and CS_GRP_CALL in last_insn.groups:
            call_target = None
            for op in last_insn.operands:
                if op.type == CS_OP_IMM:
                    call_target = op.value.imm
                    break
            
            if call_target is not None:
                # For CFG, the "return site" is the primary successor within the function
                if next_insn_addr in basic_blocks:
                     adj[bb_addr].append((next_insn_addr, f"call_ret_site (to 0x{call_target:x})"))
                else: # Call at end of function block without subsequent instructions in this function
                     adj[bb_addr].append((None, f"call_ret_site_external (to 0x{call_target:x})")) # No next block in func
            else: # Indirect call
                if next_insn_addr in basic_blocks:
                    adj[bb_addr].append((next_insn_addr, "call_indirect_ret_site"))
                else:
                    adj[bb_addr].append((None, "call_indirect_ret_site_external"))


        # Fall-through for non-terminating, non-unconditional jump, non-call instructions
        if not is_unconditional_jump and not is_ret_or_iret and not (last_insn.groups and CS_GRP_CALL in last_insn.groups):
            if next_insn_addr in basic_blocks: # Next instruction starts a new BB
                # Avoid duplicate fallthrough if already added by conditional jump logic
                if not any(succ[0] == next_insn_addr and succ[1] == "fallthrough_cond_nottaken" for succ in adj[bb_addr]):
                    adj[bb_addr].append((next_insn_addr, "fallthrough_sequential"))
    return adj


@typechecked
def build_cfg_for_function(disassembler: capstone.Cs, func_code_bytes: bytes, func_base_address: int):
    if not func_code_bytes:
        return {}, {}

    instructions: list[capstone.CsInsn] = list(disassembler.disasm(func_code_bytes, func_base_address))
    if not instructions:
        return {}, {}

    sorted_leaders = identify_leaders(instructions)
    
    basic_blocks = form_basic_blocks(instructions, sorted_leaders)

    adj = identify_edges(basic_blocks)
    
    return basic_blocks, adj


def parse_file(filepath):
    binary = lief.parse(filepath)
    if not binary:
        print(f"Could not parse {filepath} as a supported executable format.")
        sys.exit(1)
    return binary


def check_arch(machine_type):
    if machine_type != lief.ELF.ARCH.RISCV:
        print(f"The provided file is not of RISCV architecture.")
        sys.exit(1)

@typechecked
def extract_function_symbols(binary: lief.ELF.Binary) -> list[lief.ELF.Symbol]:
    text_section: lief.ELF.Section = binary.get_section(".text")
    if not text_section:
        print("'.text' section not found. Cannot proceed.")
        sys.exit(1)

    # Sort symbols by address to help determine function boundaries
    # Filter for function symbols and ensure they have a valid address
    function_symbols = sorted(
        [s for s in binary.symbols if s.is_function and s.value >= 0],
        key=lambda s: s.value
    )
    
    # If function symbols is empty
    if not function_symbols:
        print("No function symbols found.")
        sys.exit(1)
    
    return function_symbols

@typechecked
def extract_all_cfgs(binary: lief.ELF.Binary, function_symbols: list[lief.ELF.Symbol]):
    # initialize capstone
    md: capstone.Cs  = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    md.detail = True  # Enable instruction details (groups, operands)
    text_section: lief.ELF.Section = binary.get_section(".text")
    all_cfgs = {}
    for i, func_sym in enumerate(function_symbols):
        print(f"\n--- Analyzing Function: {func_sym.name} @ 0x{func_sym.value:x} ---")
        
        func_code_bytes: bytes = get_function_code_slice(text_section, func_sym)

        func_size: int = get_function_size(func_sym)
        func_start_va: int = get_function_start_address(func_sym)

        # Check if we got any bytes
        if not func_code_bytes or func_size == 0:
            print(f"Could not get code for function {func_sym.name} or size is zero. Skipping.")
            continue
        
        print(f"Attempting to disassemble 0x{func_size:x} bytes from 0x{func_start_va:x}")

        basic_blocks, adj = build_cfg_for_function(md, func_code_bytes, func_start_va)
        all_cfgs[func_sym.name] = (basic_blocks, adj)

        if not basic_blocks:
            print("No basic blocks generated for this function.")
            continue

        print("Basic Blocks:")
        for bb_addr, bb in sorted(basic_blocks.items()):
            print(f"  {bb}")
            # for insn_idx, insn in enumerate(bb.instructions):
            #     print(f"    0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
            # print(f"    Successors: {adj.get(bb_addr, [])}")
        
        print("Edges (Adjacency List):")
        for from_bb, to_bbs in sorted(adj.items()):
            if basic_blocks.get(from_bb): # Check if from_bb exists (it should)
                 print(f"  From BB @ 0x{from_bb:x}:")
                 for to_bb_addr, edge_type in to_bbs:
                     to_bb_str = f"BB @ 0x{to_bb_addr:x}" if to_bb_addr is not None and to_bb_addr in basic_blocks else f"External/Unresolved @ 0x{to_bb_addr:x}" if to_bb_addr is not None else "External/Return"
                     print(f"    -> {to_bb_str} ({edge_type})")
            else:
                print(f"  Warning: Edge from non-existent BB @ 0x{from_bb:x}")

@typechecked
def main(filepath: str):
    # parse the provided file with lief
    binary: lief.ELF.Binary = parse_file(filepath)
    global header_file_type 
    header_file_type = binary.header.file_type

    # check for right architecture
    check_arch(binary.header.machine_type)

    # Now it is not actually clear how to approach a problem of finding CFG
    # One suggests to extract functions from symbol table and then perform
    # CFG for each function. Maybe we could do that. 

    # First extract function symbols
    function_symbols: list[lief.ELF.Symbol] = extract_function_symbols(binary)

    # With binary and function symbols get all cfgs
    all_cfgs = extract_all_cfgs(binary, function_symbols)



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <object_file_path>")
        sys.exit(1)
    filepath = sys.argv[1]
    main(filepath)