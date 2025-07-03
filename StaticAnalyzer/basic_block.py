"""
Defines the BasicBlock class for representing code blocks in disassembly.

Attributes:
    start_address (int): Starting address of the block.
    instructions (list): List of instructions in the block.
    successors (list): List of (target_address, edge_type) pairs.
"""
from typeguard import typechecked
from control_flow_type import ControlFlowType
from typing import Optional
import capstone

@typechecked
class BasicBlock:
    def __init__(self, start_address):
        # Start and end address of BasicBlock
        self.start_address: int = start_address
        self.end_address: int = start_address # Will be updated

        # The instructions of the BasicBlock
        self.instructions: list[capstone.CsInsn] = []
        # Successors in the style of List of (target_address, edge_type)
        self.successors: list[tuple[int, str]] = []
        # Successors in the style of List of BasicBlocks that follow
        self.successors_2: list[Optional[BasicBlock]] = []
        
        # Every BasicBlock has some type of the control flow 
        # associated with it and this object should take care 
        # of that information
        self.cft: ControlFlowType = None
        self.is_loop = False

    def add_instruction(self, insn):
        self.instructions.append(insn)
        self.end_address = insn.address + insn.size -1 # Inclusive end address

    def __repr__(self):
        return f"BB @ 0x{self.start_address:x} (size: {len(self.instructions)} insns, ends @ 0x{self.end_address:x})"