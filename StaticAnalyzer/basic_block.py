"""
Defines the BasicBlock class for representing code blocks in disassembly.

Attributes:
    start_address (int): Starting address of the block.
    instructions (list): List of instructions in the block.
    successors (list): List of (target_address, edge_type) pairs.
"""

class BasicBlock:
    def __init__(self, start_address):
        self.start_address = start_address
        self.instructions = []
        self.end_address = start_address # Will be updated
        self.successors = [] # List of (target_address, edge_type)

    def add_instruction(self, insn):
        self.instructions.append(insn)
        self.end_address = insn.address + insn.size -1 # Inclusive end address

    def __repr__(self):
        return f"BB @ 0x{self.start_address:x} (size: {len(self.instructions)} insns, ends @ 0x{self.end_address:x})"