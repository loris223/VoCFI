from typeguard import typechecked
from basic_block import BasicBlock
from typing import Optional
from simple_path import SimplePath
import typing
if typing.TYPE_CHECKING:
    from meta_path import MetaPath


@typechecked
class LoopPath:
    """
    Exit node should be the last branch the jumps backwards.
    Meaning that there are multiple branch instructions that jump
    to the beginning of the function if there is or condition.
    If there is and condition there  exists one branch that is quite similar 
    to the break instruction.

    Break instructions tend to jump after the exit node. Next BB after exit BB.

    And continue instructions tend to jump into entry node of the loop.

    - We should identify backward jumps/branches in the function
    There can by many. For example if we have multiple loop conditions
    that are in or relationship. Continue statement should also jump to 
    the entry node.

    - Based on backward jumps we should recognize the entry points
    to the loops (destination of the backward jump).
    There can by many entry points - nested loops for example.

    - Based on the entry nodes we should group together all the jumps/branches
    that are destined to particular entry node

    - The last node address-wise will be the exit node.
    
    - The continuation node should be the node that is afterward exit node.
    This is not mandatory 

    - Every path taken in a loop shoud sooner or later reach continuation node.
    
    - Why need for continuation node? We noticed that after the if with only break
    statement inside the compiler outputs jump from that if directly to 
    nop instruction which is after the exit node. But this nop instruction
    is also considered basic block because the exit node jumps to the
    instruction that is afterwards the nop instruction. It shouldn't
    pose problems but just to keep in mind where the problems could arise. 

    """

    CUR_ID: int = 0
    ENTRY_BLOCKS: list[BasicBlock] = []
    LOOP_PATHS: list['LoopPath'] = []
    

    def __init__(self):
        # Set id, every loop should have unique id
        self.id = LoopPath.CUR_ID
        LoopPath.CUR_ID += 1
        LoopPath.LOOP_PATHS.append(self)

        # Set entry basic block, it should be unique to every object
        # It is also enforced
        self.entry_bb: Optional[BasicBlock] = None
        
        # Backward jumps basic blocks, all blocks that are able
        # to jump to an entry node
        self.backward_jump_bbs: list[BasicBlock] = []

        # Exit BB should be the one that keeps loop running
        self.exit_bb: Optional[BasicBlock] = None

        # Continuation bb should be the first bb after
        # the loop has ended
        self.continuation_bb: Optional[BasicBlock] = None

        # loop blocks that the loop contains
        self.loop_bbs: set[BasicBlock] = []
        self.loop_bbs_determined: bool = False

        # break statements and other conditions
        self.forward_outside_jump_bbs: list[BasicBlock] = []
        self.forward_outside_jump_bbs_determined: bool = False

        # Parent
        self.parent: Optional[LoopPath] = None
        self.childs: list[LoopPath] = []


        # There should be list of paths that the loop can take
        self.path: list[Optional['MetaPath']] = None

        self.hashed_sequence: list[tuple[int, int]] = []
        self.hashes: list[bytes] = []

    
    def set_entry_bb(self, bb: BasicBlock) -> None:
        self.entry_bb = bb
        LoopPath.ENTRY_BLOCKS.append(bb)

    def set_backward_jumps(self, backward_jump_bbs: list[BasicBlock]) -> None:
        self.backward_jump_bbs = backward_jump_bbs

    def add_backward_jump_bb(self, backward_jump_bb: BasicBlock) -> None:
        self.backward_jump_bbs.append(backward_jump_bb)

    def get_backward_jump_bbs(self) -> list[BasicBlock]:
        return self.backward_jump_bbs

    def set_entry_block(self, entry_bb: BasicBlock) -> None:
        self.entry_bb = entry_bb
    
    def get_entry_block(self) -> BasicBlock:
        return self.entry_bb

    def set_exit_block(self, exit_bb: BasicBlock) -> None:
        self.exit_bb = exit_bb
    
    def get_exit_block(self) -> BasicBlock:
        return self.exit_bb

    def set_continuation_block(self, continuation_bb: BasicBlock) -> None:
        self.continuation_bb = continuation_bb
    
    def sort_backward_jump_bbs(self) -> None:
        self.backward_jump_bbs = \
            sorted(self.backward_jump_bbs, key=lambda x: x.end_address)


    @staticmethod
    def new_entry_bb(bb: BasicBlock) -> None:
        if bb in LoopPath.ENTRY_BLOCKS:
            raise ValueError("The entry block is already used.")
        else:
            LoopPath.ENTRY_BLOCKS.append(bb)
    
    def __repr__(self):
        # Header with ID
        header = f"LoopPath(ID={self.id}, "
        
        # Entry block info
        entry_info = "Entry: None"
        if self.entry_bb:
            entry_addr = f"0x{self.entry_bb.start_address:x}"
            entry_info = f"Entry: {entry_addr}, "
        
        # Exit block info
        exit_info = "Exit: None"
        if self.exit_bb:
            exit_addr = f"0x{self.exit_bb.start_address:x}"
            exit_info = f"Exit: {exit_addr}, "
        
        # Continuation block info
        cont_info = "Continuation: None"
        if self.continuation_bb:
            cont_addr = f"0x{self.continuation_bb.start_address:x}"
            cont_info = f"Continuation: {cont_addr}, "
        
        # Backward jumps info
        backward_info = ["    Backward jumps:"]
        for i, bb in enumerate(self.backward_jump_bbs):
            addr_range = f"0x{bb.start_address:x}-0x{bb.end_address:x}"
            backward_info.append(f"        {i}: {addr_range}")
        
        # Forward jumps (break-like) info
        forward_info = ["    Forward jumps (break-like):"]
        for i, bb in enumerate(self.forward_outside_jump_bbs):
            addr_range = f"0x{bb.start_address:x}-0x{bb.end_address:x}"
            forward_info.append(f"        {i}: {addr_range}")
        
        # Loop blocks info
        loop_blocks_info = ["    Loop blocks:"]
        for i, bb in enumerate(self.loop_bbs):
            addr_range = f"0x{bb.start_address:x}-0x{bb.end_address:x}"
            loop_blocks_info.append(f"        {i}: {addr_range}")
        
        # Parent/child info
        parent_info = f"    Parent: {self.parent.id if self.parent else 'None'}"
        child_info = "    Children: None"
        if self.childs:
            child_ids = ", ".join(str(child.id) for child in self.childs)
            child_info = f"    Children: [{child_ids}]"

        loop_hashes_sequence_info = ["    Hash sequence start options:"]
        for i, t in enumerate(self.hashed_sequence):
            addr_range = f"0x{t[0]:x} ----> 0x{t[1]:x}"
            loop_hashes_sequence_info.append(f"        {i}: {addr_range}")

        loop_hashes_info = ["    Hashes:"]
        for i, h in enumerate(self.hashes):
            hash_value =  f" 0x{h.hex()}"
            loop_hashes_info.append(f"        {i}: {hash_value}")

        # Path
        indented_lines = []
        
        for e in self.path:
            # Split each element's string representation into lines
            for line in str(e).splitlines():
                # Indent each line by 4 spaces
                indented_lines.append("    " + line)
            # Add an extra newline between elements if needed
            indented_lines.append("")
        
        path_info = "    Path:\n" + "\n".join(indented_lines).rstrip() + "\n"

        header = header + entry_info + exit_info + cont_info + "){"
        
        # Build the output
        parts = [header]
        
        if len(self.backward_jump_bbs) > 0:
            parts.extend(backward_info)
        
        if len(self.forward_outside_jump_bbs) > 0:
            parts.extend(forward_info)
        
        if len(self.loop_bbs) > 0:
            parts.extend(loop_blocks_info)
        
        if len(self.hashed_sequence) > 0:
            parts.extend(loop_hashes_sequence_info)

        if len(self.hashes) > 0:
            parts.extend(loop_hashes_info)
        
        parts.extend([parent_info, child_info, path_info])

        hs: str = "{"
        for h in self.hashed_sequence:
            hs += f"(0x{h[0]:x}, 0x{h[1]:x}),"
        hs += "}"
        
        return "\n".join(parts) + "}" #+ hs
        


