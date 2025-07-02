from typeguard import typechecked
from basic_block import BasicBlock
from typing import Optional
from simple_path import SimplePath


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

        # Exit exit bb
        self.exit_bb: Optional[BasicBlock] = None

        # Continuation bb
        self.continuation_bb: Optional[BasicBlock] = None

        # break statements and other conditions
        self.forward_outside_jump_bbs: list[BasicBlock] = []

        # loop blocks
        self.loop_bbs: set[BasicBlock] = []


        # There should be list of paths that the loop can take
        self.path: Optional[SimplePath] = None

    
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
        


