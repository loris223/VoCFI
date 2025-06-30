"""
TODO
"""

from typeguard import typechecked
from basic_block import BasicBlock
from typing import Optional


# Functionality for the type_loop should be 
# almost the same as for a path. But that way
# it should be easier to differentiate when
# to pay attention for circular graph

# typechecked works for whole class. So this means
# for all that is inside class.
@typechecked
class SimplePath:

    def __init__(self):
        self.path: list[BasicBlock] = []
        self.ends_with_loop: bool = False
        self.ends_with_loop_bb: BasicBlock = None
        self.ends_with_path: bool = False
        self.ends_with_path_bb: BasicBlock = None
        self.successor_paths: list[SimplePath]
    
    def append(self, bb: BasicBlock):
        self.path.append(bb)
    
    def prepend(self, bb: BasicBlock):
        self.path = [bb] + self.path
    
    def set_end_loop_bb(self, bb: BasicBlock):
        self.ends_with_loop = True
        self.ends_with_loop_bb = bb
    
    def set_end_path_bb(self, bb: BasicBlock):
        self.ends_with_path = True
        self.ends_with_path_bb = bb
    
    def get_ends_with_loop(self) -> Optional[BasicBlock]:
        if self.ends_with_loop:
            return self.ends_with_loop_bb
        else:
            return None
    
    def get_ends_with_path(self) -> Optional[BasicBlock]:
        if self.ends_with_path:
            return self.ends_with_path_bb
        else:
            return None
    
    def get_last_bb(self) -> BasicBlock:
        return self.path[-1]
    
    def add_successor(self, sp: 'SimplePath') -> None:
        self.seccessor_paths.append(sp)
    
    def assign_successor_list(self, sps: list['SimplePath']) -> None:
        self.successor_paths = sps

    def __repr__(self):
        path_type = "PATH"
        loop_info = ""
        
        if self.ends_with_loop:
            loop_addr = f"0x{self.ends_with_loop_bb.start_address:x}" if self.ends_with_loop_bb else "None"
            loop_info = f", ends with loop @ {loop_addr}"
            
        blocks_info = "\n  ".join(
            f"{i}: {bb}" 
            for i, bb in enumerate(self.path)
        )
        return (
            f"SimplePath(type={path_type}{loop_info}, "
            f"length={len(self.path)} blocks):\n  {blocks_info}\n"
        )







if __name__ == "__main__":
    sp: SimplePath = SimplePath(1)
    sp2: SimplePath = SimplePath(2)
    print(sp.type)
    print(sp2.type)