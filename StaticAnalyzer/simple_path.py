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
    CURR_ID: int = 0
    SIMPLE_PATHS: list['SimplePath'] = []

    def __init__(self):
        self.id: int = SimplePath.get_id()
        self.path: list[BasicBlock] = []
        self.ends_with_loop: bool = False
        self.ends_with_loop_bb: BasicBlock = None
        self.ends_with_path: bool = False
        self.ends_with_path_bb: BasicBlock = None
        self.successor_paths: list[SimplePath] = []
        self.link_paths: list[SimplePath] = []
        SimplePath.SIMPLE_PATHS.append(self)
        self.to_be_extended: bool = False
        self.loop_end: bool = False
        self.function_end: bool = False
    
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
        self.successor_paths.append(sp)
    
    def assign_successor_list(self, sps: list['SimplePath']) -> None:
        self.successor_paths = sps

    def __repr__(self):
        # Calculate start and end addresses
        start_addr = f"0x{self.path[0].start_address:x}" if self.path else "None"
        end_addr = f"0x{self.path[-1].end_address:x}" if self.path else "None"
        
        # Header with ID, length and addresses
        header = (
            f"SimplePath(ID={self.id}, length={len(self.path)} blocks, "
            f"start={start_addr}, end={end_addr})"
        )
        
        # End conditions
        end_info = []
        if self.ends_with_loop:
            addr = f"0x{self.ends_with_loop_bb.start_address:x}"
            end_info.append(f"Ends with loop @ {addr}")
        if self.ends_with_path:
            addr = f"0x{self.ends_with_path_bb.start_address:x}"
            end_info.append(f"Ends with path @ {addr}")
        
        # Block list with improved indentation
        blocks_info = []
        for i, bb in enumerate(self.path):
            addr_range = f"0x{bb.start_address:x}-0x{bb.end_address:x}"
            blocks_info.append(f"{i}: {addr_range}")
        
        # Successors
        succ_info = "None"
        if self.successor_paths:
            succ_ids = ", ".join(str(sp.id) for sp in self.successor_paths)
            succ_info = f"[{succ_ids}]"
        
        # Link infos
        link_info = "None"
        if self.link_paths:
            link_ids = ", ".join(str(sp.id) for sp in self.link_paths)
            link_info = f"[{link_ids}]"
        
        # Build output with consistent 4-space indentation
        parts = [header]
        
        if end_info:
            parts.append("    " + "\n    ".join(end_info))
        
        if blocks_info:
            parts.append("    Blocks:")
            # Add extra 4-space indent for block lines
            parts.extend("        " + line for line in blocks_info)
        
        parts.append(f"    Successors: {succ_info}")

        parts.append(f"    Links: {link_info}")
        
        return "\n".join(parts) + "\n"

    
    @staticmethod
    def get_id() -> int:
        SimplePath.CURR_ID += 1
        return SimplePath.CURR_ID - 1 







if __name__ == "__main__":
    sp: SimplePath = SimplePath(1)
    sp2: SimplePath = SimplePath(2)
    print(sp.type)
    print(sp2.type)