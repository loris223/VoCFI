"""
TODO
"""

from typeguard import typechecked
from simple_path import SimplePath
from basic_block import BasicBlock
import typing
#if typing.TYPE_CHECKING:
from loop_path import LoopPath





@typechecked
class MetaPath:
    """
    MetaPath will be just the holder of the SimplePath
    and LoopPath. It shouldn't be needed but because we have
    some particular way of handling loops there is a need for this.
    """

    def __init__(self):
        self.path: list[typing.Union[SimplePath, 'LoopPath']] = []
        self.hash_bytes: typing.Optional[bytes] = None
        self.hashes: list[bytes] = []

    def append(self, path: typing.Union[SimplePath, 'LoopPath']) -> None:
        self.path.append(path)
    
    def prepend(self, path: typing.Union[SimplePath, 'LoopPath']) -> None:
        self.path.insert(0, path)
    
    def prepend_meta_path(self, mp: 'MetaPath') -> None:
        tmp = mp.path.copy()
        tmp.reverse()
        for e in tmp:
            self.prepend(e)
    """        
    def get_hash(self) -> bytes:
        current_hash: bytes = bytes(32)
        previous_obj: typing.Union[SimplePath, 'LoopPath'] = SimplePath()
        for p in self.path:
            if isinstance(p, SimplePath) and isinstance(previous_obj, LoopPath):
                current_hash = p.get_hash(current_hash, previous_src_addr=previous_obj.loop_bbs[-1].end_address-3)
            elif isinstance(p, SimplePath):
                current_hash = p.get_hash(current_hash)
            previous_obj = p
            
        return current_hash
    """


    def __repr__(self):
        """name: str = "MetaPath\n"
        other: str = ""
        for e in self.path:
            other += str(e)
        return name+other"""
        name = "MetaPath{\n"
        indented_lines = []
        
        for e in self.path:
            # Split each element's string representation into lines
            for line in str(e).splitlines():
                # Indent each line by 4 spaces
                indented_lines.append("    " + line)
            # Add an extra newline between elements if needed
            indented_lines.append("")
        
        for h in self.hashes:
            indented_lines.append("    " + f"0x{h.hex()}\n")
        
        
        # Join all lines and remove any trailing whitespace
        if self.hash_bytes is not None:
            return name + "\n".join(indented_lines).rstrip() + "\n}"
        else:
            return name + "\n".join(indented_lines).rstrip() + "\n}" #+ f"Hash: 0x{self.get_hash().hex()}"