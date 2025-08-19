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

    def append(self, path: typing.Union[SimplePath, 'LoopPath']) -> None:
        self.path.append(path)
    
    def prepend(self, path: typing.Union[SimplePath, 'LoopPath']) -> None:
        self.path.insert(0, path)
    
    def prepend_meta_path(self, mp: 'MetaPath') -> None:
        tmp = mp.path.copy()
        tmp.reverse()
        for e in tmp:
            self.prepend(e)

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
        
        # Join all lines and remove any trailing whitespace
        return name + "\n".join(indented_lines).rstrip() + "\n}"