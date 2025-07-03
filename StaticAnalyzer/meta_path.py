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
    some other way of handling loops there is a need for this.
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
        name: str = "MetaPath\n"
        other: str = ""
        for e in self.path:
            other += str(e)
        return name+other