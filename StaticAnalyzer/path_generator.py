"""
CFGs possible paths generator.

It accepts CFG of a program and generates
all possible valid paths that the program 
can take.
TODO

Example:
    >>> generate_paths('firmware.elf')
    
"""
"""
To enable efficient run-time loop detection, we utilize a
property of RISC architectures that implement a link-register,
such as PowerPC, ARM, SPARC, and RISC-V. LO-FAT uses
a simple heuristic to differentiate between backward branches
that constitute loops, and branches for subroutine calls where
the call target resides earlier in memory. Since subroutine
calls use instructions that update the link-register, we con-
sider the target of each non-linking backwards branch as
a loop entry node. The basic block proceeding the branch
instruction is considered a loop exit node. We base our heuris-
tic on our observations of the RISC-V compiler assembly and
the calling convention described in the instruction manual:
any subroutine call with multiple call sites must be linking
and updates the link-register. Subroutines with a single call
site are still compiled as a linking branch or are optimized
by traditional inlining using the RISC-V compiler.
"""

from typeguard import typechecked
from basic_block import BasicBlock
from control_flow_type import ControlFlowType
import logging
logging.basicConfig(level=logging.DEBUG)





@typechecked
def get_loops(func_name: str, func_cfg: dict[int, BasicBlock]):
    """
    TODO
    """
    logging.info(f"Detecting loops in function {func_name}.")
    start_addr: int
    bb: BasicBlock
    for start_addr, bb in func_cfg.items():
        end_addr = bb.instructions[-1].address
        cft: ControlFlowType = bb.cft
        if cft.is_linking():
            continue
        if cft.goes_backwards(end_addr):
            logging.info(f"Backwards jump detected! This should be some kind of loop.")


@typechecked
def trace_path(bb: BasicBlock, func_cfg: dict[int, BasicBlock],\
               last_bb: BasicBlock)-> list[list[BasicBlock]]:
    """
    TODO
    """
    # End condition
    if bb.start_address == last_bb.start_address:
        return [[last_bb]]
    
    # Result
    res: list[list[BasicBlock]] = []

    # Get all destinations of basic block
    dests = bb.cft.get_destinations()
    for d in dests:
        res = res + trace_path(func_cfg[d], func_cfg, last_bb)
        
    res = list(map(lambda x: [bb] + x, res))
    return res


@typechecked
def mark_loops(func_cfg: dict[int, BasicBlock]) -> None:
    """
    TODO
    """
    addr: int
    bb: BasicBlock
    for addr, bb in func_cfg.items():
        if bb.cft.goes_backwards(bb.end_address):
            bb.is_loop = True


@typechecked
def generate_paths_of_function(func_name: str, func_cfg: dict[int, BasicBlock]):
    """
    TODO
    """
    logging.info(f"Generating possible paths of function: {func_name=} TODO")

    # Get the first bb of the function
    addr: int
    first_bb: BasicBlock
    addr, first_bb = sorted(func_cfg.items())[0]
    addr2, last_bb = sorted(func_cfg.items())[-1]

    # First mark loop entries
    mark_loops(func_cfg)
    # When we have the first block it is time to trace
    # all the others
    res = trace_path(first_bb, func_cfg, last_bb)
    print(res)




@typechecked
def generate_all_paths(all_cfgs: dict[str, dict[int, BasicBlock]]):
    """
    TODO
    """
    logging.info("Starting to generate all paths of all functions.")
    func_name: str
    func_cfg: dict[int, BasicBlock]
    for func_name, func_cfg in all_cfgs.items():
        get_loops(func_name, func_cfg)
        generate_paths_of_function(func_name, func_cfg)

