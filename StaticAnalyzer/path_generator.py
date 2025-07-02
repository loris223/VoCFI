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
from simple_path import SimplePath
from typing import Optional
from loop_handler import analyze_loops
logging.basicConfig(level=logging.DEBUG)







@typechecked
def trace_path(bb: BasicBlock, func_cfg: dict[int, BasicBlock],\
               last_bb: BasicBlock)-> SimplePath:
    """
    TODO
    """
    # End condition
    if bb.start_address == last_bb.start_address:
        sp: SimplePath = SimplePath()
        sp.append(bb)
        return sp
    elif bb.is_loop:
        sp: SimplePath = SimplePath()
        sp.set_end_loop_bb(bb)
        sp.to_be_extended = True
        return sp
    
    # Result
    res: Optional[SimplePath] = None

    # Get all destinations of basic block
    dests = bb.cft.get_destinations()
    if len(dests) > 1:
        res = SimplePath()
        res.append(bb)
        p1: SimplePath = trace_path(func_cfg[dests[0]], func_cfg, last_bb)
        p2: SimplePath = trace_path(func_cfg[dests[1]], func_cfg, last_bb)
        res.add_successor(p1)
        res.add_successor(p2)
    else:
        res: SimplePath = trace_path(func_cfg[dests[0]], func_cfg, last_bb)
        res.prepend(bb)

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
def get_unextended_paths(sp: SimplePath) -> list[SimplePath]:
    pass

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
    print("Trace path")
    res: SimplePath = trace_path(first_bb, func_cfg, last_bb)
    print(res)

    
    """
    while was_extended:
        was_extended = False
        for sp in res:
            if sp.get_last_bb().start_address != last_bb.start_address:
                was_extended = True
                new_start_1: Optional[BasicBlock] = sp.get_ends_with_loop()
                new_start_2: Optional[BasicBlock] = sp.get_ends_with_path()
                if (new_start_1 is not None) and (new_start_2 is not None):
                    print("Something wrong. - generate_paths_of_function")
                elif new_start_1 is not None:
                    #tmp_res: list[SimplePath] = trace_loop(new_start_1, func_cfg, last_bb)
                    #sp.assign_successor_list(tmp_res)
                    pass
                elif new_start_2 is not None:
                    tmp_res: list[SimplePath] = trace_path(new_start_2, func_cfg, last_bb)
                    sp.assign_successor_list(tmp_res)
                else:
                    print("Something wrong. - generate_paths_of_function")
    """





@typechecked
def generate_all_paths(all_cfgs: dict[str, dict[int, BasicBlock]]):
    """
    TODO
    """
    logging.info("Starting to generate all paths of all functions.")
    func_name: str
    func_cfg: dict[int, BasicBlock]
    
    analyze_loops(all_cfgs)
    for func_name, func_cfg in all_cfgs.items():
        # trace_loop(func_name, func_cfg)
        generate_paths_of_function(func_name, func_cfg)

