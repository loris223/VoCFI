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

import os
from typeguard import typechecked
from basic_block import BasicBlock
from control_flow_type import ControlFlowType
import logging
from simple_path import SimplePath
from typing import Optional
from loop_handler import analyze_loops
from loop_path import LoopPath
from meta_path import MetaPath
from analyzer_hashing import hash_meta_paths
logging.basicConfig(level=logging.DEBUG)







@typechecked
def trace_path(bb: BasicBlock, last_bb: BasicBlock,
               cur_sp: SimplePath) -> list[MetaPath]:
    """
    TODO
    """
    # Loop encounter
    if bb in LoopPath.ENTRY_BLOCKS:
        index: int = LoopPath.ENTRY_BLOCKS.index(bb)
        next_loop: LoopPath = LoopPath.LOOP_PATHS[index]
        mp: MetaPath = MetaPath()
        mp.append(cur_sp)
        mp.append(next_loop)
        res: list[MetaPath] = []
        for d in next_loop.forward_outside_jump_bbs:
            res = res + trace_path(d, last_bb, SimplePath())
        for r in res:
            r.prepend_meta_path(mp)
        return res
    
    # End condition
    if bb == last_bb:
        cur_sp.append(bb)
        mp: MetaPath = MetaPath()
        mp.append(cur_sp)
        return [mp]
    
    cur_sp.append(bb)
    # Result
    res: list[MetaPath] = []

    # Get all destinations of basic block
    if len(bb.successors_2) > 1:
        bb_x1: BasicBlock = bb.successors_2[0]
        bb_x2: BasicBlock = bb.successors_2[1]

        # Create new simple path object and copy its contents
        sp: SimplePath = SimplePath()
        sp.path = cur_sp.path.copy()

        res = res + trace_path(bb_x1, last_bb, cur_sp)
        res = res + trace_path(bb_x2, last_bb, sp)
    elif len(bb.successors_2) == 1:
        bb_x: BasicBlock = bb.successors_2[0]
        res = res + trace_path(bb_x, last_bb, cur_sp)
    else:
        print("Problem - trace path")

    return res




@typechecked
def get_unextended_paths(sp: SimplePath) -> list[SimplePath]:
    pass

@typechecked
def generate_paths_of_function(func_name: str, func_cfg: dict[int, BasicBlock]) -> list[MetaPath]:
    """
    TODO
    """
    logging.info(f"Generating possible paths of function: {func_name=} TODO")

    # Get the first bb of the function
    addr: int
    first_bb: BasicBlock
    addr, first_bb = sorted(func_cfg.items())[0]
    addr2, last_bb = sorted(func_cfg.items())[-1]

    # When we have the first block it is time to trace
    # all the others
    logging.info("Trace path")
    res: list[MetaPath] = trace_path(first_bb, last_bb, SimplePath())
    print(f"\n\nRESULT OF PATH TRACING:")
    for i, r in enumerate(res):
        hash_meta_paths(r)
        print(f"-------------------------- PATH {i} ------------------------------------------")
        print(f"{r}")
        print(f"----------------------------------------------------------------------------")
    return res


def get_entry_hashes(loop_id: int, all_paths: list[list[MetaPath]]):
    res = []
    for func_paths in all_paths:
        for m_path in func_paths:
            for i, el in enumerate(m_path.path):
                if el.id == loop_id:
                    if(i > 0):
                        #print(f"TODO: 0x{m_path.path[i-1].hash_bytes.hex()}")
                        res.append(m_path.path[i-1].hash_bytes)
    return res
    
    
    
def write_results_to_file(all_loops: dict[str, list[LoopPath]], all_paths: list[list[MetaPath]]):
    riscv_path = os.getenv('RISCV')
    if riscv_path:
        file_path = os.path.join(riscv_path, 'analyzer_output')
        with open(file_path, 'w') as f:
            f.write("LOOPS\n")
            for name, loops in all_loops.items():
                for l in loops:
                    f.write("LOOP\n")
                    f.write("ENTRIES\n")
                    entry_hashes = get_entry_hashes(l.id, all_paths)
                    for h in entry_hashes:
                        f.write("0x" + str(h.hex()))
                        f.write("\n")
                    if len(entry_hashes) == 0:
                        f.write("0x" + '0' * 64)
                        f.write("\n")
                    f.write("PATHS\n")
                    for h in l.hashes:
                        f.write("0x" + str(h.hex()))
                        f.write("\n")
                    f.write("\n")
            f.write("MAIN PATHS\n")
            for l1 in all_paths:
                for l2 in l1:
                    for h in l2.hashes:
                        f.write("0x" + str(h.hex()))
                        f.write("\n")
        
        print(f"File created at: {file_path}")
    else:
        print("RISCV environment variable is not set")




@typechecked
def generate_all_paths(all_cfgs: dict[str, dict[int, BasicBlock]]):
    """
    TODO
    """
    logging.info("Starting to generate all paths of all functions.")
    func_name: str
    func_cfg: dict[int, BasicBlock]
    
    all_loops: dict[str, list[LoopPath]] = analyze_loops(all_cfgs)

    all_paths: list[list[MetaPath]] = []
    for func_name, func_cfg in all_cfgs.items():
        # trace_loop(func_name, func_cfg)
        all_paths += [generate_paths_of_function(func_name, func_cfg)]
    
    
    write_results_to_file(all_loops, all_paths)

