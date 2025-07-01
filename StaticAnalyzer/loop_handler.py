"""
TODO
For now it should do all the preprocessing of loops.
"""


from typeguard import typechecked
from basic_block import BasicBlock
from loop_path import LoopPath
from simple_path import SimplePath



@typechecked
def identify_backward_jumps(cfg: dict[int, BasicBlock]) -> list[BasicBlock]:
    """
    Finds all basic blocks which can jump backward. 
    """
    res: list[BasicBlock] = []
    for addr, bb in cfg.items():
        if bb.cft.goes_backwards(bb.end_address):
            res.append(bb)
    return res


@typechecked
def identify_entry_bbs(backward_bbs: list[BasicBlock],
                       cfg: dict[int, BasicBlock]) -> list[BasicBlock]:
    """
    Find all entry basic blocks.
    """
    res: list[BasicBlock] = []
    for bb in backward_bbs:
        res.append(cfg[bb.cft.get_backward_dest(bb.end_address)])
    return res


def group_backward_jumps(backward_bbs: list[BasicBlock],
                         entry_bbs: list[BasicBlock],
                         loops: list[LoopPath]) -> None:
    """
    TODO
    """
    bb_enty_bbs_addrs: list[int] = \
        [bb.start_address for bb in entry_bbs]

    for bb in backward_bbs:
        bb_dst: int = bb.cft.get_backward_dest(bb.end_address)
        index: int = bb_enty_bbs_addrs.index(bb_dst)
        loops[index].add_backward_jump_bb(bb)
        


@typechecked
def determine_exit_node(loops: list[LoopPath]) -> None:
    """
    TODO
    """

    for l in loops:
        """
        bbs: list[BasicBlock] = l.get_backward_jump_bbs()
        end_addrs: list[int] = [bb.end_address for bb in bbs]
        index_max = max(range(len(end_addrs)), key=end_addrs.__getitem__)
        l.set_continuation_block(bbs[index_max])
        """
        l.sort_backward_jump_bbs()
        l.set_exit_block(l.get_backward_jump_bbs()[-1])


@typechecked
def determine_continuation_node(cfg: dict[int, BasicBlock], loops: list[LoopPath]) -> None:
    """
    TODO
    """

    """
    bbs: list[BasicBlock] = l.get_backward_jump_bbs()
    end_addrs: list[int] = [bb.end_address for bb in bbs]
    index_max = max(range(len(end_addrs)), key=end_addrs.__getitem__)
    l.set_continuation_block(bbs[index_max])
    """
    for l in loops:
        exit_bb: BasicBlock = l.get_exit_block()
        dst: int = max(exit_bb.cft.get_destinations())
        l.set_continuation_block(cfg[dst])



@typechecked
def trace_loop_path(bb: BasicBlock, func_cfg: dict[int, BasicBlock],\
               last_bbs: list[BasicBlock], current_loop: LoopPath,\
                entry_bbs: list[BasicBlock])-> list[SimplePath]:
    """
    TODO
    """
    # Nested loop
    if (current_loop.entry_bb is not bb) and (bb in entry_bbs):
        sp: SimplePath = SimplePath()
        sp.set_end_loop_bb(bb)
        return [sp]
    # End condition
    if bb in last_bbs:
        sp: SimplePath = SimplePath()
        sp.append(bb)
        return [sp]
    
    
    current_loop.loop_bbs.append(bb)

    # Result
    res: list[SimplePath] = []

    # Get all destinations of basic block
    dests = bb.cft.get_destinations()
    for d in dests:
        res = res + trace_loop_path(func_cfg[d], func_cfg, last_bbs, current_loop, entry_bbs)
        #print(res)

    list(map(lambda x: x.prepend(bb), res))
    return res


@typechecked
def determine_forward_outside_jumps() -> None:
    """
    TODO
    Maybe we should trace paths in loops and
    afterwards find forward outside jumps
    """



@typechecked
def analyze_loops_function(cfg: dict[int, BasicBlock]):
    """
    The process is described in Looppath
    """
    
    # Identify backward jumps
    backward_bbs: list[BasicBlock] = identify_backward_jumps(cfg)

    # Identify entry basic blocks
    entry_bbs: list[BasicBlock] = identify_entry_bbs(backward_bbs, cfg)
    print(f"Entry blocks: {entry_bbs}")

    # based on entry blocks create loops
    loops: list[LoopPath] = []
    for entry_bb in entry_bbs:
        lp: LoopPath = LoopPath()
        lp.set_entry_bb(entry_bb)
        loops.append(lp)

    print(loops[0].entry_bb)

    # Group barckward jumps
    group_backward_jumps(backward_bbs, entry_bbs, loops)

    # determine exit node
    determine_exit_node(loops)
    print(f"Exit node: {loops[0].exit_bb}")
    # determine continuation node
    determine_continuation_node(cfg, loops)

    print(f"Continuation node: {loops[0].continuation_bb}")

    for e, l in zip(entry_bbs, loops):
        sp_list: list[SimplePath] = trace_loop_path\
            (e, cfg, [l.exit_bb, l.continuation_bb], l, entry_bbs)
        print(sp_list)



    


@typechecked
def analyze_loops(all_cfgs: dict[str, dict[int, BasicBlock]]):
    """
    TODO
    """
    print("Starting to analyze loops.")

    for name, cfg in all_cfgs.items():
        print(f"Analyzing loop: {name}")
        analyze_loops_function(cfg)

    print("Ending loop analyzation.")



if __name__ == "__main__":
    print("TODO")