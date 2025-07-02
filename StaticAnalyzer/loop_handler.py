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


@typechecked
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
def determine_exit_nodes(loops: list[LoopPath]) -> None:
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
def determine_continuation_nodes(cfg: dict[int, BasicBlock], loops: list[LoopPath]) -> None:
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
                entry_bbs: list[BasicBlock])-> SimplePath:
    """
    TODO
    """
    # Nested loop
    if (current_loop.entry_bb is not bb) and (bb in entry_bbs):
        sp: SimplePath = SimplePath()
        sp.set_end_loop_bb(bb)
        sp.to_be_extended = True
        return sp
    # End condition
    if bb in last_bbs:
        sp: SimplePath = SimplePath()
        sp.append(bb)
        # TODO
        # add successors
        sp.to_be_extended = True
        sp.loop_end = True
        return sp
    
    # Add loop basic block
    current_loop.loop_bbs.append(bb)

    # Result
    res: SimplePath

    # Get all destinations of basic block
    dests = bb.cft.get_destinations()
    if len(dests) > 1:
        # If there is a junction we should make an end to current
        # Simple Path and then follow both ways and make new SimplePath
        res = SimplePath()
        res.append(bb)
        p1: SimplePath = trace_loop_path(func_cfg[dests[0]], func_cfg, last_bbs, current_loop, entry_bbs)
        p2: SimplePath = trace_loop_path(func_cfg[dests[1]], func_cfg, last_bbs, current_loop, entry_bbs)
        res.add_successor(p1)
        res.add_successor(p2)
    else:
        res: SimplePath = trace_loop_path(func_cfg[dests[0]], func_cfg, last_bbs, current_loop, entry_bbs)
        res.prepend(bb)
    #for d in dests:
    #    res = res + trace_loop_path(func_cfg[d], func_cfg, last_bbs, current_loop, entry_bbs)
        #print(res)

    #list(map(lambda x: x.prepend(bb), res))
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

    # print(loops[0].entry_bb)

    # Group barckward jumps
    group_backward_jumps(backward_bbs, entry_bbs, loops)

    # determine exit node
    determine_exit_nodes(loops)
    # print(f"Exit node: {loops[0].exit_bb}")
    # determine continuation node
    determine_continuation_nodes(cfg, loops)

    # print(f"Continuation node: {loops[0].continuation_bb}")

    # These are paths for every loop starting 
    # with entry node but the continuation could
    # follow via SimplePath linkeage like tree
    simple_paths: list[SimplePath] = []
    for e, l in zip(entry_bbs, loops):
        sp: SimplePath = trace_loop_path\
            (e, cfg, [l.exit_bb, l.continuation_bb], l, entry_bbs)
        print(l)
        l.path = sp
        simple_paths.append(sp)
    #print(simple_paths)
    
    # If the simple path ends with another loop
    # we should link those simple paths
    for sp in SimplePath.SIMPLE_PATHS:
        if sp.ends_with_loop:
            #print(sp)
            index: int = entry_bbs.index(sp.ends_with_loop_bb)
            sp.link_paths.append(simple_paths[index])
            sp.to_be_extended = False
    
    print(SimplePath.SIMPLE_PATHS)
            

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