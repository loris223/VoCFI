"""
TODO
For now it should do all the preprocessing of loops.
"""


from typeguard import typechecked
from basic_block import BasicBlock
from loop_path import LoopPath
from simple_path import SimplePath
from meta_path import MetaPath
from analyzer_hashing import hash_loops
import copy
import logging



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
    res_tmp: list[int] = []
    for bb in backward_bbs:
        tmp: int = bb.cft.get_backward_dest(bb.end_address)
        if tmp not in res_tmp:
            res.append(cfg[tmp])
            res_tmp.append(tmp)
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
        #print(f"None: {l.get_backward_jump_bbs()}")
        #print(f"Entry node: {l.entry_bb}")
        l.set_exit_block(l.get_backward_jump_bbs()[-1])


@typechecked
def correct_continuation_node(cfg: dict[int, BasicBlock], loops: list[LoopPath]) -> None:
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
        if not l.forward_outside_jump_bbs_determined:
            print(f"The forward outside jumps are not determined at the time.")
        exit_bb: BasicBlock = l.get_exit_block()
        dst: int = max(exit_bb.cft.get_destinations() + [b.start_address for b in l.forward_outside_jump_bbs])
        l.set_continuation_block(cfg[dst])

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
def trace_loop_path(bb: BasicBlock, last_bbs: list[BasicBlock], current_loop: LoopPath,
                    loops: list[LoopPath], entry_bbs: list[BasicBlock],
                    cur_sp: SimplePath)-> list[MetaPath]:
    """
    TODO
    """
    # Nested loop
    if (current_loop.entry_bb is not bb) and (bb in entry_bbs):
        # print(f"Jow: {bb}")
        #sp: SimplePath = SimplePath()
        index: int = entry_bbs.index(bb)
        next_loop: LoopPath = loops[index]
        # sp.extension_path = loops[index]
        mp: MetaPath = MetaPath()
        mp.append(cur_sp)
        mp.append(next_loop)
        res: list[MetaPath] = []
        for d in next_loop.forward_outside_jump_bbs:
            # print(f"Next {d}")
            res = res + trace_loop_path(d, last_bbs, current_loop, loops, entry_bbs, SimplePath(inside_loop=True))
            
        
        for r in res:
            r.prepend_meta_path(mp)
        return res
    
    # End condition
    if bb == current_loop.continuation_bb \
        or bb.start_address >= current_loop.continuation_bb.start_address:
        # cur_sp.append(bb)
        mp: MetaPath = MetaPath()
        mp.append(cur_sp)
        return [mp]

    # End condition
    
    if bb in last_bbs:
        res: list[MetaPath] = []
        mp: MetaPath = MetaPath()
        cur_sp.append(bb)
        mp.append(cur_sp)
        res += [mp]
        if bb == current_loop.loop_bbs[-1]:
            return res
        if len(bb.successors_2) <= 1:
            print("Can not happen! Should not happen?")
        bb_x1: BasicBlock = bb.successors_2[0]
        bb_x2: BasicBlock = bb.successors_2[1]
        sp: SimplePath = SimplePath(inside_loop=True)
        sp.path = cur_sp.path.copy()
        if bb_x1 in entry_bbs:
            res += trace_loop_path(bb_x2, last_bbs, current_loop, loops, entry_bbs, sp)
        elif bb_x2 in entry_bbs:
            res += trace_loop_path(bb_x1, last_bbs, current_loop, loops, entry_bbs, sp)

        return res
    
    cur_sp.append(bb)

    res: list[MetaPath] = []
    if len(bb.successors_2) > 1:
        bb_x1: BasicBlock = bb.successors_2[0]
        bb_x2: BasicBlock = bb.successors_2[1]
        # Create new simple path object and copy its contents
        sp: SimplePath = SimplePath(inside_loop=True)
        sp.path = cur_sp.path.copy()

        res = res + trace_loop_path(bb_x1, last_bbs, current_loop, loops, entry_bbs, cur_sp)
        res = res + trace_loop_path(bb_x2, last_bbs, current_loop, loops, entry_bbs, sp)
    elif len(bb.successors_2) == 1:
        bb_x: BasicBlock = bb.successors_2[0]
        res = res + trace_loop_path(bb_x, last_bbs, current_loop, loops, entry_bbs, cur_sp)
    else:
        #print("Problem - trace loop path")
        # It can actually be final node
        pass
    
    return res


@typechecked
def determine_forward_outside_jumps(loop: LoopPath) -> None:
    """
    TODO
    
    """
    for bb in loop.loop_bbs:
        for bb_x in bb.successors_2:
            if bb_x.start_address > loop.exit_bb.end_address:
                loop.forward_outside_jump_bbs.append(bb_x)
                loop.forward_outside_jump_bbs_2.append(bb)
    
    loop.forward_outside_jump_bbs_2 = list(set(loop.forward_outside_jump_bbs_2))

    
@typechecked
def determine_all_loop_blocks(bb: BasicBlock, loop: LoopPath, entry_bbs: list[BasicBlock],
                              loops: list[LoopPath],
                              visited: list[BasicBlock]) -> list[BasicBlock]:
    """
    TODO
    first bb should be the entry block of the loop
    This does not work if the nested loop has not been resolved, maybe can work
    by the pure luck or compiler design but it is not ok. 
    """
    #print("Start")
    #print(bb)

    # We have three conditions that can stop recursion
    # 1. There is a nested loop
    # 2. The BasicBlock has already been visited
    # 3. We have reached continuation node
    if (bb != loop.entry_bb) and (bb in entry_bbs):
        #print("Thhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")
        # TODO
        # Maybe we could just call recursively?
        # Nah
        # Maybe just flag it and deal with that later
        # add loops argument to the function
        # identify child loop and somehow use it
        index: int = entry_bbs.index(bb)
        child_loop: LoopPath = loops[index]
        res: list[BasicBlock] = []
        if child_loop.forward_outside_jump_bbs_determined:
            #print("To se ne zgodi")
            # If the outs of the child loop are determined
            # Then we can follow the paths
            bb_x: BasicBlock
            for bb_x in child_loop.forward_outside_jump_bbs:
                res = res + determine_all_loop_blocks(bb_x, loop, entry_bbs, loops, visited)
        else:
            #print("To se zgodi")
            loop.loop_bbs_determined = False

        return res
    
    #print(f"Continuation node:  {loop.continuation_bb}")
    # Ugly solution this last condition
    # But so is compiler that does that nop instruction which is
    # reached after the loop break is executed
    if (bb in visited) or (bb == loop.continuation_bb) or \
          (bb.start_address > loop.continuation_bb.start_address):
        #print(f"Visited: {visited}")
        #print(f"Pogoji: {(bb in visited)}, {(bb == loop.continuation_bb)}")
        #print("Vracamo")
        return []
    
    # Otherwise we can add this bb to loop block
    res: list[BasicBlock] = [bb]
    # Add to visited blocks
    visited.append(bb)

    # Go through all successors of the block
    #print(f"BB: {bb}")
    #print(f"BB suc: {bb.successors_2}")
    for suc in bb.successors_2:
        #print(f"suc: {suc}")
        res = res + determine_all_loop_blocks(suc, loop, entry_bbs, loops, visited)
        #print(f"res: {res}")
    #print(f"res: {res}")
    return res


@typechecked
def determine_nested_loops\
    (bb: BasicBlock, loop: LoopPath, entry_bbs: list[BasicBlock],
     loops: list[LoopPath], visited: list[BasicBlock]) -> None:
    """
    TODO
    """
    # We have three conditions that can stop recursion
    # 1. There is a nested loop
    # 2. The BasicBlock has already been visited
    # 3. We have reached continuation node

    if (bb in visited) or (bb == loop.continuation_bb):
        return
    
    # Here we are interested in nested loops
    if (bb != loop.entry_bb) and (bb in entry_bbs):
        index: int = entry_bbs.index(bb)
        loops[index].parent = loop
        loop.childs.append(loops[index])
        return
    
    # Add to visited blocks
    visited.append(bb)

    # Go through all successors of the block
    for suc in bb.successors_2:
        determine_nested_loops(suc, loop, entry_bbs, loops, visited)
    

@typechecked
def analyze_loops_function(cfg: dict[int, BasicBlock]) -> list[LoopPath]:
    """
    The process is described in LoopPath
    """
    
    # Identify backward jumps
    backward_bbs: list[BasicBlock] = identify_backward_jumps(cfg)

    # Identify entry basic blocks
    entry_bbs: list[BasicBlock] = identify_entry_bbs(backward_bbs, cfg)
    # print(f"Entry blocks: {entry_bbs}")

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
    determine_exit_node(loops)
    # print(f"Exit node: {loops[0].exit_bb}")
    # determine continuation node
    determine_continuation_node(cfg, loops)

    

    """
    Here we have a problem. The thing is that this three
    things - loop blocks, forward outside jumps and nested
    loops are interconnected. One can not be determined without
    the other being precomputed. It is hard to predefine what 
    has to be precomputed. We could do one big recursion that 
    handles all the cases but it will probably be prone to errors.
    We have to somehow slice it to pieces. Can we define order
    of computiations?
        - We can start with the blocks that don't have childs?
        - Hard to do it in code
    We wil just iteratively do all together. Ugly but should
    be the fastest way to implement.
    """
    changed: bool = True
    while changed:
        ll: list[LoopPath] = loops.copy()
        l: LoopPath
        # determine all loop blocks
        for l in ll:
            if l.loop_bbs_determined:
                continue
            l.loop_bbs_determined = True
            l.loop_bbs = determine_all_loop_blocks(l.entry_bb, l, entry_bbs, loops, [])
            #print("Loop blocks")
            #print(f"Loop blocks determined: {l.loop_bbs_determined}")
            #print(l.loop_bbs)

        # Filter the ones that the loop blocks weren't determined
        ll = [l for l in ll if l.loop_bbs_determined]
        #print(f"Len of ll: {len(ll)}")
        # now that we have all loop blocks
        # we can:
        # determine forward outside jumps
        for l in ll:
            if l.forward_outside_jump_bbs_determined:
                continue
            l.forward_outside_jump_bbs_determined = True
            determine_forward_outside_jumps(l)
        if len(ll) == len(loops):
            changed = False
    
    # Now we can correct continuation node when forward outside jumps were determined
    # correct_continuation_node(cfg, loops)
    # Determine nested loops
    for l in ll:
        determine_nested_loops(l.entry_bb, l, entry_bbs, ll, [])
        #print(f"Childs: {l.childs}")


    # print(f"Continuation node: {loops[0].continuation_bb}")

    #for l in ll:
    #    print(f"Loop")
    #    print(f"Entry bb: {l.entry_bb}")
    #    print(f"Exit bb: {l.exit_bb}")
    #    print(f"Exits: {l.forward_outside_jump_bbs}")

    # Now the loop tracing
    
    meta_paths: list[MetaPath]
    print(f"\n\nRESULT OF LOOP ANALYZATION:")
    if len(loops) == 0:
        print("No loops detected.")
    for i, l in enumerate(loops):
        l.backward_jump_bbs
        last_bbs: list[BasicBlock] = l.backward_jump_bbs.copy()
        # There shouldn't be a need for continuation block to be in there but just to be on the safe side.
        last_bbs.append(l.continuation_bb)
        res: list[MetaPath] = trace_loop_path(l.entry_bb, last_bbs, l, loops, entry_bbs, SimplePath(inside_loop=True))
        l.path = res
        hash_loops(l)
        print(f"-------------------------- Loop {i} ------------------------------------------")
        print(f"{l}")
        print(f"----------------------------------------------------------------------------")

    """
    meta_paths: list[MetaPath]
    lp: SimplePath
    for lp in loop_paths:
        mp: MetaPath = MetaPath()
        mp.append(lp)
        if lp.to_be_extended:
            mp.append(lp.extension_path)
        meta_paths.append(mp)
    
    changed = True
    while changed:
        for mp in meta_paths:
            pass
        changed = False
    """            
            
    """
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
    """
    return loops
            

@typechecked
def analyze_loops(all_cfgs: dict[str, dict[int, BasicBlock]])\
    -> dict[str, list[LoopPath]]:
    """
    TODO
    """
    logging.info("Starting to analyze loops.")
    result: dict[str, list[LoopPath]] = {}

    for name, cfg in all_cfgs.items():
        logging.info(f"Analyzing loops in function: {name}")
        res: list[LoopPath] = analyze_loops_function(cfg)
        result[name] = res

    logging.info("Ending loop analyzation.")
    return result


if __name__ == "__main__":
    print("TODO")