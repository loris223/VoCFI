import hashlib
from typing import Optional
import typing
from loop_path import LoopPath
from simple_path import SimplePath
from meta_path import MetaPath
from typeguard import typechecked

hash_size: int = 32

@typechecked
def hash_branch_addrs(prev_hash: Optional[bytes], src: int, dst: int) -> bytes:
    # Initialize BLAKE2b hasher
    hasher = hashlib.blake2b(digest_size=hash_size)  # crypto_generichash_BYTES is 32 by default in Libsodium
    
    # If prev_hash is provided, update with its data; otherwise, use zeros
    if prev_hash is not None:
        hasher.update(prev_hash)
    else:
        zero_hash = bytes(64)  # Zero-initialized array of size 64
        hasher.update(zero_hash)
    
    # Hash source address (as little-endian bytes, assuming x86/ARM architecture)
    hasher.update(src.to_bytes(8, byteorder='little'))
    
    # Hash destination address (as little-endian bytes)
    hasher.update(dst.to_bytes(8, byteorder='little'))
    
    # Return the final digest
    return hasher.digest()

@typechecked
def hash_simple_paths(sp: SimplePath, current_hash: bytes = None) -> bytes:
    if current_hash is None:
        current_hash = bytes(hash_size)
    
    # Go through all blocks of simple path
    for i in range(len(sp.path)-1):
        # There are cases (SimpleLoop for example) where are two basic blocks
        # of the loop. But there are two because the previous code jumps to the
        # second block to evaluate condition before executing actual code which
        # is in the first block. So there are two but actually it is just one
        # for lo-fat since it does not have branch/jump instruction after first
        # block. So we need to leave out those. It is meaningfull to include them 
        # but it is just very space demanding to do it in spike since you would have
        # to keep in memory all the jumps/blocks...
        if sp.path[i].cft.insn_type == 4:
            #print(f"{self.path[i-1].cft.insn_type}, {self.path[i].cft.insn_type}")
            continue
        #print(f"Previous hash: 0x{current_hash.hex()}")
        #print(f"Hashing: 0x{sp.path[i].end_address-3:x} -> 0x{sp.path[i+1].start_address:x}")
        current_hash = hash_branch_addrs(current_hash, sp.path[i].end_address-3, sp.path[i+1].start_address)
        sp.hashed_sequence += [(sp.path[i].end_address-3, sp.path[i+1].start_address)]
    sp.hash_bytes = current_hash
    return current_hash

@typechecked
def hash_meta_paths(mp: MetaPath, current_hash: typing.Optional[bytes] = None) -> list[bytes]:
    if current_hash is None:
        current_hash = bytes(hash_size)

    #if len(mp.hashes) > 0:
    #    return mp.hashes

    
    previous_obj: typing.Optional[typing.Union[SimplePath, 'LoopPath']] = None
    possible_hashes: list[bytes] = [current_hash]
    for p in mp.path:
        if isinstance(p, SimplePath) and isinstance(previous_obj, LoopPath):
            loop_exit_addrs: list[int] = [(b.end_address - 3) for b in previous_obj.forward_outside_jump_bbs_2]
            #loop_exit_addr: int = previous_obj.loop_bbs[-1].end_address-3
            sp_entry_addr: int = p.path[0].start_address
            p.hashed_sequence += [(loop_exit_addrs[0], sp_entry_addr)] # The list should fork!!
            new_possible_hashes: list[bytes] = []
            for c_h in possible_hashes:
                for addr in loop_exit_addrs:
                    new_possible_hashes.append(hash_branch_addrs(c_h, addr, sp_entry_addr))
            possible_hashes = new_possible_hashes

        if isinstance(p, SimplePath):
            new_possible_hashes: list[bytes] = []
            for c_h in possible_hashes:
                new_possible_hashes.append(hash_simple_paths(p, c_h))
            possible_hashes = new_possible_hashes
        
        if isinstance(p, LoopPath):
            hash_loops(p)
        previous_obj = p
    mp.hash_bytes = current_hash
    mp.hash_bytes = possible_hashes[0]
    mp.hashes += possible_hashes
    return possible_hashes


@typechecked
def hash_loops(loop: LoopPath,current_hash: typing.Optional[bytes] = None):
    if current_hash is None:
        current_hash = bytes(hash_size)
    
    if len(loop.hashes) > 0:
        return

    possible_entries: list[bytes] = []
    for bb in loop.backward_jump_bbs:
        possible_entries.append(hash_branch_addrs(current_hash, bb.end_address-3, loop.entry_bb.start_address))
        loop.hashed_sequence.append((bb.end_address-3, loop.entry_bb.start_address))
   
    # because it is a loop path we first need to hash last block jumping to the first one
    # current_hash = hash_branch_addrs(current_hash, loop.loop_bbs[-1].end_address-3, loop.loop_bbs[0].start_address)
    
    #hash_copy:bytes = current_hash
    for pe in possible_entries:
        current_hash = pe
        for p in loop.path:
            new_hashes = hash_meta_paths(p, current_hash)
            loop.hashes += new_hashes
        



# Example usage:
if __name__ == "__main__":
    # Example variables (you can replace these with actual data)
    prev_hash_example = None  # or some bytes of length 64
    src_example = 123456789
    dst_example = 987654321
    
    result = hash_branch_addrs(prev_hash_example, src_example, dst_example)
    print("Hash result:", result.hex())