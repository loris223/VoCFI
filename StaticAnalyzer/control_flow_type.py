"""
TODO
The class should make it easier to gather instruction type
and then to save destination address or addresses. And 
it should make it easier to print out branch type.
"""
from capstone.riscv import RISCV_INS_BEQ, RISCV_INS_BNE, RISCV_INS_BLT, \
    RISCV_INS_BGE, RISCV_INS_BLTU, RISCV_INS_BGEU, RISCV_INS_JAL, \
    RISCV_INS_JALR

BRANCH_TYP = 1
UNCOND_TYP = 2
INDIRECT_TYP = 3
NONCTF_TYP = 4

class ControlFlowType:
    VALID_TYPES = [
        'jal', 'jalr', 'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu'
    ]
    
    BRANCHES_IDS = [
        RISCV_INS_BEQ, RISCV_INS_BNE, RISCV_INS_BLT,
        RISCV_INS_BGE, RISCV_INS_BLTU, RISCV_INS_BGEU
    ]

    JUMPS_IDS = [
        RISCV_INS_JAL, RISCV_INS_JALR
    ]

    VALID_IDS = BRANCHES_IDS + JUMPS_IDS

    # type is of main importance for this to work
    # 0 - not set
    # 1 - branch
    # 2 - unconditional jump
    # 3 - indirect jump
    # 4 - non control flow instruction


    def __init__(self, id, description="TODO"):
        self.description = description
        self.id = id
        if self.id in self.BRANCHES_IDS:
            self.insn_type = 1
        elif self.id == RISCV_INS_JAL:
            self.insn_type = 2
        elif self.id == RISCV_INS_JALR:
            self.insn_type = 3
        else:
            self.insn_type = 4
        
        self.condition_taken_addr = -1
        self.condition_not_taken_addr = -1
        self.destination_addr = -1
        self.desc = "Not set"
        self.desc_1 = "Not set"
        self.desc_2 = "Not set"
    

    def set_condition_taken_addr(self, addr, desc="Not set"):
        if self.insn_type == BRANCH_TYP:
            self.condition_taken_addr = addr
            self.desc_1 = desc
        else:
            raise ValueError(f"{id} is not of type branch.")
    
    def set_condition_not_taken_addr(self, addr, desc="Not set"):
        if self.insn_type == BRANCH_TYP:
            self.condition_not_taken_addr = addr
            self.desc_2 = desc
        else:
            raise ValueError(f"{id} is not of type branch.")
    
    def set_destination_addr(self, addr, desc="Not set"):
        if self.insn_type != BRANCH_TYP:
            self.destination_addr = addr
            self.desc = desc
        else:
            raise ValueError(f"{id} is not of type branch.")
        
    def get_destinations(self):
        res = []
        if self.insn_type == BRANCH_TYP:
            res = [self.condition_taken_addr, self.condition_not_taken_addr]
        elif self.insn_type in [UNCOND_TYP, NONCTF_TYP]:
            res = [self.destination_addr]
        return res
    
    def goes_backwards(self, bb_end_addr):
        dests = self.get_destinations()
        for d in dests:
            if d < bb_end_addr:
                return True
        
    def get_backward_dest(self, bb_end_addr):
        # Should make better
        if self.goes_backwards(bb_end_addr):
            dests = self.get_destinations()
            for d in dests:
                if d < bb_end_addr:
                    return d
        else:
            return None
    

    def is_branch(self):
        return self.id in self.BRANCHES_IDS
    
    def __repr__(self):
        return self.__to_str__()

    def __str__(self):
        return self.__to_str__()
    
    def __to_str__(self):
        return self.description
    
    def is_linking(self):
        if self.id == RISCV_INS_JALR:
            return True
        else:
            return False