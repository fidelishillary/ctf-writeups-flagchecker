#!/usr/bin/env python3
"""Flag Checker VI - eboot.bin solver.

The check function at the start of the code segment reads 40 input bytes,
b[0x00]..b[0x27], gates on length == 0x28, then enforces 65 arithmetic/bitwise
constraints before returning true. No plaintext compare, so I turn every block
into a Z3 constraint and solve the system.

All math in the binary runs in 32-bit registers (movzx byte -> 32-bit), so the
bytes are modelled as 32-bit BitVecs to reproduce wraparound and the negative
compares exactly.

    pip install z3-solver
"""
from z3 import *

b = [BitVec(f"b{i}", 32) for i in range(0x28)]
s = Solver()

# the flag is printable ASCII
for x in b:
    s.add(x >= 0x20, x <= 0x7e)

# --- one constraint per compare block, in order ---
s.add(((b[0x14] + b[6]) | b[0x17]) ^ b[0x14] == 0xae)                      # C1
s.add(((b[0x10] ^ b[0x21]) | b[0x27]) * b[0] == 0x35b6)                    # C2
s.add(b[0x19] * b[0x17] - b[0x11] - b[0xf] == 0x2334)                      # C3
s.add(((b[0x13] ^ b[0x27] ^ b[0x15]) | b[0x16]) == 0x77)                   # C4
s.add((((b[0x22] | b[0x25]) & b[0x1a]) + b[0x22]) == 0xa7)                 # C5
s.add((((b[0xe] | b[0x1e]) - b[0x22]) | b[0x22]) == 0xffffffff)            # C6
s.add((((b[0xe] + b[0x16]) - b[2]) ^ b[0x19]) == 0x70)                     # C7
s.add((((b[0x23] * b[0xe]) | b[9]) & b[0x16]) == 0x64)                     # C8
s.add((((b[0x1e] + b[5]) * b[9]) & b[6]) == 0x30)                          # C9
s.add(((b[9] ^ b[0x25] ^ b[0x20]) * b[0x23]) == 0xb98)                     # C10
s.add((((b[0xd] | b[6]) ^ b[0x19]) * b[4]) == 0xfc8)                       # C11
s.add((b[0x17] * b[6] - (b[0x15] + b[0xa])) == 0x1257)                     # C12
s.add((((b[0x1f] ^ b[0xd]) | b[0x16]) ^ b[0x25]) == 0x42)                  # C13
s.add(b[9] - (b[0x16] + b[3] + b[7]) == 0xffffff46)                        # C14
s.add(b[0x1f] == 0x6e)                                                     # C15
s.add((((b[5] + b[0x23]) | b[0xc]) ^ b[0x17]) == 0xbe)                     # C16
s.add((b[0xe] - b[0x22] + b[2] + b[0x1c]) == 0x93)                         # C17
s.add((((b[7] | b[0x1f]) - b[5]) * b[0x12]) == 0x57c)                      # C18
s.add(((b[0x25] - b[0x21] - b[0x17]) ^ b[4]) == 0xffffffcb)                # C19
s.add(((b[0x1a] * b[0x14] * b[4]) ^ b[0x20]) == 0x70774)                   # C20
s.add((((b[0xc] | b[4]) * b[5]) + b[0xc]) == 0x317c)                       # C21
s.add((b[0x1b] + b[0x23]) * b[4] - b[6] == 0x401d)                         # C22
s.add((((b[0x1b] | b[4]) - b[0x10]) & b[0x20]) == 0x64)                    # C23
s.add((((b[0x23] | b[0xf]) ^ b[0x20]) | b[0x1b]) == 0x7f)                  # C24
s.add((((b[0x1d] ^ b[0x1c]) + b[0x11]) * b[0x17]) == 0x3814)               # C25
s.add((((b[0x1c] * b[0x1a]) + b[0x15]) | b[7]) == 0x1237)                  # C26
s.add((((b[0x26] & b[0]) * b[0xa]) + b[0x10]) == 0x9c8)                    # C27
s.add((((b[0x10] * b[0x21]) & b[0x19]) & b[8]) == 0)                       # C28 (test/jne)
s.add((((b[0x1f] * b[0xa]) ^ b[0x1e]) + b[3]) == 0x16dc)                   # C29
s.add((((b[0xb] | b[0x1a]) ^ b[0x14]) - b[0x27]) == 0xffffffa4)            # C30
s.add((((b[0x1e] | b[6]) + b[8]) * b[7]) == 0x24b4)                        # C31
s.add((b[0xa] ^ b[8] ^ b[0x1a] ^ b[2]) == 7)                               # C32
s.add((((b[2] & b[0x19]) * b[0xe]) ^ b[0x26]) == 0x11b7)                   # C33
s.add(((b[0x1d] & b[0x11]) + b[2] + b[0x22]) == 0x153)                     # C34
s.add(((b[0x12] | b[0x1e]) - b[7]) == 0xffffffff)                          # C35
s.add(((b[0x20] - 2 * b[0x21]) & b[0x25]) == 4)                            # C36
s.add((((b[0x24] | b[0x26]) ^ b[6]) & b[0x23]) == 5)                       # C37
s.add(((b[0xe] * b[0x15]) - b[8] - b[0x18]) == 0x13d4)                     # C38
s.add((((b[3] & b[0x19]) + b[0x24]) ^ b[0x1c]) == 0xcd)                    # C39
s.add((((b[0x15] * b[0x21]) | b[0x10]) + b[0x22]) == 0x13e7)               # C40
s.add(((b[0x1c] | b[0x13] | b[0x1b]) * b[9]) == 0x311d)                    # C41
s.add((((b[2] - b[0x17]) & b[0x24]) * b[0xd]) == 0xab1)                    # C42
s.add((((b[0x1b] & b[0x16]) ^ b[8]) - b[0x13]) == 0xffffffa6)              # C43
s.add((((b[0x12] & b[0x17]) ^ b[0x19]) * b[0xa]) == 0x19cc)                # C44
s.add((((b[0x18] & b[3]) | b[0xb]) - b[0x1c]) == 0x1f)                     # C45
s.add(((b[0x27] - b[0x1c] + b[0x18]) & b[8]) == 0x50)                      # C46
s.add((b[0] + b[6]) * b[0x22] + b[0x1f] == 0x4ace)                         # C47
s.add((((b[0x12] + b[0x15]) | b[0x18]) & b[0xd]) == 0x37)                  # C48
s.add(((b[3] & b[0x21] & b[0x26]) * b[4]) == 0x12f0)                       # C49
s.add((b[0x16] + b[0x1e] + b[0] + b[0x21]) == 0x143)                       # C50
s.add((((b[2] | b[0x1e]) & b[0x14]) * b[0x10]) == 0x26f0)                  # C51
s.add(((b[2] * b[0xf]) | b[0xd]) == 0x2cff)                                # C52
s.add((((b[0x19] & b[1]) - b[0x18]) ^ b[0x1d]) == 0x78)                    # C53
s.add((((b[0xb] ^ b[7]) | b[0x1c]) ^ b[0x17]) == 0x3e)                     # C54
s.add((((b[0x1e] | b[0x13]) * b[0xb]) ^ b[6]) == 0x33cc)                   # C55
s.add((((b[0x17] ^ b[0xf]) - b[0x26]) | b[0x27]) == 0xffffffff)            # C56
s.add((((b[0x10] + b[7]) ^ b[0x1d]) + b[0xe]) == 0x104)                    # C57
s.add((b[0xe] + b[0x14]) * b[0xa] + b[0x11] == 0x1e14)                     # C58
s.add((((b[0x1c] & b[7]) ^ b[0]) - b[0x14]) == 0x19)                       # C59
s.add(((b[0xb] + b[0xc] + b[0x18]) * b[7]) == 0x36a2)                      # C60
s.add((b[0] - b[8]) + b[0x1f] * b[0x18] == 0x1727)                         # C61
s.add(((b[0x1e] - (b[0x25] + b[0xc])) | b[1]) == 0xfffffff7)               # C62
s.add(((b[0x1b] | b[0xf] | b[0x24]) ^ b[0x18]) == 0x49)                    # C63
s.add(((b[0x26] & b[9]) - (b[0x13] + b[0x21])) == 0xffffff7a)              # C64
s.add((((b[0x24] & b[0xa]) ^ b[0x1e]) + b[0xc]) == 0x64)                   # C65

assert s.check() == sat, "no solution"
m = s.model()
flag = bytes(m[b[i]].as_long() for i in range(0x28))
print(flag.decode())

# prove the solution is unique
s.add(Or([b[i] != m[b[i]] for i in range(0x28)]))
assert s.check() == unsat, "solution is not unique"
