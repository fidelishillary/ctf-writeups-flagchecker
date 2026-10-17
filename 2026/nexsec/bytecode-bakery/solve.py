#!/usr/bin/env python3
"""The Bytecode Bakery — recipe.bin solver.

recipe.bin is bytecode for the little stack VM in oven.py. The program
checks a 50-byte "ingredient list" (our input) and returns true only for
the one correct string, which is the flag.

Approach:
  1. Parse the header and follow the entry JMP to the *real* routine
     (the block before it is a decoy that is jumped over and never runs).
  2. The real routine is one check-block per input byte, each ending in
     EQ then AND. Block 0 constrains in[0] alone; block i (i>0) constrains
     in[i] together with in[i-1]. So every byte is pinned by the byte
     before it.
  3. Split the routine into blocks, then solve greedily left to right:
     for each position, the single printable byte that makes its block's
     EQ succeed (given the already-fixed previous byte).

Usage:  python solve.py [recipe.bin]
"""
import os
import struct
import sys

# opcodes (from oven.py)
PUSH, PUSHIN, ADD, SUB, XOR, ROL, EQ, JNZ, JMP, RETF, RETT, DUP, AND = range(1, 14)
OPLEN = {PUSH: 2, PUSHIN: 2, JNZ: 3, JMP: 3}  # bytes incl. operand(s); rest are 1


def load(path):
    blob = open(path, "rb").read()
    assert blob[:4] == b"BAKE", "not a recipe file"
    version, input_len = blob[4], blob[5]
    code_len = struct.unpack("<H", blob[6:8])[0]
    assert version == 1, "unsupported version"
    return input_len, blob[8:8 + code_len]


def decode(code, start, stop):
    """Decode code[start:stop] into (opcode, operand_or_None) instructions."""
    pc, out = start, []
    while pc < stop:
        op = code[pc]
        if op == JMP or op == JNZ:
            out.append((op, code[pc + 1] | code[pc + 2] << 8))
        elif op in (PUSH, PUSHIN):
            out.append((op, code[pc + 1]))
        else:
            out.append((op, None))
        pc += OPLEN.get(op, 1)
    return out


def eval_block(block, inp):
    """Run one check-block on a fresh stack; return the EQ result (top)."""
    st = []
    for op, arg in block:
        if op == PUSH:
            st.append(arg)
        elif op == PUSHIN:
            st.append(inp[arg])
        elif op == ADD:
            b, a = st.pop(), st.pop(); st.append((a + b) & 0xFF)
        elif op == SUB:
            b, a = st.pop(), st.pop(); st.append((a - b) & 0xFF)
        elif op == XOR:
            b, a = st.pop(), st.pop(); st.append(a ^ b)
        elif op == ROL:
            n, v = st.pop() & 7, st.pop()
            st.append(((v << n) | (v >> (8 - n))) & 0xFF)
        elif op == EQ:
            b, a = st.pop(), st.pop(); st.append(1 if a == b else 0)
    return st[-1]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "recipe.bin")
    n, code = load(path)

    # Entry must be the JMP that skips the decoy; start at its target.
    entry = decode(code, 0, 3)[0]
    assert entry[0] == JMP, "expected entry JMP"
    real_start = entry[1]

    # Decode the real routine and cut it into blocks at each AND.
    # (Stop at the first control-flow op: JNZ/RETF/RETT mark the tail.)
    instrs = decode(code, real_start, len(code))
    blocks, cur = [], []
    for op, arg in instrs:
        if op in (JNZ, RETF, RETT):
            break
        cur.append((op, arg))
        if op == AND:
            blocks.append(cur[:-1])  # drop the AND itself
            cur = []
    assert len(blocks) == n, f"got {len(blocks)} blocks, expected {n}"

    # Which input indices each block reads.
    deps = [sorted({a for op, a in b if op == PUSHIN}) for b in blocks]

    # Solve greedily, left to right.
    sol = [0] * n
    for i, (blk, dep) in enumerate(zip(blocks, deps)):
        assert dep and max(dep) == i, f"block {i} has unexpected deps {dep}"
        hits = [c for c in range(0x20, 0x7F)
                if eval_block(blk, sol[:i] + [c] + [0] * (n - i - 1))]
        if len(hits) != 1:
            raise SystemExit(f"byte {i}: {len(hits)} candidates {hits!r}")
        sol[i] = hits[0]

    print(bytes(sol).decode())


if __name__ == "__main__":
    main()
