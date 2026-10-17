# The Bytecode Bakery

- **Event:** NexSec CTF 2026
- **Category:** Reverse Engineering
- **Difficulty:** Easy / Medium
- **Flag:** `nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}`

---

## Challenge

> The Bytecode Bakery oven bakes a recipe (bytecode) using the ingredient list
> (your input). If the recipe accepts your ingredients, you have found the flag.

**Files:** `oven.py`, `recipe.bin`

`oven.py` is a tiny stack virtual machine. It loads `recipe.bin`, asks me for an
"ingredient list" (a string), and runs the recipe against it. The recipe returns
true for exactly one 50-character string — that string is the flag.

---

## The VM

Reading `oven.py`, the recipe is a flat array of bytecode executed by a stack
machine. The header is `BAKE`, a version byte, a one-byte input length, and a
two-byte code length; then the code. The opcodes are:

| Op | Name | Effect |
|----|------|--------|
| `0x01` | `PUSH imm` | push the next byte |
| `0x02` | `PUSHIN i` | push `input[i]` |
| `0x03` | `ADD` | `a + b` (mod 256) |
| `0x04` | `SUB` | `a - b` (mod 256) |
| `0x05` | `XOR` | `a ^ b` |
| `0x06` | `ROL` | rotate `a` left by `b & 7` (8-bit) |
| `0x07` | `EQ` | push `1` if `a == b` else `0` |
| `0x08` | `JNZ t` | pop; jump to `t` if non-zero |
| `0x09` | `JMP t` | unconditional jump |
| `0x0A` | `RET false` | dough collapsed |
| `0x0B` | `RET true` | fresh from the oven |
| `0x0C` | `DUP` | duplicate top |
| `0x0D` | `AND` | `a & b` |

All arithmetic is 8-bit. The header says `input_len = 0x32 = 50`, so the flag is
exactly 50 characters.

---

## First thing I noticed: a decoy

The very first instruction of the recipe is:

```
0x0000: 09 ec 00     JMP 0x00ec
```

So execution jumps straight to `0x00ec`, and the whole block from `0x0003` to
`0x00eb` is **dead code** — it never runs. And it's not empty filler; it's a
full set of plausible-looking checks:

```
0x0003: 01 01        PUSH 0x01
0x0005: 02 00        PUSHIN 0      ; in[0]
0x0007: 01 f2        PUSH 0xf2
0x0009: 05           XOR
0x000a: 01 9c        PUSH 0x9c
0x000c: 07           EQ
0x000d: 0d           AND
...
```

It's a trap. If I disassemble from the top and start solving those constraints, I
get a believable-but-wrong 50-byte string. The real checks are the ones reachable
from `0x00ec`, so that's the only region that matters.

---

## The real routine

From `0x00ec` the code is extremely regular: a seed, then one check-block per
input byte. The first block:

```
0x00ec: 01 01        PUSH 0x01     ; seed the accumulator = 1
0x00ee: 02 00        PUSHIN 0      ; in[0]
0x00f0: 01 aa        PUSH 0xaa
0x00f2: 05           XOR           ; in[0] ^ 0xaa
0x00f3: 01 8b        PUSH 0x8b
0x00f5: 05           XOR           ; ^ 0x8b
0x00f6: 01 07        PUSH 0x07
0x00f8: 06           ROL           ; rotate-left 7
0x00f9: 01 dd        PUSH 0xdd
0x00fb: 04           SUB           ; - 0xdd
0x00fc: 01 ca        PUSH 0xca
0x00fe: 07           EQ            ; == 0xca ?
0x00ff: 0d           AND           ; fold into accumulator
```

Every following block looks the same except it starts by combining the current
byte with the previous one:

```
0x0100: 02 01        PUSHIN 1      ; in[1]
0x0102: 02 00        PUSHIN 0      ; in[0]
0x0104: 05           XOR           ; in[1] ^ in[0]
0x0105: 01 97        PUSH 0x97
0x0107: 05           XOR
0x0108: 01 03        PUSH 0x03
0x010a: 06           ROL
0x010b: 01 dc        PUSH 0xdc
0x010d: 03           ADD
0x010e: 01 c0        PUSH 0xc0
0x0110: 07           EQ
0x0111: 0d           AND
```

So each block is:

```
t = (in[i] ^ in[i-1]) ^ K_i          # block 0 uses in[0] alone
t = ROL(t, R_i)
t = (t + C_i) or (t - C_i)           # ADD or SUB, varies per block
accumulator &= (t == Z_i)
```

with per-block constants `K_i, R_i, C_i, Z_i` baked into the bytecode. After all
50 blocks the tail is:

```
...          JNZ 0x0476    ; if accumulator != 0 ...
0x0475: 0a   RET false
0x0476: 0b   RET true      ; ... bake succeeds
```

The key observation: **block 0 constrains `in[0]` by itself, and block `i`
constrains `in[i]` only together with the already-known `in[i-1]`.** That chain
structure means I don't need a general solver — I can peel the bytes off one at a
time, left to right.

---

## Solving it

I let the program tell me its own constants instead of transcribing them. The
solver parses the header, follows the entry `JMP` to the real routine, splits it
into blocks at each `AND`, and then for each position brute-forces the single
printable byte (`0x20`–`0x7e`) that makes that block's `EQ` succeed given the
previous byte. Each position had exactly one solution.

```python
#!/usr/bin/env python3
"""The Bytecode Bakery - recipe.bin solver."""
import os, struct, sys

PUSH, PUSHIN, ADD, SUB, XOR, ROL, EQ, JNZ, JMP, RETF, RETT, DUP, AND = range(1, 14)
OPLEN = {PUSH: 2, PUSHIN: 2, JNZ: 3, JMP: 3}


def load(path):
    blob = open(path, "rb").read()
    assert blob[:4] == b"BAKE", "not a recipe file"
    version, input_len = blob[4], blob[5]
    code_len = struct.unpack("<H", blob[6:8])[0]
    assert version == 1, "unsupported version"
    return input_len, blob[8:8 + code_len]


def decode(code, start, stop):
    pc, out = start, []
    while pc < stop:
        op = code[pc]
        if op in (JMP, JNZ):
            out.append((op, code[pc + 1] | code[pc + 2] << 8))
        elif op in (PUSH, PUSHIN):
            out.append((op, code[pc + 1]))
        else:
            out.append((op, None))
        pc += OPLEN.get(op, 1)
    return out


def eval_block(block, inp):
    st = []
    for op, arg in block:
        if op == PUSH:    st.append(arg)
        elif op == PUSHIN: st.append(inp[arg])
        elif op == ADD:   b, a = st.pop(), st.pop(); st.append((a + b) & 0xFF)
        elif op == SUB:   b, a = st.pop(), st.pop(); st.append((a - b) & 0xFF)
        elif op == XOR:   b, a = st.pop(), st.pop(); st.append(a ^ b)
        elif op == ROL:
            n, v = st.pop() & 7, st.pop()
            st.append(((v << n) | (v >> (8 - n))) & 0xFF)
        elif op == EQ:    b, a = st.pop(), st.pop(); st.append(1 if a == b else 0)
    return st[-1]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "recipe.bin")
    n, code = load(path)

    entry = decode(code, 0, 3)[0]            # the decoy-skipping JMP
    assert entry[0] == JMP
    instrs = decode(code, entry[1], len(code))

    blocks, cur = [], []                     # cut the routine at each AND
    for op, arg in instrs:
        if op in (JNZ, RETF, RETT):
            break
        cur.append((op, arg))
        if op == AND:
            blocks.append(cur[:-1]); cur = []
    assert len(blocks) == n

    sol = [0] * n                            # peel bytes off left to right
    for i, blk in enumerate(blocks):
        hits = [c for c in range(0x20, 0x7F)
                if eval_block(blk, sol[:i] + [c] + [0] * (n - i - 1))]
        assert len(hits) == 1, (i, hits)
        sol[i] = hits[0]

    print(bytes(sol).decode())


if __name__ == "__main__":
    main()
```

---

## Running it

```console
$ python solve.py recipe.bin
nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}

$ echo 'nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}' | python oven.py recipe.bin
Enter ingredient list: Fresh from the oven! Submit your ingredient list as the flag.
```

## Flag

```
nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}
```

## Takeaways

- **Follow control flow before you solve anything.** The entry `JMP` makes the
  first, most obvious block dead code; solving it gives a clean-looking wrong
  answer. Disassembling and checking reachability first saves a lot of pain.
- **Chained constraints collapse a search.** Because each byte depends only on
  itself and the one before it, a brute force that would be `95^50` naively
  becomes `50 * 95` — solved byte by byte.
- **Let the bytecode carry its own constants.** Parsing the blocks straight out of
  `recipe.bin` (rather than copying ~200 magic numbers by hand) keeps the solver
  short and removes transcription mistakes.
