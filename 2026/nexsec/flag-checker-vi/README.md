# Flag Checker VI

- **Event:** NexSec CTF 2026
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Flag:** `nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}`

---

## Challenge

> My friend just downloaded **GTA FLAGCHECKER VI** for his new PlayStation 5 Pro.
> The game asks for a password upon initial launch. Find the correct password!!

**Files:** `flagchecker.zip`

The "game" is a PS5 homebrew that prompts for a password on launch. One 40-character
string gets accepted — that string is the flag.

The CTF only allowed **DeepSeek** as an AI assistant, so I worked through it with
DeepSeek prompt-by-prompt and did everything in plain Python (no IDA, no Ghidra). My
full session is here: https://chat.deepseek.com/share/i909iqbwid1go3gga4

---

## Getting the files out

First annoyance: extracting `flagchecker.zip` with the normal Windows "Extract All"
just gave me **empty folders**. That's the tell-tale sign of a password-protected / AES
zip — Explorer and PowerShell's `Expand-Archive` don't support those and silently
produce nothing.

The zip password shipped with the challenge, so I used 7-Zip:

```cmd
"C:\Program Files\7-Zip\7z.exe" x flagchecker.zip -p1f315b89b575d6cf8cdf093a6184a956 -oflagchecker_out
```

Since I was staying in Python anyway, the equivalent is:

```python
import pyzipper
with pyzipper.AESZipFile("flagchecker.zip") as z:
    z.setpassword(b"1f315b89b575d6cf8cdf093a6184a956")
    z.extractall("flagchecker_out")
```

That gave me the real contents:

```
flagchecker/
├── eboot.bin          # 314 KB, the actual game logic
└── sce_sys/           # PS5 package metadata (icon, param.json, trophies) - ignore
```

`eboot.bin` is a PS5 homebrew executable, and its header is a standard **x86-64 ELF**
(the PS5 runs a FreeBSD-derived OS), so this is just ordinary static reversing.

---

## Recon

I didn't have the `strings` command or IDA, so I wrote a `strings` + ELF-header dump in
Python:

```python
import re, struct
d = open("eboot.bin", "rb").read()

# strings
for m in re.finditer(rb"[\x20-\x7e]{5,}", d):
    print(hex(m.start()), m.group().decode())

# program headers (where is the executable segment?)
e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phnum, = struct.unpack_from("<H", d, 0x38)
for i in range(e_phnum):
    off = e_phoff + i * 0x38
    p_type, p_flags = struct.unpack_from("<II", d, off)
    p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", d, off + 8)
    print(hex(p_type), "flags", p_flags, "off", hex(p_offset),
          "vaddr", hex(p_vaddr), "size", hex(p_filesz))
```

The strings were useless — only library names (`libkernel.prx`, `libScePad.prx`, …) and
NID symbol hashes. No `nexsec26{`, no "wrong password" message. So the password isn't
stored anywhere; it's checked by code.

The program headers showed the first `PT_LOAD` segment is the executable one
(flags `5` = `r-x`): file offset `0x4000`, virtual address `0x0`, size `0x8000`. The
check lives in there.

---

## Finding the check

`capstone` handles the disassembly:

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
d = open("eboot.bin", "rb").read()
code = d[0x4000:0x4000 + 0x8000]        # the r-x segment
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(code, 0x0):
    print(f"{ins.address:#06x}: {ins.mnemonic} {ins.op_str}")
```

Right at the start of the segment is the checker:

```asm
0x00f0: xor eax, eax
0x00f2: test rdi, rdi
0x00f5: je  0x9c3             ; null input -> return 0
0x00fb: cmp esi, 0x28
0x00fe: jne 0x9c3             ; length must be 0x28 (40) -> else return 0
...
0x0115: movzx r15d, byte ptr [rdi + 6]
0x011a: movzx r8d,  byte ptr [rdi + 0x14]
0x011f: movzx r14d, byte ptr [rdi + 0x17]
...
```

So it's `check(char *input /*rdi*/, int len /*esi*/)`: the input must be **exactly 40
bytes** and it reads every byte from `[rdi+0]` to `[rdi+0x27]`.

After the loads comes a long run of blocks that each look like this:

```asm
0x0124: lea ecx, [r8 + r15]      ; (b[0x14] + b[6])
0x0128: or  ecx, r14d            ; | b[0x17]
0x012b: xor ecx, r8d             ; ^ b[0x14]
0x012e: cmp ecx, 0xae            ; must equal 0xae
0x0134: jne 0x9b2                ; else -> the single shared fail exit
```

Every block mixes a handful of input bytes with `+`, `*` (`imul`), `^`, `&`, `|`, `-`,
compares the result against a constant, and `jne`s to one common failure label. Fall
through **all** of them and the function does `sete al` / returns 1.

There's nothing to read out of the binary here — it's a **system of equations** over the
40 input bytes. Solving it by hand would be brutal, so I handed it to Z3.

---

## Solving it

I translated every compare block into one Z3 constraint. Two gotchas mattered:

- **Everything is 32-bit.** Each byte is `movzx`-ed into a 32-bit register and all the
  arithmetic happens there, so the wraparound and the negative compares
  (e.g. `cmp ..., 0xffffff46`) only match if the bytes are modelled as **32-bit
  BitVecs**, not 8-bit.
- **One block is `test` / `jne`, not `cmp`.** `test r11d, edx; jne fail` means that
  `AND` has to be **zero** to pass, so it becomes `(... & ...) == 0`.

Constraining each byte to printable ASCII makes Z3 return the readable flag directly. A
few of the blocks (all 65 are in [`solve.py`](./solve.py)):

```python
from z3 import *
b = [BitVec(f"b{i}", 32) for i in range(0x28)]
s = Solver()
for x in b:
    s.add(x >= 0x20, x <= 0x7e)

s.add(((b[0x14] + b[6]) | b[0x17]) ^ b[0x14] == 0xae)       # C1
s.add(((b[0x10] ^ b[0x21]) | b[0x27]) * b[0] == 0x35b6)     # C2
s.add(b[0x19] * b[0x17] - b[0x11] - b[0xf] == 0x2334)       # C3
# ... 62 more, one per block ...
s.add((((b[0x24] & b[0xa]) ^ b[0x1e]) + b[0xc]) == 0x64)    # C65
```

There are **65 constraints** in total.

---

## Running it

```console
$ python solve.py
nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
```

The script also adds "give me a different solution" and gets back `unsat`, so this is the
**one and only** 40-character input that passes — exactly the password the game wants.

## Flag

```
nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
```

## Takeaways

- **Empty folders after extraction = encrypted zip.** Windows' built-in extractor fails
  silently on password-protected / AES archives; reach for 7-Zip (or `pyzipper`) and the
  files appear.
- **No `strings` hit means the check is in code.** When the flag isn't anywhere in the
  binary, stop grepping and go find the comparison routine.
- **A wall of `cmp`/`jne` blocks is a system of equations.** Don't solve it by hand — model
  each block as a constraint and let Z3 do it. The only real work is reading the asm
  correctly, especially the 32-bit arithmetic and the `test`/`jne` (`== 0`) block.
- The flag text (`c4n_w3_pl4y_gta6_0n_w1nd0w5???`) is just the author having fun — this is
  a homebrew crackme, not an actual Rockstar title.
