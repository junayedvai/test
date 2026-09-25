# Dead Link — bcsctf pwn writeup

> *"A collector for the dead internet. Recently patched and declared stable. The
> auditors found nothing left to fix."*

Flag format: `bcsctf{*}`

---

## 1. Recon

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       enabled
PIE:      enabled
SHSTK / IBT: enabled     (CET)
Not stripped
libc:     Ubuntu glibc 2.35 (Ubuntu 22.04)
```

Every mitigation is on, so we need a full leak set (PIE, libc, stack, canary)
and a controlled arbitrary write. The service is a classic heap note manager
("Dead Link node") behind a proof-of-work-style gate.

### Menu

```
Add a node      malloc(size+0x10); node = {next, size, data[size]}; append to list
Delete a node   unlink + free; keeps the freed pointer in a global bin[]
Change a node   re-read node->size bytes into node->data
Print all nodes prints each node->data
View recycle bin prints bin[i]: next=*(bin[i]) size=*(bin[i]+8) data=bin[i]+0x10
Exit
```

Node layout (16-byte header):

```
+0x00  next   (list link)
+0x08  size
+0x10  data...
```

---

## 2. The gate

`gate()` reads 32 random bytes from `/dev/urandom` into `gate_token`, prints them
as hex, and then requires 32 bytes back. The check (from the disassembly) is:

```
((i*7) ^ input[i] ^ 0xC3) & 0xff == token[i]
```

so the answer is simply:

```python
answer[i] = token[i] ^ 0xC3 ^ ((7*i) & 0xFF)
```

The gate also prints a **PIE leak** disguised as a diagnostic:

```
[*] Diagnostics: system() @ 0x....369
```

That address is **not** `system` — it is the internal `dead_filter` function
(offset `0x1369`). So:

```python
pie_base = leak - exe.sym["dead_filter"]
```

---

## 3. The bugs

### Bug 1 — off-by-one NUL overflow (`read_with_null`)

`read_with_null(fd, buf, n)` does:

```c
r = read(0, buf, n);
if (r <= 0) _exit(0);
if (buf[r-1] == '\n') buf[r-1] = 0;
else                  buf[r]   = 0;   // <-- writes buf[n] when r == n
```

If you send **exactly `n` bytes** and the last one isn't `\n`, it writes a NUL at
`buf[n]` — one byte past the data buffer, straight into the next chunk's size
field. That is a **poison-null-byte / House of Einherjar** primitive. `change()`
re-reads with the *stored* `node->size`, so the overflow is fully repeatable.

### Bug 2 — recycle-bin UAF read (`delete` / `binview`)

`delete()` frees a node but **keeps its pointer in the global `bin[]` array**, and
`binview()` dereferences those stale pointers:

```
Bin(i): next=*(bin[i])  size=*(bin[i]+8)  data=(char*)bin[i]+0x10
```

* On a freed chunk this leaks `fd` (safe-linked heap pointer) and, for an unsorted
  chunk, `main_arena` (libc).
* If we can make a `bin[]` entry point at an **arbitrary address**, `binview`
  becomes an **arbitrary read**.

### The troll

`.rodata` contains a decoy flag `bcsctf{f@ke_f1ag_1n_th3_b1n}`. The description
("auditors found nothing left to fix") and the string literally saying *fake flag
in the bin* bait players who only reach the recycle-bin leak. The real flag is in
`flag.txt`, reachable only via code execution.

---

## 4. Exploitation

### 4.1 Heap leak (safe-linking)

Allocate two `0x40` chunks, free the head twice, and read the recycle bin:

* `Bin(0).next` on the first free = the safe-linking **key** (`heap>>12`).
* `Bin(1).next` on the second free = encoded `fd`; `fd ^ key` = real chunk address.

### 4.2 Arbitrary read via a fake bss node

Groom `A | B(0x400) | C1 | C2` plus seven `0x400` fillers so that freeing `B`
misses tcache and consolidates. Using bug 1, forge a fake chunk inside `A`, set
`B.prev_size`, and null `B.size`'s low byte (`0x401 -> 0x400`). Freeing `B`
consolidates backward; a subsequent large allocation (`D`) returns a chunk that
**overlaps `A`**, giving overlapping control.

Free `C2` then `C1` into `tcache[0x100]`, and use the `A/D` overlap (bug 1 again)
to overwrite `C1->fd` with a safe-linked pointer to a **fake node at
`pie+0x5050`** — i.e. `bin - 0x10`. Two allocations later, that fake node is a
live list entry whose `data` region **is the `bin[]` array**. Writing it sets
`bin[0]` and `bin_cnt`, so:

```python
def leak_qword(addr):
    set_bin_ptr(addr)      # change(fake_node): bin[0]=addr, bin_cnt=1
    return parse_bin(viewbin())   # binview prints *(addr)
```

With arbitrary read:

* `printf@GOT` → libc base
* `environ` → a stack address
* scan the stack for the saved return address into `main` (`pie+0x200b`, the
  instruction after `call binview`) → `saved_rip`
* `*(saved_rip-0x10)` → canary, `*(saved_rip-0x8)` → saved RBP

### 4.3 Arbitrary write → ROP

Repeat the poison, this time aiming a `tcache[0x100]` chunk at the saved return
frame, and let `add()`'s data read write a short ROP chain:

```
ret ; pop rdi ; rdi = "cat flag.txt" ; system
```

`add()` fixes up the (correct) canary in place, so the stack check passes and the
function returns straight into the chain.

---

## 5. The bug that made the first attempt EOF (and the fix)

The original exploit aimed the final chunk at `saved_rip - 0x28`. `add()` runs,
immediately after `malloc`:

```asm
mov QWORD [rax], 0        ; node->next = 0
mov edx, [rbp-0x1c]       ; edx = requested size
mov [rax+8], rdx          ; node->size = size
...
mov eax, [rbp-0x1c]       ; size passed to read_with_null
```

`add()`'s own `size` local lives at `[rbp-0x1c] == saved_rip-0x24`. With a target
of `saved_rip-0x28`, the `node->next = 0` store (`saved_rip-0x28 .. saved_rip-0x20`)
**covers `saved_rip-0x24` and zeroes the size local**. `read_with_null` is then
called with length `0`, `read` returns `0`, and it calls `_exit(0)`.

Confirmed with a faithful glibc-2.35 harness under `strace`:

```
read(0, "232\n", 9) = 4          # size = 232 = 0xe8
write(1, "Data?", 5) = 5
read(0, "", 0)      = 0          # <-- length 0!
exit_group(0)                    # clean exit -> your "Got EOF"
```

**Fix:** use `stack_target = saved_rip - 0x38`.

* Header stores (`next`,`size`) now land at `saved_rip-0x38 / -0x30`, **below**
  `add()`'s locals, so the size local survives.
* The data read starts at `saved_rip-0x28`, which is **above** `read_with_null`'s
  own frame/canary (so we don't smash its canary), and still reaches up through
  `add()`'s canary (`saved_rip-0x10`), saved RBP, and return slot.

`0x38` is essentially the only viable offset: `>= 0x30` to spare the size local,
`< 0x40` to stay above `read_with_null`'s frame, and 16-byte aligned for the
tcache `aligned_OK` check.

Chain layout (data starts at `saved_rip-0x28`):

```
saved_rip-0x10 : canary        (add() re-validates -> passes)
saved_rip-0x08 : saved RBP
saved_rip+0x00 : ret           (16-byte align for system's movaps)
saved_rip+0x08 : pop rdi ; ret
saved_rip+0x10 : cmd_addr  ---> "cat flag.txt"
saved_rip+0x18 : system
saved_rip+0x20 : "cat flag.txt\0"
```

Also: do **not** send menu option `7`/out-of-range afterward — that path calls
`_exit`. The ROP fires when the final `add()` itself returns.

---

## 6. Run

```bash
# local (faithful glibc 2.35 harness)
python3 solve_deadlink.py

# remote
python3 solve_deadlink.py REMOTE            # uses HOST/PORT env or defaults
HOST=172.16.38.22 PORT=6656 python3 solve_deadlink.py REMOTE
```

The script prints all leaks and then `cat flag.txt`.

---

## 7. Notes / caveats

* All leak stages (heap key, PIE, libc, environ, canary, saved RIP) reproduce
  exactly, matching the values seen against the live service.
* The second poison round (House of Einherjar) is sensitive to the exact
  allocator state of the target's glibc build; if the final `add()` returns a
  heap pointer instead of `stack_target` on your box, re-verify the `A/D` overlap
  offsets (`c1_off`) against your libc and, if needed, sweep `OFF` around `0x38`.
* Full RELRO + removed malloc/free hooks (glibc ≥ 2.34) rule out GOT/hook
  overwrites — hijacking a saved return address is the intended path.
