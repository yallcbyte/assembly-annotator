"""Ready-made listings, used by the Examples menu."""

EXAMPLES = [
    {
        'id': 'loop_sum',
        'name': 'Counted loop (x86, NASM)',
        'blurb': 'Adds 5+4+3+2+1 with a LOOP counter, then exits.',
        'code': """section .text
    global _start

_start:
    mov ecx, 5              ; loop counter
    xor eax, eax            ; running total

loop_start:
    add eax, ecx
    loop loop_start

    ; eax now holds 5 + 4 + 3 + 2 + 1
    mov ebx, eax
    mov eax, 1
    int 0x80
""",
    },
    {
        'id': 'password_check',
        'name': 'Licence check (x86)',
        'blurb': 'Classic prologue, magic-constant comparison and branch.',
        'code': """check_licence:
    push ebp
    mov ebp, esp
    sub esp, 0x20

    mov eax, [ebp+8]        ; the key the user typed
    cmp eax, 0x1337C0DE     ; compare against the magic value
    jne .denied

    mov eax, 1              ; return true
    jmp .done

.denied:
    xor eax, eax            ; return false

.done:
    mov esp, ebp
    pop ebp
    ret
""",
    },
    {
        'id': 'shellcode',
        'name': 'execve("/bin/sh") shellcode (x86)',
        'blurb': 'Stack-built string, zeroed registers, direct syscall.',
        'code': """_start:
    xor eax, eax
    push eax
    push 0x68732f2f         ; "//sh"
    push 0x6e69622f         ; "/bin"
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov al, 11              ; execve
    int 0x80
""",
    },
    {
        'id': 'x64_write',
        'name': 'Hello world (x86-64, Linux)',
        'blurb': '64-bit syscall convention with RAX/RDI/RSI/RDX.',
        'code': """section .data
    msg db "Hello, world", 10
    len equ $ - msg

section .text
    global _start

_start:
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, msg
    mov rdx, len
    syscall

    mov rax, 60             ; sys_exit
    xor rdi, rdi
    syscall
""",
    },
    {
        'id': 'att_syntax',
        'name': 'AT&T syntax (GAS)',
        'blurb': 'Source-first operand order with % and $ sigils.',
        'code': """    .globl main
main:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    $42, %eax
    addl    $8, %eax
    cmpl    $50, %eax
    jne     .L2
    movl    $1, %eax
.L2:
    popq    %rbp
    ret
""",
    },
    {
        'id': 'arm64',
        'name': 'AArch64 function',
        'blurb': 'ARM64 prologue with STP, and an SVC system call.',
        'code': """_start:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    mov x0, #1              // stdout
    adrp x1, msg
    mov x2, #13
    mov x8, #64             // write
    svc #0

    mov x8, #93             // exit
    mov x0, #0
    svc #0
""",
    },
    {
        'id': 'anti_debug',
        'name': 'Anti-analysis tricks',
        'blurb': 'Timing checks, CPUID fingerprinting and a NOP sled.',
        'code': """detect:
    rdtsc
    mov esi, eax

    cpuid                   ; hypervisor fingerprint
    rdtsc
    sub eax, esi
    cmp eax, 0x10000
    ja  being_debugged

    nop
    nop
    nop
    nop
    jmp carry_on

being_debugged:
    int3
    hlt

carry_on:
    ret
""",
    },
    {
        'id': 'objdump',
        'name': 'objdump output',
        'blurb': 'Pasted straight from a disassembler, addresses and all.',
        'code': """0000000000001129 <main>:
    1129:	55                   	push   %rbp
    112a:	48 89 e5             	mov    %rsp,%rbp
    112d:	48 83 ec 10          	sub    $0x10,%rsp
    1131:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1138:	8b 45 fc             	mov    -0x4(%rbp),%eax
    113b:	83 c0 01             	add    $0x1,%eax
    113e:	89 45 fc             	mov    %eax,-0x4(%rbp)
    1141:	c9                   	leave
    1142:	c3                   	ret
""",
    },
]

BY_ID = {e['id']: e for e in EXAMPLES}
