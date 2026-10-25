"""Linux system-call tables.

Turns `mov eax, 4 / int 0x80` into "write() — write to a file descriptor",
which is usually the single most useful annotation in a shellcode listing.
"""

# i386, selected via EAX with `int 0x80`
LINUX_X86 = {
    1: ('exit', 'terminate the process'),
    2: ('fork', 'create a child process'),
    3: ('read', 'read from a file descriptor'),
    4: ('write', 'write to a file descriptor'),
    5: ('open', 'open a file'),
    6: ('close', 'close a file descriptor'),
    7: ('waitpid', 'wait for a child process'),
    8: ('creat', 'create a file'),
    9: ('link', 'create a hard link'),
    10: ('unlink', 'delete a file'),
    11: ('execve', 'replace this process with a new program'),
    12: ('chdir', 'change the working directory'),
    15: ('chmod', 'change file permissions'),
    19: ('lseek', 'reposition a file offset'),
    20: ('getpid', 'get the process ID'),
    23: ('setuid', 'set the user ID'),
    24: ('getuid', 'get the user ID'),
    37: ('kill', 'send a signal to a process'),
    39: ('mkdir', 'create a directory'),
    41: ('dup', 'duplicate a file descriptor'),
    42: ('pipe', 'create a pipe'),
    45: ('brk', 'change the heap break'),
    54: ('ioctl', 'device control operation'),
    57: ('setpgid', 'set the process group'),
    63: ('dup2', 'duplicate a file descriptor onto another'),
    90: ('mmap', 'map memory'),
    91: ('munmap', 'unmap memory'),
    102: ('socketcall', 'socket operation (socket/bind/connect/listen/accept)'),
    119: ('sigreturn', 'return from a signal handler'),
    120: ('clone', 'create a thread or process'),
    125: ('mprotect', 'change memory protection flags'),
    162: ('nanosleep', 'sleep for an interval'),
    174: ('rt_sigaction', 'install a signal handler'),
    192: ('mmap2', 'map memory'),
}

# x86-64, selected via RAX with `syscall`
LINUX_X64 = {
    0: ('read', 'read from a file descriptor'),
    1: ('write', 'write to a file descriptor'),
    2: ('open', 'open a file'),
    3: ('close', 'close a file descriptor'),
    4: ('stat', 'get file status'),
    8: ('lseek', 'reposition a file offset'),
    9: ('mmap', 'map memory'),
    10: ('mprotect', 'change memory protection flags'),
    11: ('munmap', 'unmap memory'),
    12: ('brk', 'change the heap break'),
    13: ('rt_sigaction', 'install a signal handler'),
    16: ('ioctl', 'device control operation'),
    22: ('pipe', 'create a pipe'),
    32: ('dup', 'duplicate a file descriptor'),
    33: ('dup2', 'duplicate a file descriptor onto another'),
    39: ('getpid', 'get the process ID'),
    41: ('socket', 'create a socket'),
    42: ('connect', 'connect a socket'),
    43: ('accept', 'accept a connection'),
    44: ('sendto', 'send on a socket'),
    45: ('recvfrom', 'receive from a socket'),
    49: ('bind', 'bind a socket to an address'),
    50: ('listen', 'listen for connections'),
    56: ('clone', 'create a thread or process'),
    57: ('fork', 'create a child process'),
    59: ('execve', 'replace this process with a new program'),
    60: ('exit', 'terminate the process'),
    61: ('wait4', 'wait for a child process'),
    62: ('kill', 'send a signal to a process'),
    101: ('ptrace', 'trace or control another process'),
    102: ('getuid', 'get the user ID'),
    105: ('setuid', 'set the user ID'),
    231: ('exit_group', 'terminate all threads in the process'),
    257: ('openat', 'open a file relative to a directory'),
}

# AArch64, selected via X8 with `svc #0`
LINUX_ARM64 = {
    56: ('openat', 'open a file relative to a directory'),
    57: ('close', 'close a file descriptor'),
    63: ('read', 'read from a file descriptor'),
    64: ('write', 'write to a file descriptor'),
    93: ('exit', 'terminate the process'),
    94: ('exit_group', 'terminate all threads in the process'),
    221: ('execve', 'replace this process with a new program'),
    222: ('mmap', 'map memory'),
}

# Syscalls worth calling out in a security review.
NOTEWORTHY = {
    'execve': 'spawns a new program — the payload of most shellcode',
    'ptrace': 'traces another process — common anti-debugging check',
    'mprotect': 'changes page permissions — often used to make memory executable',
    'socket': 'opens a network socket',
    'connect': 'opens an outbound connection — reverse-shell building block',
    'bind': 'binds a listening port — bind-shell building block',
    'setuid': 'changes the process user — privilege manipulation',
    'dup2': 'redirects file descriptors — wires a shell to a socket',
}

TABLES = {
    ('x86', 32): LINUX_X86,
    ('x86', 64): LINUX_X64,
    ('arm', 64): LINUX_ARM64,
}


def lookup(number: int, arch: str = 'x86', bits: int = 32):
    """Return (name, description) for a syscall number, or None."""
    table = TABLES.get((arch, bits))
    return table.get(number) if table else None
