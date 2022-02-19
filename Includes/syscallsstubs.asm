.globl NtCreateProcess, NtCreateThreadEx, NtClose, NtReadVirtualMemory, NtWriteVirtualMemory, NtAllocateVirtualMemory, NtProtectVirtualMemory

NtCreateProcess:
mov %rcx, 0x8(%rsp)
mov %rdx, 0x10(%rsp)
mov %r8, 0x18(%rsp)
mov %r9, 0x20(%rsp)
sub $0x1c, %rsp
mov $0x6d9f6e00, %ecx
call SW2_GetSyscallNumber
add $0x1c, %rsp
mov 0x8(%rsp), %rcx
mov 0x10(%rsp), %rdx
mov 0x18(%rsp), %r8
mov 0x20(%rsp), %r9
mov %rcx, %r10
syscall
ret

NtCreateThreadEx:
mov %rcx, 0x8(%rsp)
mov %rdx, 0x10(%rsp)
mov %r8, 0x18(%rsp)
mov %r9, 0x20(%rsp)
sub $0x1c, %rsp
mov $0x11385def, %ecx
call SW2_GetSyscallNumber
add $0x1c, %rsp
mov 0x8(%rsp), %rcx
mov 0x10(%rsp), %rdx
mov 0x18(%rsp), %r8
mov 0x20(%rsp), %r9
mov %rcx, %r10
syscall
ret

NtClose:
mov %rcx, 0x8(%rsp)
mov %rdx, 0x10(%rsp)
mov %r8, 0x18(%rsp)
mov %r9, 0x20(%rsp)
sub $0x1c, %rsp
mov $0x42cdb7dd, %ecx
call SW2_GetSyscallNumber
add $0x1c, %rsp
mov 0x8(%rsp), %rcx
mov 0x10(%rsp), %rdx
mov 0x18(%rsp), %r8
mov 0x20(%rsp), %r9
mov %rcx, %r10
syscall
ret

NtWriteVirtualMemory:
mov %rcx, 0x8(%rsp)
mov %rdx, 0x10(%rsp)
mov %r8, 0x18(%rsp)
mov %r9, 0x20(%rsp)
sub $0x1c, %rsp
mov $0xf798ed1a, %ecx
call SW2_GetSyscallNumber
add $0x1c, %rsp
mov 0x8(%rsp), %rcx
mov 0x10(%rsp), %rdx
mov 0x18(%rsp), %r8
mov 0x20(%rsp), %r9
mov %rcx, %r10
syscall
ret

NtAllocateVirtualMemory:
mov %rcx, 0x8(%rsp)
mov %rdx, 0x10(%rsp)
mov %r8, 0x18(%rsp)
mov %r9, 0x20(%rsp)
sub $0x1c, %rsp
mov $0xf768efe9, %ecx
call SW2_GetSyscallNumber
add $0x1c, %rsp
mov 0x8(%rsp), %rcx
mov 0x10(%rsp), %rdx
mov 0x18(%rsp), %r8
mov 0x20(%rsp), %r9
mov %rcx, %r10
syscall
ret

NtProtectVirtualMemory:
mov %rcx, 0x8(%rsp)
mov %rdx, 0x10(%rsp)
mov %r8, 0x18(%rsp)
mov %r9, 0x20(%rsp)
sub $0x1c, %rsp
mov $0x3910913, %ecx
call SW2_GetSyscallNumber
add $0x1c, %rsp
mov 0x8(%rsp), %rcx
mov 0x10(%rsp), %rdx
mov 0x18(%rsp), %r8
mov 0x20(%rsp), %r9
mov %rcx, %r10
syscall
ret