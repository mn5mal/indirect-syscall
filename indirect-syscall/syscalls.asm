; syscalls.asm - Indirect Syscalls for File Operations
.code

; External variables for syscall numbers and addresses
EXTERN wNtCreateFile:DWORD           ; Holds the dynamic retrieved SSN for NtCreateFile
EXTERN sysAddrNtCreateFile:QWORD     ; he actual address of the NtCreateFile syscall in ntdll.dll
EXTERN wNtWriteFile:DWORD            ; Holds the dynamic retrieved SSN for NtWriteFile
EXTERN sysAddrNtWriteFile:QWORD      ; The actual address of the NtWriteFile syscall in ntdll.dll
EXTERN wNtClose:DWORD                ; Holds the dynamic retrieved SSN for NtClose
EXTERN sysAddrNtClose:QWORD          ; The actual address of the NtClose syscall in ntdll.dll

; NtCreateFile procedure
NtCreateFile PROC
    mov r10, rcx
    mov eax, wNtCreateFile
    jmp QWORD PTR [sysAddrNtCreateFile]
NtCreateFile ENDP

; NtWriteFile syscall procedure  
NtWriteFile PROC
    mov r10, rcx                            ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, wNtWriteFile                   ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtWriteFile]      ; Jump to the actual syscall.
NtWriteFile ENDP                            ; End of the procedure.

; NtClose procedure
NtClose PROC
    mov r10, rcx
    mov eax, wNtClose
    jmp QWORD PTR [sysAddrNtClose]
NtClose ENDP

END