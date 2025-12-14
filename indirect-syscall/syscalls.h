#ifndef _SYSCALLS_H  // If _SYSCALLS_H is not defined then define it and the contents below. This is to prevent double inclusion.
#define _SYSCALLS_H  // Define _SYSCALLS_H

#include <windows.h>  // Include the Windows API header
#include <winternl.h> // exposes prototypes of internal Windows APIs
// The type NTSTATUS is typically defined in the Windows headers as a long.
typedef long NTSTATUS;  // Define NTSTATUS as a long
typedef NTSTATUS* PNTSTATUS;  // Define a pointer to NTSTATUS

// Declare the function prototype for NtCreateFile
extern NTSTATUS NtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);

// Declare the function prototype for NtWriteFile
extern NTSTATUS NtWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
);

// Declare the function prototype for NtClose
extern NTSTATUS NtClose(
    HANDLE Handle
);

#endif // _SYSCALLS_H  // End of the _SYSCALLS_H definition