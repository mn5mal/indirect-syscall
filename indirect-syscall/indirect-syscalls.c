#include <windows.h>
#include <stdio.h>
#include "syscalls.h"

// Global variables for syscall numbers and addresses
DWORD wNtCreateFile;
UINT_PTR sysAddrNtCreateFile;
DWORD wNtWriteFile;
UINT_PTR sysAddrNtWriteFile;
DWORD wNtClose;
UINT_PTR sysAddrNtClose;
//
// Pattern matching function to find syscall instruction
UINT_PTR FindSyscallInstruction(UINT_PTR functionAddress) {
    if (!functionAddress) {
        printf("Null function address\n");
        return 0;
    }

    BYTE* funcBytes = (BYTE*)functionAddress;

    // Search for "0F 05" = syscall instruction
    for (int i = 0; i < 0x50; i++) {
        if (funcBytes[i] == 0x0F && funcBytes[i + 1] == 0x05) {
            printf("Found syscall at offset 0x%X\n", i);
            return functionAddress + i;
        }
    }

    printf("Syscall instruction not found at 0x%p!\n", (void*)functionAddress);
    return 0;
}

// Initialize all syscalls
void InitializeSyscalls(void) {
    printf("=== Initializing File Creation Syscalls ===\n");

    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("Could not get ntdll.dll\n");
        return;
    }
    printf("ntdll.dll base: 0x%p\n", (void*)hNtdll);

    // Initialize NtCreateFile
    UINT_PTR pNtCreateFile = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateFile");
    if (pNtCreateFile) {
        printf("NtCreateFile function: 0x%p\n", (void*)pNtCreateFile);
        wNtCreateFile = ((BYTE*)pNtCreateFile)[4];
        printf("NtCreateFile syscall number: 0x%X\n", wNtCreateFile);
        sysAddrNtCreateFile = FindSyscallInstruction(pNtCreateFile);
        printf("NtCreateFile syscall instruction: 0x%p\n", (void*)sysAddrNtCreateFile);
    }

    // Initialize NtWriteFile
    UINT_PTR pNtWriteFile = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteFile");
    if (pNtWriteFile) {
        printf("NtWriteFile function: 0x%p\n", (void*)pNtWriteFile);
        wNtWriteFile = ((BYTE*)pNtWriteFile)[4];
        printf("NtWriteFile syscall number: 0x%X\n", wNtWriteFile);
        sysAddrNtWriteFile = FindSyscallInstruction(pNtWriteFile);
        printf("NtWriteFile syscall instruction: 0x%p\n", (void*)sysAddrNtWriteFile);
    }

    // Initialize NtClose
    UINT_PTR pNtClose = (UINT_PTR)GetProcAddress(hNtdll, "NtClose");
    if (pNtClose) {
        printf("NtClose function: 0x%p\n", (void*)pNtClose);
        wNtClose = ((BYTE*)pNtClose)[4];
        printf("NtClose syscall number: 0x%X\n", wNtClose);
        sysAddrNtClose = FindSyscallInstruction(pNtClose);
        printf("NtClose syscall instruction: 0x%p\n", (void*)sysAddrNtClose);
    }

    printf("=== Syscalls Initialization Complete ===\n\n");
}

int main() {
    // Initialize syscalls
    InitializeSyscalls();

    // Check if all syscalls were initialized
    if (!sysAddrNtCreateFile || !sysAddrNtWriteFile || !sysAddrNtClose) {
        printf("One or more syscalls not initialized!\n");
        return 1;
    }

    printf("=== Creating File on Desktop with Indirect Syscalls ===\n");

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    UNICODE_STRING fileName;

    //Get actual username
    wchar_t username[256];
    wchar_t filePath[512];
    DWORD usernameSize = 256;

    // Get current username
    if (!GetUserNameW(username, &usernameSize)) {
        printf("Could not get username\n");
        // Fallback to simple path
        wcscpy_s(filePath, 512, L"\\??\\C:\\Users\\Public\\Desktop\\indirect_file.txt");
    }
    else {
        // Create path with actual username
        swprintf_s(filePath, 512, L"\\??\\C:\\Users\\%s\\Desktop\\indirect_file.txt", username);
    }

    printf("Creating file: %ls\n", filePath);

    // Use manual UNICODE_STRING initialization
    fileName.Buffer = filePath;
    fileName.Length = (USHORT)(wcslen(filePath) * sizeof(wchar_t));
    fileName.MaximumLength = fileName.Length + sizeof(wchar_t);

    // Initialize OBJECT_ATTRIBUTES
    InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Create file using indirect syscall
    NTSTATUS status = reNtCreateFile(
        &hFile,
        FILE_GENERIC_WRITE | FILE_GENERIC_READ,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    getchar();  // This prevents the program from exiting, allowing you to inspect it in a dynamic debugger.
    
    // Use NT_SUCCESS macro for status checking
    if (!NT_SUCCESS(status)) {
        printf("NtCreateFile failed with status: 0x%X\n", status);

        // Try Public Desktop as fallback
        printf("Trying Public Desktop as fallback.\n");
        wcscpy_s(filePath, 512, L"\\??\\C:\\Users\\Public\\Desktop\\indirect_file.txt");

        // Manual UNICODE_STRING initialization
        fileName.Buffer = filePath;
        fileName.Length = (USHORT)(wcslen(filePath) * sizeof(wchar_t));
        fileName.MaximumLength = fileName.Length + sizeof(wchar_t);

        InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = reNtCreateFile(
            &hFile,
            FILE_GENERIC_WRITE | FILE_GENERIC_READ,
            &objectAttributes,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (!NT_SUCCESS(status)) {
            printf("Fallback also failed with status: 0x%X\n", status);
            return 1;
        }
    }

    printf("File created successfully!\n");
    printf("File handle: 0x%p\n", (void*)hFile);

    // Write data to file
    char data[] = "Hello from Indirect Syscalls! File created using NtCreateFile syscall.";
    ULONG dataLength = (ULONG)strlen(data);

    status = reNtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        data,
        dataLength,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("NtWriteFile failed with status: 0x%X\n", status);
        reNtClose(hFile);
        return 1;
    }

    printf("Data written to file: %lu bytes\n", dataLength);

    // Close file handle
    status = reNtClose(hFile);
    if (!NT_SUCCESS(status)) {
        printf("NtClose failed with status: 0x%X\n", status);
        return 1;
    }

    printf("File handle closed\n");
    printf("File created using indirect syscalls!\n");
    printf("Check your Desktop for: indirect_file.txt\n");

    return 0;
}
