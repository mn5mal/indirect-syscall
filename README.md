## ℹ️ Overview  

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Let’s set the stage before we get into the article itself, because it’s very important to understand the system first.
Think of it like this: on your computer or phone, apps can’t just grab whatever they want-memory, files and etc... They gotta ask the kernel, the system’s main guard, for a green light. They do that through a series of APIs. It’s all about keeping things locked down, so one bad app doesn’t crash everything or steal data. These APIs come in two types: documented ones (like kernel32.dll and kernelbase.dll) and undocumented ones (like ntdll.dll). Microsoft probably did this to stop devs or malicious actors from getting too comfortable with the deep system structure. So they divided up the access rights into four rings and keep calm, Sauron and Frodo aren’t involved this time.<br />
   
- Ring 3 is for user-space applications - the least privileged level. Every app gets its own virtual memory space and can’t see other apps. This sandbox prevents a crash in one app from taking down the whole system. Ring 3 is where the magic starts.<br />
   
- Ring 2 and 1 were designed for device drivers or intermediate OS services but offer less protection than Ring 0. These intermediate levels are generally unused in Windows, most drivers run directly in Ring 0 for performance or are isolated in user mode.<br />

- Ring 0 the kernel. It has access to the entire system and acts as the bridge connecting user programs to the hardware,the magic happens here.
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/9e7f628d-eaf6-444e-970c-206bf320b5a0" />
<br />
<br />
The diagram below shows the distinction between the two modes, and an high-level overview of the key components included with each one.<br />
<img width="747" height="623" alt="image" src="https://github.com/user-attachments/assets/bd7f0a4c-baea-4bd6-9408-e6b878c5ceae" />
<br />
<br />

## :snowflake: indirect system call

In Windows, a system call is how a user-mode program temporarily switches to kernel mode. For example this is needed for tasks like saving a file from Notepad. Every system call has a unique syscall ID(SSN), and these SSNs can change from one Windows version to another. Indirect system calls are a technique used by attackers (red teams) to execute code via Windows APIs from within the memory space of ntdll.dll. This makes the execution of the syscall command appear more legitimate to EDR (Endpoint Detection and Response) systems. The return statement from the system call is then directed back from ntdll.dll memory to the memory of the attacker's own assembly code.
<br />
<br />
<br /> Normal windows flow:
<br />
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/c48c0071-6955-45be-8da2-231521ef14f2" />
<br />
<br />
Indirect system call flow:
<br />
<img width="1659" height="939" alt="image" src="https://github.com/user-attachments/assets/253c4eb9-1466-4074-bfce-6b184504bfe3" />
<br />
<br />
Okay, let’s get to the guts of this article. If you want to write similar code yourself, you’ll need a little guidance. I’ll help you do it, step by step.
    You’ll need to create several files in your IDE. In my example, there are three:

   - The main C file: **indirect-syscalls.c**<br />
      The program's starting point,the orchestrator and the user interface.

   - The assembly file: **syscalls.asm**<br />
   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;we do not want to ask **ntdll.dll** for the syscall stub or the content or code of the syscall stub (assembly instructions **mov r10, rcx, mov eax**, SSN etc.) of the native functions we use, instead we have to implement the necessary assembly code in the assembly itself.


   - The header file: **syscalls.h**<br />
     &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;We don't want ask **ntdll.dll** for the function definition of the native APIs. But we still want to use the native functions, so we need to define or directly implement the structure for all four native functions in a header file. In this case, the header file should be called **syscalls.h**.

   They will also require some specific adjustments, which you can find illustrated in the screenshots below.
   <img width="1965" height="992" alt="Screenshot 2025-12-16 104449" src="https://github.com/user-attachments/assets/5e97db40-d05c-42d3-9ac5-e636ded99a8f" />
<img width="1734" height="714" alt="Screenshot 2025-12-16 104627" src="https://github.com/user-attachments/assets/a4cdb8a6-330f-4c4e-bfc6-67b2004b5fea" />
<br />
<br />
First we want to use **GetModuleHandleA** to open a handle to ntdll.dll at runtime.<br />
```
HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("Could not get ntdll.dll\n");
        return;
    }
```
<br />
 Declare and initialize a pointer to the NtCreateFile function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module <br />
   
   ```UINT_PTR pNtCreateFile = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateFile");```

<br />
   
   The (BYTE*) cast treats the function pointer as an array of bytes, letting us read the function's raw machine code byte-by-byte. The syscall number for NtCreateFile is embedded within its implementation in ntdll.dll. On modern 64-bit Windows, this value is typically stored starting at the 5th byte (index [4]) of the function's prologue.<br />
    ```wNtCreateFile = ((BYTE*)pNtCreateFile)[4];```<br />

   The syscall stub (actual system call instruction) is some bytes further into the function.<br />
   In this case, it's assumed to be 0x12 (18 in decimal) bytes from the start of the function.<br />
   I chose to locate it dynamically by scanning for the **0F 05** byte sequence, which is the machine code for the **syscall** instruction in 64-bit Windows. Alternatively, you can add **0x12** to the function's starting address to reach the same instruction, as that is a common static offset in modern **ntdll.dll**.<br />
   ```
 for (int i = 0; i < 0x50; i++) {
        if (funcBytes[i] == 0x0F && funcBytes[i + 1] == 0x05) {
            printf("Found syscall at offset 0x%X\n", i);
            return functionAddress + i;
        }
   ```
<br />

```sysAddrNtCreateFile = FindSyscallInstruction(pNtCreateFile);```=
```sysAddrNtCreateFile =pNtCreateFile + 0x12;```
