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

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;In Windows, a system call is how a user-mode program temporarily switches to kernel mode. For example this is needed for tasks like saving a file from Notepad. Every system call has a unique syscall ID(SSN), and these SSNs can change from one Windows version to another. Indirect system calls are a technique used by attackers (red teams) to execute code via Windows APIs from within the memory space of ntdll.dll. This makes the execution of the syscall command appear more legitimate to EDR (Endpoint Detection and Response) systems. The return statement from the system call is then directed back from ntdll.dll memory to the memory of the attacker's own assembly code.
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
```sysAddrNtCreateFile = pNtCreateFile + 0x12;```<br />

All extracted information will be used for an **unconditional** jump (**jmp**)<br />
```

reNtCreateFile PROC                      ; NtCreateFile syscall procedure
    mov r10, rcx                         ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, wNtCreateFile               ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtCreateFile]  ; Jump to the actual syscall.
reNtCreateFile ENDP                      ; End of the procedure.
```
<br />
Visual Schema for NtCreateFile:<br />
<pre>
┌─────────────────────────────────────────────────────────┐
│                    NTDLL.DLL MEMORY                     │
├─────────────────────────────────────────────────────────┤
│ Base Address: 0x00007FFFB8CA0000                        │
│                                                         │
│ ... (other functions) ...                               │
│                                                         │
│ ┌─────────────────────────────────────────────────┐     │
│ │ NtCreateFile @ 0x00007FFFB8E02750 ◄─────────────┼─────┼─── Function Address
│ ├─────────────────────────────────────────────────┤     │ (Base + 0x162750)
│ │ +0x00: mov r10, rcx                             │     │
│ │ +0x03: mov eax, 0x55      ◄─────────────────────┼─────┼─── SSN (Syscall Number)
│ │ +0x08: test byte ptr [7FFE0308h], 1             │     │
│ │ +0x0F: jne short jump_target                    │     │
│ │ +0x11: syscall            ◄─────────────────────┼─────┼─── Kernel Transition
│ │ +0x13: ret                                      │     │
│ └─────────────────────────────────────────────────┘     │
│                                                         │
│ ... (other functions) ...                               │
└─────────────────────────────────────────────────────────┘
         ▼ syscall instruction executed ▼   
┌─────────────────────────────────────────────────────────┐
│                   KERNEL MODE (ntoskrnl)                │
├─────────────────────────────────────────────────────────┤
│  SSDT (System Service Descriptor Table)                 │
│  ┌──────────┬─────────────────────────┐                 │
│  │ Index    │ Kernel Function         │                 │
│  ├──────────┼─────────────────────────┤                 │
│  │ 0x55 ◄───┼─► NtCreateFile (kernel) │                 │
│  │ ...      │ ...                     │                 │
│  └──────────┴─────────────────────────┘                 │
└─────────────────────────────────────────────────────────┘
</pre>
<br />
<br />

## :mag: Proof of Concept(PoC)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;You can use Visual Studio’s dumpbin tool to check which Windows APIs are imported through kernel32.dll. The following command shows these imports:<br />
```dumpbin /imports nameOfTheProgram.exe```<br />
    I won't provide the standard Windows API code here - [that’s well documented by Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/). I believe if you've come this far, you can write a simple Portable Executable (PE) for your own tests, but I will show you the difference between a standard API call and indirect syscalls.<br />
    Standard method using **kernel32.dll**:<img width="922" height="853" alt="normal" src="https://github.com/user-attachments/assets/29ffaf6b-64fd-468e-a26b-a82693f14cd4" />
 <br />
 <br />
 <br />
    As you can see, our POC has no imports from Windows APIs: **Createfile**, **WriteFile**, **CloseHandle**   <img width="816" height="1046" alt="Screenshot 2025-12-18 095615" src="https://github.com/user-attachments/assets/226ea9a1-01a8-405a-845a-f1937af0ad49" />
 <br />
 <br />
 <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;You can also debug the executable dynamically to trace its execution. For this example, I used x64dbg. <br />
Start **indirect-syscall.exe** and attach your debugger to it. The **getchar()** call inside **indirect-syscalls.c** will pause execution, keeping the program waiting in the popped-up window until you press Enter.<br />
Start x64dbg (or your preferred debugger) and attach to the process.
After attaching, go to the **Modules** view and examine the functions to confirm that it's using the unhooked version of **ntdll.dll**.
You can also place a breakpoint on the syscall function - when it's hit, you'll see the unhooked code execute in real time.
Refer to the screenshots below for visual guidance.


<table>
   <tr>
 <td><img width="291" height="249" alt="Screenshot 2025-12-22 095335" src="https://github.com/user-attachments/assets/9bcc1e93-1754-459e-9bed-7d01cb86e3e8" width="400"></td>
 <td><img width="808" height="431" alt="Screenshot 2025-12-22 095403" src="https://github.com/user-attachments/assets/0f030881-7b3c-4f3c-8946-f02c43f1083d" width="400"></td>
 <td><img width="249" height="642" alt="Screenshot 2025-12-22 095432" src="https://github.com/user-attachments/assets/18c5361a-a866-436e-aa27-84d27bd1b3b6" width="400"></td>
  </tr>
</table>



<table>
   <tr>
 <td><img width="1441" height="121" alt="Screenshot 2025-12-22 095532" src="https://github.com/user-attachments/assets/4ef31fdd-354e-4b64-a1a0-32c5a66725c4" width="600"></td>
 <td><img width="376" height="198" alt="Screenshot 2025-12-22 095613" src="https://github.com/user-attachments/assets/4887deb6-df03-430b-b254-7e4e162c0f0a" width="600"></td>
 <td><img width="1380" height="213" alt="Screenshot 2025-12-22 095647" src="https://github.com/user-attachments/assets/a3dc6212-b4bf-4bd3-8ff3-9789b400b53c" width="600"></td>
  </tr>
</table>

<br />
<br />
<br />
This is how a not modified syscall stub looks in memory:
<img width="1346" height="186" alt="Screenshot 2025-12-22 095732" src="https://github.com/user-attachments/assets/727ff24e-962b-4195-8b81-34a063153915" />
<br />
<br />
This is an example of a syscall stub that is hooked by a modern EDR:
<img width="1229" height="210" alt="Screenshot from 2025-12-22 20-47-12" src="https://github.com/user-attachments/assets/1aa814c5-dcee-4f75-849f-7a94fca38576" />
<br />
<br />

## :scroll: Summary 
- This approach achieves the following:
- Eliminates import dependencies on both **kernel32.dll** and **ntdll.dll**.
- Implements the syscall stub directly within the loader’s own **.text** section.
- Executes the actual **syscall** and **ret** instructions from the memory space of **ntdll.dll**.
- Bypasses user‑mode API hooks set by EDR inside ntdll.dll, though this often requires supplementary methods such as SysWhispers2 & syswhispers3.
- Evades EDR detection mechanisms that monitor syscall origins and return addresses in the call stack.
<br />
<br />

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Indirect syscalls represent an improvement over direct syscalls, yet they are not without constraints. A key limitation in the POC discussed here arises when an EDR places an inline hook on a Native API.
Here's the issue: the EDR's inline hook replaces the crucial __mov eax, SSN__ instruction (which holds the syscall number) with an unconditional **jmp** to its own detection routine. When this happens, the syscall number can no longer be dynamically read from the **ntdll.dll** loaded in memory.
To work around this, the inline hook must first be removed from the affected API to restore and read the original **mov eax, SSN** instruction.
However, a critical point emerged during this exploration: while an EDR can hook or replace the **mov eax, SSN**, it cannot hook the **syscall** instruction itself. This is why indirect syscalls remain effective - the EDR cannot block us from executing the actual syscall instruction within the memory of **ntdll.dll**.<br />
If an EDR leverages Event Tracing for Windows (ETW) or Event Tracing for Windows Threat Intelligence (ETW TI) to analyze the entire call stack - rather than just checking where the syscall was executed or its return address - then indirect syscalls will likely be detected.
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Think of this technique as a single snowflake in a blizzard - one snowflake isn’t enough to build a snowman, but if you collect enough, you can bring the whole storm with you.

<img width="1346" height="186" alt="Screenshot 2025-12-22 095732" src="https://github.com/user-attachments/assets/0ab0d48a-608c-4b11-a935-5c4e0082a7d3" />
<br />
<br />
## :receipt:References
https://redops.at/en/knowledge-base<br />
https://fzm.ooo/<br />
https://blog.sektor7.net/#!res/2021/halosgate.md<br />
https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html<br />
https://www.outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/<br />
https://www.crow.rip/nest/<br />
https://trickster0.github.io/posts/Halo%27s-Gate-Evolves-to-Tartarus-Gate/<br />
https://en.wikipedia.org/wiki/Protection_ring/<br />

Special thanks to: [byte4byte)](https://emryll.gitbook.io/byte4byte) and [eversinc33](https://x.com/eversinc33)
