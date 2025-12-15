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

