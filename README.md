# indirect-syscall    

   Let’s set the stage before we get into the article itself, because it’s very important to understand the system first.
Think of it like this: on your computer or phone, apps can’t just grab whatever they want-memory, files and etc... They gotta ask the kernel, the system’s main guard, for a green light. They do that through a series of APIs. It’s all about keeping things locked down, so one bad app doesn’t crash everything or steal data. These APIs come in two types: documented ones (like kernel32.dll and kernelbase.dll) and undocumented ones (like ntdll.dll). Microsoft probably did this to stop devs or malicious actors from getting too comfortable with the deep system structure. So they divided up the access rights into four rings and keep calm, Sauron and Frodo aren’t involved this time.


<img width="800" height="450" alt="image" src="https://github.com/user-attachments/assets/9e7f628d-eaf6-444e-970c-206bf320b5a0" />
