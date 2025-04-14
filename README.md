# koneko
A Cobalt Strike shellcode loader with multiple advanced evasion features.

## Disclaimer
Don't be evil with this. I created this tool to learn. I'm not responsible if the Feds knock on your door.

----------------------------------------------------------------------------------------------------------

Historically was able to (and may still) bypass
- Palo Alto Cortex xDR
- Windows Defender
- Malwarebytes Anti-Malware

![cortex](https://github.com/user-attachments/assets/d2ff0d1c-70eb-49be-bbb3-88e56bdb96e7)

## Features
- Fully custom sleep implementation with thread callstack spoofing using NtCreateEvent and NtWaitForSingleObject
- Inline hook on Sleep/SleepEx to redirect to said custom sleep implementation
- Switching between Fiber threads to further avoid memory scanning
- Return address spoofing on (almost?) every other API/NTAPI call
- All the indirect syscalls!
- Bunch of anti-VM and anti-debugger checks
- Splitting and hiding shellcode as a bunch of x64 addresses with the EncodePointer API
- Probably other stuff I forgot to mention here

## Negatives
- It's not a UDRL loader, these spoof tricks are limited to only the running executable and will go away when you process inject to something else.
- The sleep obfuscation is tailored to Cobalt Strike. To work with other C2s you'd need to tailor how the hooking happens. Use a tool like `apimonitor` to intercept API calls from your beacon, detect the API(s) called on the sleep cycle, and then adjust the hooks as needed.
