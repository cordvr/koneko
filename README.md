# koneko
A Cobalt Strike shellcode loader with multiple advanced evasion features.

![1739210063119](https://github.com/user-attachments/assets/1d3d84fc-edf1-4e1a-b754-bdb382de5f36)

## Disclaimer
Don't be evil with this. I created this tool to learn. I'm not responsible if the Feds knock on your door.

----------------------------------------------------------------------------------------------------------

Historically was able to (and may still) bypass
- Palo Alto Cortex xDR
- Microsoft Defender for Endpoints
- Windows Defender
- Malwarebytes Anti-Malware

![cortex](https://github.com/user-attachments/assets/340b46f1-f123-4c4a-ab57-9eabae38865e)

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
