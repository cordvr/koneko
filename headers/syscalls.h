#pragma once

#ifndef SYSCALLS_H
#define SYSCALLS_H

EXTERN_C DWORD dwSSN;
EXTERN_C PVOID qwJMP;
EXTERN_C PVOID CallR12(PVOID Function, ULONGLONG nArgs, PVOID r12_gadget, ...);
NTAPI_FUNCTION CallMe();

extern PBYTE hNtdll;
extern NTSTATUS status;

// Super reliable way to find the base address of a given module
PBYTE FindModuleBase(const CHAR* moduleName);

// Resolve System Service Number (SSN), Address, and Offset for a System Call Name
SyscallEntry SSNLookup(PCHAR syscall);

// Collect all instances of a given ROP gadget in a given module
std::vector<PVOID> CollectGadgets(const PBYTE gadget, SIZE_T gadgetSize, PBYTE hModule);

// Choose a random gadget
PVOID GoGoGadget(std::vector<PVOID> gadgets);

// Checks the bytes immediately before each gadget
VOID CheckGadgetPreBytes(const std::vector<PVOID>& gadgets, SIZE_T gadgetSize, SIZE_T lookbackSize);

#endif