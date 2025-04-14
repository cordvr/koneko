#pragma once

#ifndef CALLSTACKSPOOF_H
#define CALLSTACKSPOOF_H

// Function to get the Exception Directory from .PDATA
VOID GetExceptionAddress(PEXCEPTION_INFO pExceptionInfo);

// Backend function that does all the hard work
ULONG CalculateStackSizeBackend(PRUNTIME_FUNCTION pRuntimeFunctionTable, ULONG functionCount, DWORD64 ImageBase, DWORD64 pFuncAddr);

// Wrapper function for CalculateStackSizeBackend
ULONG CalculateStackSize(PVOID ReturnAddress);

#endif