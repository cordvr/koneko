#include <includes.h>

// Function to get the Exception Directory from .PDATA
VOID GetExceptionAddress(PEXCEPTION_INFO pExceptionInfo) {
    PIMAGE_NT_HEADERS64 pImgNtHdr = (PIMAGE_NT_HEADERS64)(pExceptionInfo->hModule + ((PIMAGE_DOS_HEADER)pExceptionInfo->hModule)->e_lfanew);
    PIMAGE_DATA_DIRECTORY pExcDir = &pImgNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    pExceptionInfo->pExceptionDirectory = pExceptionInfo->hModule + pExcDir->VirtualAddress;
    pExceptionInfo->dwRuntimeFunctionCount = pExcDir->Size / sizeof(RUNTIME_FUNCTION);
}

// Backend function for CalculateStackSize that does all the hard work
ULONG CalculateStackSizeBackend(PRUNTIME_FUNCTION pRuntimeFunctionTable, ULONG functionCount, DWORD64 ImageBase, DWORD64 pFuncAddr) {
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };

    // Locate the correct RUNTIME_FUNCTION using Binary Search
    ULONG low = 0, high = functionCount - 1;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;

    while (low <= high) {
        ULONG mid = (low + high) / 2;
        PRUNTIME_FUNCTION pMidFunction = &pRuntimeFunctionTable[mid];

        if (pFuncAddr < (ImageBase + pMidFunction->BeginAddress))
            high = mid - 1;
        else if (pFuncAddr > (ImageBase + pMidFunction->EndAddress))
            low = mid + 1;
        else {
            pRuntimeFunction = pMidFunction; // Found the function
            break;
        }
    }

    if (!pRuntimeFunction) return STATUS_INVALID_PARAMETER; // Function not found

    // If UnwindData is invalid, try retrieving function entry from Exception Directory
    if (pRuntimeFunction->UnwindData >= 0x80000000) {
        EXCEPTION_INFO excInfo = { 0 };
        excInfo.hModule = ImageBase;
        GetExceptionAddress(&excInfo);

        // Manually search for the function in the Exception Directory
        pRuntimeFunction = (PRUNTIME_FUNCTION)excInfo.pExceptionDirectory;
        for (DWORD i = 0; i < excInfo.dwRuntimeFunctionCount; i++) {
            if (pFuncAddr >= (ImageBase + pRuntimeFunction[i].BeginAddress) &&
                pFuncAddr <= (ImageBase + pRuntimeFunction[i].EndAddress)) {
                pRuntimeFunction = &pRuntimeFunction[i];
                break;
            }
        }

        // Still could not find valid entry
        if (!pRuntimeFunction) return STATUS_INVALID_PARAMETER;
    }

    // Retrieve Unwind Information
    pUnwindInfo = (PUNWIND_INFO)(ImageBase + pRuntimeFunction->UnwindData);

    // Validate pUnwindInfo before using it
    if (!pUnwindInfo || (DWORD64)pUnwindInfo < ImageBase || (DWORD64)pUnwindInfo > ImageBase + 0xFFFFFF) {
        return STATUS_INVALID_PARAMETER; // Invalid pUnwindInfo
    }

    while (index < pUnwindInfo->CountOfCodes) {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;

        // Calculate Stack Size Based on Unwind Codes
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            if (operationInfo == 4)
                return STATUS_INVALID_PARAMETER;
            stackFrame.totalStackSize += 8;
            break;
        case UWOP_ALLOC_SMALL:
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            index++;
            if (index >= pUnwindInfo->CountOfCodes)
                return 0x100; // Default safe size

            frameOffset = (operationInfo == 0)
                ? pUnwindInfo->UnwindCode[index].FrameOffset * 8
                : (pUnwindInfo->UnwindCode[index].FrameOffset + (pUnwindInfo->UnwindCode[++index].FrameOffset << 16));

            if (frameOffset > 0x10000)
                return 0x100; // Default safe size

            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_PUSH_MACHFRAME:
            stackFrame.totalStackSize += (operationInfo == 0) ? 40 : 48;
            break;
        case UWOP_SAVE_NONVOL:
            index++;  // Skip next entry
            break;
        case UWOP_SAVE_NONVOL_FAR:
            index += 2;  // Skip two entries
            break;
        default:
            return 0x100; // Default safe size
        }
        index++;
    }

    // Include Return Address Size
    stackFrame.totalStackSize += 8;

    //printf("Stack size calculated: %u\n", stackFrame.totalStackSize);
    return stackFrame.totalStackSize;
}

// Wrapper function for CalculateStackSizeBackend
ULONG CalculateStackSize(PVOID ReturnAddress) {
    if (!ReturnAddress)
        return STATUS_INVALID_PARAMETER;

    PRUNTIME_FUNCTION pRuntimeFunctionTable = NULL;
    DWORD64 ImageBase = 0;
    ULONG functionCount = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    // Locate RUNTIME_FUNCTION for given Function
    pRuntimeFunctionTable = RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (!pRuntimeFunctionTable) return STATUS_ASSERTION_FAILURE;

    // Find the number of runtime function entries
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    functionCount = pDataDir->Size / sizeof(RUNTIME_FUNCTION);

    // Calculate the total stack size for the function we are "returning" to
    return CalculateStackSizeBackend(pRuntimeFunctionTable, functionCount, ImageBase, (DWORD64)ReturnAddress);
}