#include <includes.h>

// Super reliable way to find the base address of a given module
PBYTE FindModuleBase(const CHAR* moduleName) {
    // Retrieve the loader data from the Process Environment Block (PEB)
    PPEB_LDR_DATA loaderData = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
    PLIST_ENTRY moduleListHead = (PLIST_ENTRY)&loaderData->Reserved2[1]; //Reserved2[1] == InLoadOrderModuleList
    PLIST_ENTRY currentEntry = moduleListHead->Blink;

    // Iterate through the loaded modules backwards
    while (currentEntry != moduleListHead) {
        // Get the module entry
        PLDR_DATA_TABLE_ENTRY_MODIFIED moduleEntry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY_MODIFIED, InLoadOrderLinks);
        currentEntry = currentEntry->Blink;

        // Get the base address of the module
        PBYTE moduleBase = (PBYTE)moduleEntry->OriginalBase;

        // Access the NT headers of the module
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);

        // Check if the module has an export directory
        DWORD exportDirectoryRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportDirectoryRVA) continue; // No export table? skip

        // Access the export directory
        PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + exportDirectoryRVA);
        if (!exportDirectory->NumberOfNames) continue; // No symbols? skip

        // Extract the DLL name from the module entry
        char dllName[MAX_PATH]; // Buffer to store the DLL name
        snprintf(dllName, sizeof(dllName), "%wZ", moduleEntry->BaseDllName); // Extract BaseDllName

        // Compare the decoded name with the current module name
        if (strcmp(dllName, moduleName) == 0) return moduleBase; // Found the module, return its base address
    }

    // module not found
    return nullptr;
}

// Resolve System Service Number (SSN), Address, and Offset for a System Call Name
SyscallEntry SSNLookup(PCHAR syscall) {
    SyscallEntry entry = { 0 };

    // Load the Export Address Table
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(hNtdll + ((PIMAGE_DOS_HEADER)hNtdll)->e_lfanew);
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA) return { 0 }; // No export table

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(hNtdll + exportDirRVA);

    PDWORD pFunctions = (PDWORD)(hNtdll + pExportDir->AddressOfFunctions);
    PDWORD pNames = (PDWORD)(hNtdll + pExportDir->AddressOfNames);
    PWORD pNameOrdinals = (PWORD)(hNtdll + pExportDir->AddressOfNameOrdinals);

    // Load the Exception Directory
    DWORD exceptTableRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    if (!exceptTableRVA) return { 0 }; // No exception directory

    PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(hNtdll + exceptTableRVA);

    INT64 ssn = 0;
    PBYTE address = 0;

    // Search export address table
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        PCHAR pFunctionName = (PCHAR)(hNtdll + pNames[i]);
            
        // Search runtime function table
        for (INT64 i = 0; pRuntimeFuncTable[i].BeginAddress; i++) {
            for (INT64 j = 0; j < pExportDir->NumberOfFunctions; j++) {
                if (pFunctions[pNameOrdinals[j]] == pRuntimeFuncTable[i].BeginAddress) {
                    PCHAR api = (PCHAR)(hNtdll + pNames[j]);
                    PCHAR s1 = api;
                    PCHAR s2 = syscall;

                    // Compare the syscall names
                    while (*s1 && (*s1 == *s2)) s1++, s2++;
                    INT64 cmp = (INT64)*(PBYTE)s1 - *(PBYTE)s2;
                    if (!cmp) {
                        address = (hNtdll + pRuntimeFuncTable[i].BeginAddress);
                        
                        // Locate `syscall; ret` sequence
                        for (INT64 offset = 0; offset < 0x100; offset++) {// Scan up to 256 bytes
                            if (address[offset] == 0x0F && address[offset + 1] == 0x05 && address[offset + 2] == 0xC3) {

                                // Populate the SyscallEntry struct
                                entry.SSN = ssn;
                                entry.Address = address;
                                entry.Syscall = (PVOID)(address + offset);
                                return entry;
                            }
                        }
                    }
                    // If this is a syscall, increase the SSN value
                    if (*(USHORT*)api == 'wZ') ssn++;
                }
            }
        }
    }
    return { 0 }; // Didn't find it
}

// Collect all instances of a given ROP gadget in a given module
std::vector<PVOID> CollectGadgets(const PBYTE gadget, SIZE_T gadgetSize, PBYTE hModule) {
    std::vector<PVOID> gadgets;
    if (!hModule || !gadget || gadgetSize == 0) return gadgets; // Validate input

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return gadgets; // Validate DOS header

    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hModule) + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return gadgets; // Validate NT headers

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    UINT_PTR moduleBase = reinterpret_cast<UINT_PTR>(hModule);

    // Loop through each section in the module
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        // Check if the section is executable code
        if ((pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

            PBYTE sectionBase = reinterpret_cast<PBYTE>(moduleBase + pSectionHeader->VirtualAddress);
            PBYTE sectionEnd = sectionBase + pSectionHeader->Misc.VirtualSize;

            // Search within the section for the gadget pattern
            for (PBYTE currentBytes = sectionBase; currentBytes <= sectionEnd - gadgetSize; ++currentBytes) {
                if (!memcmp(currentBytes, gadget, gadgetSize)) {
                    gadgets.emplace_back(EncodePointer(reinterpret_cast<PVOID>(currentBytes))); // Construct each encoded address inside the vector
                }
            }
        }
    }
    //printf("Found %u gadgets\n", gadgets.size());
    return gadgets;
}

// Choose a random gadget
PVOID GoGoGadget(std::vector<PVOID> gadgets) {
    if (gadgets.empty()) return nullptr; // Return nullptr if the vector is empty

    // Randomly select and decode a gadget address
    static std::mt19937 rng(static_cast<unsigned int>(std::time(nullptr)));
    std::uniform_int_distribution<size_t> dist(0, gadgets.size() - 1);
    return DecodePointer((gadgets)[dist(rng)]);
}

// Checks the bytes immediately before each gadget
VOID CheckGadgetPreBytes(const std::vector<PVOID>& gadgets, SIZE_T gadgetSize, SIZE_T lookbackSize) {
    for (const auto& encodedGadget : gadgets) {
        PBYTE gadgetAddress = reinterpret_cast<PBYTE>(DecodePointer(encodedGadget)); // Decode the pointer

        // Ensure we can read preceding bytes safely
        PBYTE precedingBytes = gadgetAddress - lookbackSize;
        if (precedingBytes >= gadgetAddress) {
            printf("Skipping address %p (out of range)\n", gadgetAddress);
            continue; // Prevent underflow if the address is too low in memory
        }

        // Print address and bytes
        printf("Address: %p -> ", gadgetAddress);
        for (SIZE_T i = 0; i < lookbackSize + gadgetSize + 8; i++) { // Include gadget bytes and 4 bytes ahead of gadget too
            printf("%02X ", precedingBytes[i]);
        }
        printf("\n");
    }
}