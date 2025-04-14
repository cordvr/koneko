#pragma once

#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define WIN32_LEAN_AND_MEAN
#define NO_MIN_MAX

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= STATUS_SUCCESS)

#define NTAPI_FUNCTION EXTERN_C NTSTATUS NTAPI
#define RTL_CONSTANT_STRING(s) { sizeof((s)) - sizeof((s)[0]), sizeof((s)), (PWCH)(s) }

#define InitializeObjectAttributes(p, n, a, r, s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = (r); \
        (p)->Attributes = (a); \
        (p)->ObjectName = (n); \
        (p)->SecurityDescriptor = (s); \
        (p)->SecurityQualityOfService = nullptr; \
    } while (0)

#define RtlInitUnicodeString(DestinationString, SourceString) \
    do { \
        if ((SourceString) == nullptr) { \
            (DestinationString)->Length = 0; \
            (DestinationString)->MaximumLength = 0; \
            (DestinationString)->Buffer = nullptr; \
        } else { \
            size_t size = wcslen(SourceString) * sizeof(WCHAR); \
            (DestinationString)->Length = static_cast<USHORT>(size); \
            (DestinationString)->MaximumLength = static_cast<USHORT>(size + sizeof(WCHAR)); \
            (DestinationString)->Buffer = const_cast<PWSTR>(SourceString); \
        } \
    } while (0)

#define NEW_STREAM	L":%x%x\x00"
#define PROCESSOR_FEATURE_MAX 64
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000

#endif