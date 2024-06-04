#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <cstdio>
#include <cwchar>
#include <system_error>

/****************************************************************************************/

static HMODULE GetModuleAddress_Broken(HANDLE hProcess, LPCVOID address)
{
    HMODULE hModule = nullptr;
    SIZE_T  size    = 0;
    WIN32_MEMORY_REGION_INFORMATION info;

    if (QueryVirtualMemoryInformation(hProcess, address, MemoryRegionInfo,
                                      &info, sizeof info, &size))
    {
        hModule = static_cast<HMODULE>(info.AllocationBase);
    }
    else {
        auto err  = GetLastError();
        auto code = std::error_code(int(err), std::system_category());
        wprintf(L"Call failed with error 0x%08X: \"%hs\"\n", err, code.message().c_str());
    }

    wprintf(L"Wrote %2zu bytes to a structure of size %zu.\n", size, sizeof info);
    return hModule;
}

#ifdef _WIN64

static HMODULE GetModuleAddress_Working(HANDLE hProcess, LPCVOID address)
{
    // Everything works fine in 64-bit mode.
    return GetModuleAddress_Broken(hProcess, address);
}

#else

static HMODULE GetModuleAddress_Working(HANDLE hProcess, LPCVOID address)
{
    HMODULE hModule = nullptr;
    SIZE_T  size    = 0;

    struct WIN32_MEMORY_REGION_INFORMATION_HAX {
        UINT64 AllocationBase;
        UINT64 AllocationProtect;
        union {
            ULONG Flags;
            struct {
                ULONG Private : 1;
                ULONG MappedDataFile : 1;
                ULONG MappedImage : 1;
                ULONG MappedPageFile : 1;
                ULONG MappedPhysical : 1;
                ULONG DirectMapped : 1;
                ULONG Reserved : 26;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
        SIZE_T RegionSize;
        SIZE_T CommitSize;
    } info;

    if (QueryVirtualMemoryInformation(hProcess, address, MemoryRegionInfo,
                                      &info, sizeof info, &size))
    {
        hModule = reinterpret_cast<HMODULE>(info.AllocationBase & 0xFFFFFFFF);
    }
    else {
        auto err  = GetLastError();
        auto code = std::error_code(int(err), std::system_category());
        wprintf(L"Call failed with error 0x%08X: \"%hs\"\n", err, code.message().c_str());
    }

    wprintf(L"Wrote %2zu bytes to a structure of size %zu.\n", size, sizeof info);
    return hModule;
}

#endif

/****************************************************************************************/

// We just need something whose address we can take. If we use a function instead we will
// get warnings.
static int dummy_global;

int wmain()
{
    HANDLE hProcess    = GetCurrentProcess();
    HANDLE hModules[2] = {
        GetModuleAddress_Broken(hProcess, &dummy_global),
        GetModuleAddress_Working(hProcess, &dummy_global),
    };

    wprintf(L"\nCalls completed. Report:\n");
    // Prove we found something sensible by printing the magic sequence "MZ", if possible.
    wprintf(L"Official structure: %p -> MZ: \"%.2hs\"\n",
            hModules[0], hModules[0] ? static_cast<char const *>(hModules[0]) : "\0");
    wprintf(L"Working structure:  %p -> MZ: \"%.2hs\"\n",
            hModules[1], hModules[1] ? static_cast<char const *>(hModules[1]) : "\0");
}
