// C shim for CreateProcessWithLogonW. The real prototype (11 args:
// user, domain, password, logonFlags, appName, cmdLine, createFlags,
// env, cwd, si, pi) differs from CreateProcessAsUserW's shape; calling
// it with the AsUser arg list through a hand-written Nim import
// misaligns the stack (SIGSEGV). All process-creation state is built
// here in plain C.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>

DWORD sw_spawn_with_logon(const wchar_t* user, const wchar_t* domain,
                          const wchar_t* password, const wchar_t* cmdline,
                          const wchar_t* cwd, HANDLE* out_process) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = L"winsta0\\default";
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessWithLogonW(user, domain, password, 0, NULL,
            (LPWSTR)cmdline, 0, NULL, cwd, &si, &pi)) {
        return GetLastError();
    }
    CloseHandle(pi.hThread);
    *out_process = pi.hProcess;
    return 0;
}
