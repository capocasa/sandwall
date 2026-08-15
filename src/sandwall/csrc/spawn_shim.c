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
                          const wchar_t* env, const wchar_t* cwd,
                          HANDLE* out_process) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    // lpDesktop stays NULL: with the winsta0 + default-desktop ACL
    // grants from setup in place, NULL lets the child init in the
    // caller's desktop. An explicit "winsta0\\default" instead made
    // console-subsystem children die at loader init with 0xC0000142
    // (verified on Win11 26100: the cross-session connect fails even
    // though the DACL grants the user access).
    ZeroMemory(&pi, sizeof(pi));
    // A NULL env would hand the child a fresh (nearly empty) block:
    // NIMBOX_OUT_PIPE and the wall-proxy vars would never arrive, and
    // TEMP/TMP would point into the sandwall user's absent profile.
    // The caller passes its LIVE environment block; wide blocks need
    // CREATE_UNICODE_ENVIRONMENT or CPLW rejects them with 87.
    DWORD flags = env ? CREATE_UNICODE_ENVIRONMENT : 0;
    if (!CreateProcessWithLogonW(user, domain, password, 0, NULL,
            (LPWSTR)cmdline, flags, (LPVOID)env, cwd, &si, &pi)) {
        return GetLastError();
    }
    CloseHandle(pi.hThread);
    *out_process = pi.hProcess;
    return 0;
}
