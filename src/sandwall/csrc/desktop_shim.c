// One-time elevated setup helper: grant `user` access to the
// interactive window station (winsta0) and its default desktop so a
// cross-session CreateProcessWithLogonW child can initialize there.
// Without this, console-subsystem children die with 0xC0000142
// (verified on Win11).
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

DWORD sw_grant_desktop(const wchar_t* user) {
    PSID sid = NULL;
    DWORD rc = 0;
    DWORD cbSid = 0, cchDomain = 0;
    SID_NAME_USE use;
    LookupAccountNameW(NULL, user, NULL, &cbSid, NULL, &cchDomain, &use);
    if (cbSid == 0) return GetLastError();
    sid = (PSID)LocalAlloc(0, cbSid);
    // +1: the second LookupAccountNameW call writes cchDomain chars
    // plus a terminator (the sizing call reports chars incl. null).
    wchar_t* domain = (wchar_t*)LocalAlloc(0, (cchDomain + 1) * sizeof(wchar_t));
    if (!LookupAccountNameW(NULL, user, sid, &cbSid, domain, &cchDomain, &use)) {
        rc = GetLastError(); LocalFree(sid); LocalFree(domain); return rc;
    }
    LocalFree(domain);

    EXPLICIT_ACCESSW ea = {0};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.ptstrName = (LPWSTR)sid;

    HWINSTA ws = GetProcessWindowStation();
    PACL dacl = NULL;
    if (GetSecurityInfo(ws, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
            NULL, NULL, &dacl, NULL, NULL) != ERROR_SUCCESS) {
        rc = GetLastError(); LocalFree(sid); return rc;
    }
    PACL newDacl = NULL;
    rc = SetEntriesInAclW(1, &ea, dacl, &newDacl);
    if (rc != ERROR_SUCCESS) { LocalFree(sid); return rc; }
    rc = SetSecurityInfo(ws, SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, newDacl, NULL);
    LocalFree(newDacl);
    // The old DACL from GetSecurityInfo is deliberately NOT freed:
    // LocalFree on it heap-corrupted in session-0 callers on Win11
    // 26100 (setup died 0xC0000374 before reaching the fence install).
    // It is ~200 bytes, once per setup.

    HDESK desk = OpenDesktopW(L"default", 0, FALSE, READ_CONTROL | WRITE_DAC);
    if (!desk) { LocalFree(sid); return GetLastError(); }
    PACL ddacl = NULL;
    if (GetSecurityInfo(desk, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
            NULL, NULL, &ddacl, NULL, NULL) != ERROR_SUCCESS) {
        rc = GetLastError(); CloseDesktop(desk); LocalFree(sid); return rc;
    }
    PACL dNew = NULL;
    rc = SetEntriesInAclW(1, &ea, ddacl, &dNew);
    if (rc != ERROR_SUCCESS) { LocalFree(sid); CloseDesktop(desk); return rc; }
    ea.grfInheritance = 0;   // desktops have no children
    rc = SetSecurityInfo(desk, SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, dNew, NULL);
    LocalFree(dNew);
    CloseDesktop(desk);
    LocalFree(sid);
    return rc;
}
