// One-time elevated setup helper: grant `user` access to the
// interactive window station (winsta0) and its default desktop so a
// cross-session CreateProcessWithLogonW child can initialize its
// console/loader there. Without this, console-subsystem children hang
// or die with 0xC0000142 (verified on Win11).
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

DWORD sw_grant_desktop(const wchar_t* user) {
    // GENERIC_ALL on the window station and the desktop, merged into
    // the existing DACLs (PACL reuse semantics: SET_ACCESS would wipe
    // them).
    PSID sid = NULL;
    DWORD rc = 0;

    // Build the SID for `user` by name.
    DWORD cbSid = 0, cchDomain = 0;
    SID_NAME_USE use;
    LookupAccountNameW(NULL, user, NULL, &cbSid, NULL, &cchDomain, &use);
    if (cbSid == 0) return GetLastError();
    sid = (PSID)LocalAlloc(0, cbSid);
    wchar_t* domain = (wchar_t*)LocalAlloc(0, cchDomain * sizeof(wchar_t));
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

    HWINSTA ws = GetProcessWindowStation();   // caller is on winsta0
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
    LocalFree(newDacl); LocalFree(dacl);
    if (rc != ERROR_SUCCESS) { LocalFree(sid); return rc; }

    HDESK desk = OpenDesktopW(L"default", 0, FALSE, READ_CONTROL | WRITE_DAC);
    if (!desk) { LocalFree(sid); return GetLastError(); }
    if (GetSecurityInfo(desk, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
            NULL, NULL, &dacl, NULL, NULL) != ERROR_SUCCESS) {
        rc = GetLastError(); CloseDesktop(desk); LocalFree(sid); return rc;
    }
    rc = SetEntriesInAclW(1, &ea, dacl, &newDacl);
    if (rc != ERROR_SUCCESS) { LocalFree(dacl); CloseDesktop(desk); LocalFree(sid); return rc; }
    ea.grfInheritance = 0;   // desktops have no children
    rc = SetSecurityInfo(desk, SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, newDacl, NULL);
    LocalFree(newDacl); LocalFree(dacl);
    CloseDesktop(desk);
    LocalFree(sid);
    return rc;
}
