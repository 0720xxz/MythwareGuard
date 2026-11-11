/* win.c : thin Win32 layer. */

#include "win.h"
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>

/* ===================================================================== */
/* process inspection                                                    */
/* ===================================================================== */

BOOL ProcExists(DWORD pid)
{
    HANDLE h;
    DWORD rc;
    if (pid == 0) return FALSE;
    h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        h = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (!h) return FALSE;
    }
    rc = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return rc == WAIT_TIMEOUT;
}

BOOL ProcImage(DWORD pid, WCHAR *buf, DWORD cch)
{
    HANDLE h;
    DWORD need = cch;
    BOOL ok = FALSE;
    if (!buf || cch == 0) return FALSE;
    buf[0] = 0;
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return FALSE;
    if (QueryFullProcessImageNameW(h, 0, buf, &need)) ok = TRUE;
    CloseHandle(h);
    return ok;
}

DWORD ProcSession(DWORD pid)
{
    DWORD sid = 0xFFFFFFFF;
    if (ProcessIdToSessionId(pid, &sid)) return sid;
    return 0xFFFFFFFF;
}

int ProcsByName(const WCHAR *name, DWORD *pids, int max)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    int n = 0;

    if (!name) return 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (WStrEqI(pe.szExeFile, name)) {
                if (n < max) pids[n] = pe.th32ProcessID;
                n++;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return (n > max) ? max : n;
}

HANDLE ProcWatchHandle(DWORD pid)
{
    return OpenProcess(SYNCHRONIZE, FALSE, pid);
}

int EnumProcs(ProcCb cb, void *ctx)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    int n = 0;

    if (!cb) return 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            cb(pe.szExeFile, pe.th32ProcessID, ctx);
            n++;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PFN_NQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MWG_USTR;

BOOL GetProcCmdLine(DWORD pid, WCHAR *out, DWORD cch)
{
    HANDLE h;
    HMODULE nt;
    PFN_NQIP fn;
    ULONG len = 0;
    BYTE *buf;
    NTSTATUS st;

    if (!out || !cch || !pid) return FALSE;
    out[0] = 0;
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return FALSE;
    nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) { CloseHandle(h); return FALSE; }
    fn = (PFN_NQIP)(void *)GetProcAddress(nt, "NtQueryInformationProcess");
    if (!fn) { CloseHandle(h); return FALSE; }

    /* 60 = ProcessCommandLineInformation (Win 8.1+) */
    fn(h, 60, NULL, 0, &len);
    if (len == 0 || len > 65536) { CloseHandle(h); return FALSE; }
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (!buf) { CloseHandle(h); return FALSE; }
    st = fn(h, 60, buf, len, &len);
    if (st >= 0) {
        MWG_USTR *us = (MWG_USTR *)buf;
        if (us->Length > 0 && us->Buffer) {
            DWORD n = us->Length / sizeof(WCHAR);
            if (n >= cch) n = cch - 1;
            memcpy(out, us->Buffer, n * sizeof(WCHAR));
            out[n] = 0;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(h);
    return out[0] != 0;
}

BOOL KillPid(DWORD pid)
{
    HANDLE h;
    BOOL ok;
    if (!pid) return FALSE;
    h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return FALSE;
    ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok;
}

/* ===================================================================== */
/* sessions                                                              */
/* ===================================================================== */

int ActiveSessions(DWORD *out, int max)
{
    PWTS_SESSION_INFOW si = NULL;
    DWORD count = 0, i;
    int n = 0;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &si, &count)) {
        DWORD c = WTSGetActiveConsoleSessionId();
        if (c != 0xFFFFFFFF && max > 0) { out[0] = c; return 1; }
        return 0;
    }
    for (i = 0; i < count && n < max; i++) {
        if (si[i].SessionId == 0) continue;
        if (si[i].State != WTSActive) continue;
        out[n++] = si[i].SessionId;
    }
    WTSFreeMemory(si);
    return n;
}

DWORD CurrentSession(void)
{
    DWORD sid = 0xFFFFFFFF;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sid)) return sid;
    return 0xFFFFFFFF;
}

DWORD ConsoleSession(void)
{
    DWORD sid = WTSGetActiveConsoleSessionId();
    return (sid == 0xFFFFFFFF) ? 0xFFFFFFFF : sid;
}

/* ===================================================================== */
/* identity / privileges                                                 */
/* ===================================================================== */

static BOOL OpenSelfToken(DWORD access, PHANDLE out)
{
    return OpenProcessToken(GetCurrentProcess(), access, out) != 0;
}

BOOL IsSystemUser(void)
{
    HANDLE tok = NULL;
    TOKEN_USER *tu = NULL;
    DWORD len = 0;
    BOOL result = FALSE;

    if (!OpenSelfToken(TOKEN_QUERY, &tok)) return FALSE;
    GetTokenInformation(tok, TokenUser, NULL, 0, &len);
    if (len) {
        tu = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
        if (tu && GetTokenInformation(tok, TokenUser, tu, len, &len)) {
            LPWSTR s = NULL;
            if (ConvertSidToStringSidW(tu->User.Sid, &s)) {
                result = (wcscmp(s, L"S-1-5-18") == 0);
                LocalFree(s);
            }
        }
    }
    if (tu) HeapFree(GetProcessHeap(), 0, tu);
    CloseHandle(tok);
    return result;
}

BOOL IsElevated(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION el;
    DWORD len = 0;
    BOOL result = FALSE;

    if (!OpenSelfToken(TOKEN_QUERY, &tok)) return FALSE;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len)) {
        result = (el.TokenIsElevated != 0);
    }
    CloseHandle(tok);
    return result;
}

BOOL EnablePriv(const WCHAR *name)
{
    HANDLE tok = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL ok;

    if (!OpenSelfToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return FALSE;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        CloseHandle(tok);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(tok);
    return ok && GetLastError() == ERROR_SUCCESS;
}

/* ===================================================================== */
/* spawning                                                              */
/* ===================================================================== */

static void BuildCmdLine(const WCHAR *exe, const WCHAR *args, WCHAR *out, DWORD cch)
{
    if (args && *args) {
        WPrintf(out, cch, L"\"%s\" %s", exe, args);
    } else {
        WPrintf(out, cch, L"\"%s\"", exe);
    }
}

BOOL SpawnDetached(const WCHAR *exe, const WCHAR *args, const WCHAR *cwd,
                   DWORD *outPid)
{
    SHELLEXECUTEINFOW sei;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR cmd[2048];
    DWORD pid = 0;

    if (!exe || !exe[0]) return FALSE;

    /* Go through the shell exactly like a user double-click: full user
       environment, correct working directory, no inherited console. Several
       classroom clients refuse to initialise when started by a bare
       CreateProcess and immediately die with a runtime error dialog. */
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"open";
    sei.lpFile = exe;
    sei.lpParameters = (args && args[0]) ? args : NULL;
    sei.lpDirectory = (cwd && cwd[0]) ? cwd : NULL;
    sei.nShow = SW_SHOWNORMAL;

    if (ShellExecuteExW(&sei) && sei.hProcess) {
        pid = GetProcessId(sei.hProcess);
        CloseHandle(sei.hProcess);
        if (pid) {
            if (outPid) *outPid = pid;
            return TRUE;
        }
    }

    BuildCmdLine(exe, args, cmd, 2048);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE,
                        DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                        NULL, (cwd && cwd[0]) ? cwd : NULL, &si, &pi))
        return FALSE;
    if (outPid) *outPid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

BOOL SpawnInSession(DWORD session, const WCHAR *exe, const WCHAR *args,
                    const WCHAR *cwd, DWORD *outPid)
{
    HANDLE hTok = NULL, hDup = NULL;
    LPVOID env = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR cmd[2048];
    BOOL ok = FALSE;

    if (!exe || !exe[0] || session == 0xFFFFFFFF) return FALSE;
    if (!WTSQueryUserToken(session, &hTok)) return FALSE;
    if (!DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                          TokenPrimary, &hDup)) {
        CloseHandle(hTok);
        return FALSE;
    }
    CreateEnvironmentBlock(&env, hDup, FALSE);
    BuildCmdLine(exe, args, cmd, 2048);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = L"winsta0\\default";
    ZeroMemory(&pi, sizeof(pi));

    ok = CreateProcessAsUserW(hDup, exe, cmd, NULL, NULL, FALSE,
                              CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS |
                              CREATE_NEW_PROCESS_GROUP,
                              env, (cwd && cwd[0]) ? cwd : NULL, &si, &pi);
    if (ok) {
        if (outPid) *outPid = pi.dwProcessId;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(hDup);
    CloseHandle(hTok);
    return ok;
}

BOOL RunHidden(const WCHAR *cmdline, DWORD timeoutMs, DWORD *exitCode)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR buf[2048];
    BOOL ok;
    DWORD rc;

    WStrCpy(buf, 2048, cmdline);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ok = CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi);
    if (!ok) return FALSE;
    rc = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (exitCode) {
        if (rc == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, exitCode);
        else *exitCode = 0xFFFFFFFF;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

/* ===================================================================== */
/* hardening                                                             */
/* ===================================================================== */

BOOL DenyTerminateToUsers(DWORD pid)
{
    HANDLE h;
    PSID everyone = NULL;
    EXPLICIT_ACCESS_W ea;
    PACL oldAcl = NULL, newAcl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    BOOL ok = FALSE;

    h = OpenProcess(READ_CONTROL | WRITE_DAC, FALSE, pid);
    if (!h) return FALSE;
    if (!ConvertStringSidToSidW(L"S-1-1-0", &everyone)) {
        CloseHandle(h);
        return FALSE;
    }
    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = PROCESS_TERMINATE;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)everyone;

    if (GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, &oldAcl, NULL, &sd) == ERROR_SUCCESS) {
        if (SetEntriesInAclW(1, &ea, oldAcl, &newAcl) == ERROR_SUCCESS) {
            ok = (SetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                                  NULL, NULL, newAcl, NULL) == ERROR_SUCCESS);
            LocalFree(newAcl);
        }
        LocalFree(sd);
    }
    LocalFree(everyone);
    CloseHandle(h);
    return ok;
}

BOOL HardenProcess(DWORD pid)
{
    return DenyTerminateToUsers(pid);
}

typedef BOOL (WINAPI *PFN_RTL_SET_CRITICAL)(BOOLEAN, PBOOLEAN, DWORD);

BOOL SetSelfCritical(BOOL on)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    PFN_RTL_SET_CRITICAL fn;
    BOOLEAN old = 0;

    if (!nt) return FALSE;
    fn = (PFN_RTL_SET_CRITICAL)(void *)GetProcAddress(nt, "RtlSetProcessIsCritical");
    if (!fn) return FALSE;
    EnablePriv(L"SeDebugPrivilege");
    return fn((BOOLEAN)(on ? 1 : 0), &old, 0) != 0;
}

/* ===================================================================== */
/* misc                                                                  */
/* ===================================================================== */

void GetOwnImage(WCHAR *buf, DWORD cch)
{
    if (!buf || !cch) return;
    if (!GetModuleFileNameW(NULL, buf, cch)) buf[0] = 0;
}

BOOL SplitCommandLine(const WCHAR *cmd, WCHAR *exe, DWORD ecc,
                      WCHAR *args, DWORD acch)
{
    const WCHAR *p = cmd;
    DWORD i = 0;
    BOOL quoted = FALSE;

    if (!cmd || !exe || !args) return FALSE;
    while (*p && WCharIsSpace(*p)) p++;
    if (*p == L'"') {
        quoted = TRUE;
        p++;
        while (*p && *p != L'"' && i + 1 < ecc) exe[i++] = *p++;
        if (*p == L'"') p++;
    } else {
        while (*p && !WCharIsSpace(*p) && i + 1 < ecc) exe[i++] = *p++;
    }
    exe[i] = 0;
    while (*p && WCharIsSpace(*p)) p++;
    WStrCpy(args, acch, p);
    (void)quoted;
    return exe[0] != 0;
}
