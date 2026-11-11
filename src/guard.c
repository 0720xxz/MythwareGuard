/* guard.c : configuration, executable discovery, shared state, role spawning. */

#include "guard.h"
#include "win.h"
#include <winreg.h>

Config  g_cfg;
KvDoc  *g_discovered = NULL;

/* ===================================================================== */
/* small helpers                                                         */
/* ===================================================================== */

static BOOL WIStrContains(const WCHAR *hay, const WCHAR *needle)
{
    size_t nh, nn, i;
    if (!hay || !needle) return FALSE;
    nh = wcslen(hay);
    nn = wcslen(needle);
    if (nn == 0 || nh < nn) return FALSE;
    for (i = 0; i + nn <= nh; i++) {
        if (CompareStringOrdinal(hay + i, (int)nn, needle, (int)nn, TRUE) == CSTR_EQUAL)
            return TRUE;
    }
    return FALSE;
}

/* ===================================================================== */
/* configuration                                                         */
/* ===================================================================== */

void WriteDefaultConfig(const WCHAR *path)
{
    KvDoc *d = KvLoad(NULL);
    WCHAR v[64];

    if (!d) return;
    KvSet(d, L"debug", L"0");
    KvSet(d, L"poll_ms", L"200");
    KvSet(d, L"peer_timeout", L"12");
    KvSet(d, L"harden", L"0");
    KvSet(d, L"critical", L"0");
    KvSet(d, L"report_enable", L"1");
    KvSet(d, L"report_port", L"17800");
    KvSet(d, L"report_server", L"");
    KvSet(d, L"report_interval", L"10");
    KvSet(d, L"report_group", L"");
    /* Default: "supervise what has been seen running", not "must always run".
       MasterHelper is launched by TopDomain on demand - forcing it up at boot,
       before the service brings the client up, yields a second instance that
       dies with a runtime-error dialog. Observing first removes that race
       while still restarting anything that is killed later. */
    KvSet(d, L"target:TopDomain.exe", L"");
    KvSet(d, L"target:MasterHelper.exe", L"");
    KvSet(d, L"target:StudentMain.exe", L"");
    KvSet(d, L"target:Student.exe", L"");
    KvSet(d, L"target:MythwareStudent.exe", L"");
    WPrintf(v, 64, L"%s", MWG_VERSION);
    KvSet(d, L"version", v);
    KvSave(d, path);
    KvFree(d);
}

BOOL LoadConfig(void)
{
    int attempt;

    for (attempt = 0; attempt < 2; attempt++) {
        KvDoc *d;
        WCHAR key[160], val[PATHCH];
        int i, n;

        if (GetFileAttributesW(g_cfgpath) == INVALID_FILE_ATTRIBUTES)
            WriteDefaultConfig(g_cfgpath);

        d = KvLoad(g_cfgpath);
        if (!d) { WriteDefaultConfig(g_cfgpath); continue; }

        g_debug = KvGetInt(d, L"debug", 0) != 0;
        g_cfg.pollMs = KvGetInt(d, L"poll_ms", 200);
        if (g_cfg.pollMs < 100) g_cfg.pollMs = 100;
        if (g_cfg.pollMs > 5000) g_cfg.pollMs = 5000;
        g_cfg.peerTimeoutSec = KvGetInt(d, L"peer_timeout", 12);
        if (g_cfg.peerTimeoutSec < 5) g_cfg.peerTimeoutSec = 5;
        g_cfg.harden = KvGetInt(d, L"harden", 0);
        g_cfg.critical = KvGetInt(d, L"critical", 0);

        g_cfg.count = 0;
        n = KvCountPrefix(d, L"target:");
        for (i = 0; i < n && g_cfg.count < MAXTARGETS; i++) {
            Target *t;
            if (!KvGetPrefixAt(d, L"target:", i, key, 160, val, PATHCH)) continue;
            t = &g_cfg.targets[g_cfg.count];
            ZeroMemory(t, sizeof(*t));
            WStrCpy(t->name, 96, key + 7);
            WStrTrim(t->name);
            if (!t->name[0]) continue;
            t->session = 0xFFFFFFFF;
            if (WStrEqI(val, L"required")) {
                t->required = TRUE;
            } else if (!val[0]) {
                t->required = FALSE;
            } else {
                t->required = TRUE;
                WStrCpy(t->path, PATHCH, val);
            }
            g_cfg.count++;
        }
        KvFree(d);

        if (g_cfg.count > 0) return TRUE;
        /* config exists but carries no targets - almost always a truncated
           or corrupted file; regenerate once and retry */
        LogWrite(L"config has no targets, regenerating defaults");
        WriteDefaultConfig(g_cfgpath);
    }
    return g_cfg.count > 0;
}

/* ===================================================================== */
/* executable discovery                                                  */
/* ===================================================================== */

static BOOL FindFileInDir(const WCHAR *dir, const WCHAR *name, WCHAR *out,
                          DWORD cch, int depth)
{
    WCHAR pattern[PATHCH];
    WIN32_FIND_DATAW fd;
    HANDLE h;

    if (depth < 0 || !dir || !dir[0]) return FALSE;
    WPrintf(pattern, PATHCH, L"%s\\*", dir);

    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (WStrEqI(fd.cFileName, name)) {
            WPrintf(out, cch, L"%s\\%s", dir, fd.cFileName);
            FindClose(h);
            return TRUE;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    do {
        WCHAR sub[PATHCH];
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') continue;
        WPrintf(sub, PATHCH, L"%s\\%s", dir, fd.cFileName);
        if (FindFileInDir(sub, name, out, cch, depth - 1)) {
            FindClose(h);
            return TRUE;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return FALSE;
}

static BOOL ScanVendorRoots(const WCHAR *name, WCHAR *out, DWORD cch)
{
    static const WCHAR *probes[] = { L"ProgramFiles", L"ProgramFiles(x86)",
                                     L"ProgramW6432", L"ProgramData" };
    WCHAR roots[4][PATHCH];
    int nr = 0, r;
    DWORD n;

    for (r = 0; r < 4; r++) {
        n = GetEnvironmentVariableW(probes[r], roots[nr], PATHCH);
        if (n > 0 && n < PATHCH) nr++;
    }
    for (r = 0; r < nr; r++) {
        WCHAR pattern[PATHCH];
        WIN32_FIND_DATAW fd;
        HANDLE h;
        WPrintf(pattern, PATHCH, L"%s\\*", roots[r]);
        h = FindFirstFileW(pattern, &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            WCHAR sub[PATHCH];
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (fd.cFileName[0] == L'.') continue;
            if (!(WIStrContains(fd.cFileName, L"Mythware") ||
                  WIStrContains(fd.cFileName, L"TopDomain") ||
                  WIStrContains(fd.cFileName, L"Classroom") ||
                  WIStrContains(fd.cFileName, L"Master"))) continue;
            WPrintf(sub, PATHCH, L"%s\\%s", roots[r], fd.cFileName);
            if (FindFileInDir(sub, name, out, cch, 5)) { FindClose(h); return TRUE; }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return FALSE;
}

static BOOL ScanUninstall(const WCHAR *name, WCHAR *out, DWORD cch)
{
    static const WCHAR *subs[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    };
    int s;

    for (s = 0; s < 2; s++) {
        HKEY hk;
        DWORD idx = 0;
        WCHAR subkey[256];

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subs[s], 0, KEY_READ, &hk) != ERROR_SUCCESS)
            continue;
        for (;;) {
            DWORD cchSub = 256;
            HKEY hsub;
            if (RegEnumKeyExW(hk, idx++, subkey, &cchSub, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            if (RegOpenKeyExW(hk, subkey, 0, KEY_READ, &hsub) != ERROR_SUCCESS) continue;
            {
                WCHAR disp[512];
                DWORD cb = sizeof(disp), type = 0;
                if (RegQueryValueExW(hsub, L"DisplayName", NULL, &type,
                                     (LPBYTE)disp, &cb) == ERROR_SUCCESS && type == REG_SZ) {
                    if (WIStrContains(disp, L"Mythware") ||
                        WIStrContains(disp, L"TopDomain") ||
                        WIStrContains(disp, L"Master")) {
                        WCHAR loc[PATHCH];
                        DWORD cb2 = sizeof(loc);
                        if (RegQueryValueExW(hsub, L"InstallLocation", NULL, &type,
                                             (LPBYTE)loc, &cb2) == ERROR_SUCCESS &&
                            type == REG_SZ && loc[0]) {
                            if (FindFileInDir(loc, name, out, cch, 4)) {
                                RegCloseKey(hsub);
                                RegCloseKey(hk);
                                return TRUE;
                            }
                        }
                    }
                }
            }
            RegCloseKey(hsub);
        }
        RegCloseKey(hk);
    }
    return FALSE;
}

void RememberPath(const WCHAR *name, const WCHAR *path)
{
    if (!g_discovered || !name || !path || !path[0]) return;
    KvSet(g_discovered, name, path);
    {
        WCHAR f[PATHCH];
        WPrintf(f, PATHCH, L"%s\\discovered.ini", g_state);
        KvSave(g_discovered, f);
    }
}

BOOL DiscoverExe(const WCHAR *name, WCHAR *out, DWORD cch)
{
    const WCHAR *cached;
    DWORD pids[8];
    int n, i;

    if (!name || !out || !cch) return FALSE;
    out[0] = 0;

    cached = KvGet(g_discovered, name, NULL);
    if (cached && cached[0] && GetFileAttributesW(cached) != INVALID_FILE_ATTRIBUTES) {
        WStrCpy(out, cch, cached);
        return TRUE;
    }

    n = ProcsByName(name, pids, 8);
    for (i = 0; i < n; i++) {
        WCHAR img[PATHCH];
        if (ProcImage(pids[i], img, PATHCH)) {
            WStrCpy(out, cch, img);
            RememberPath(name, img);
            return TRUE;
        }
    }

    if (ScanUninstall(name, out, cch)) { RememberPath(name, out); return TRUE; }
    if (ScanVendorRoots(name, out, cch)) { RememberPath(name, out); return TRUE; }
    return FALSE;
}

/* ===================================================================== */
/* shared state                                                          */
/* ===================================================================== */

BOOL StatePathOf(const WCHAR *key, WCHAR *out, DWORD cch)
{
    if (!key || !key[0]) return FALSE;
    WPrintf(out, cch, L"%s\\%s.ini", g_state, key);
    return TRUE;
}

BOOL StateRead(const WCHAR *key, DWORD *pid, ULONGLONG *ts)
{
    WCHAR path[PATHCH];
    KvDoc *d;
    const WCHAR *v;

    if (pid) *pid = 0;
    if (ts) *ts = 0;
    if (!StatePathOf(key, path, PATHCH)) return FALSE;
    d = KvLoad(path);
    if (!d) return FALSE;
    if (pid) *pid = (DWORD)KvGetInt(d, L"pid", 0);
    v = KvGet(d, L"ts", L"0");
    if (ts) *ts = (ULONGLONG)(v && v[0] ? _wcstoi64(v, NULL, 10) : 0);
    KvFree(d);
    return TRUE;
}

BOOL StateWrite(const WCHAR *key)
{
    WCHAR path[PATHCH], buf[256], tsbuf[32];
    int n;

    if (!StatePathOf(key, path, PATHCH)) return FALSE;
    _ui64tow((unsigned long long)UnixMs(), tsbuf, 10);
    n = WPrintf(buf, 256, L"pid=%lu\r\nts=%s\r\nver=%s\r\n",
                (unsigned long)GetCurrentProcessId(), tsbuf, MWG_VERSION);
    if (n <= 0) return FALSE;
    return WriteTextFile(path, buf);
}

/* ===================================================================== */
/* role spawning                                                         */
/* ===================================================================== */

static BOOL RestoreCopy(const WCHAR *dst)
{
    WCHAR bak[PATHCH];

    WStrCpy(bak, PATHCH, g_mirror);
    WStrCat(bak, PATHCH, L"\\bin.dat");
    if (GetFileAttributesW(bak) != INVALID_FILE_ATTRIBUTES) {
        if (CopyFileW(bak, dst, FALSE)) {
            LogWrite(L"restored %s from mirror", dst);
            return TRUE;
        }
    }
    if (!WStrEqI(g_self, dst) && GetFileAttributesW(g_self) != INVALID_FILE_ATTRIBUTES) {
        if (CopyFileW(g_self, dst, FALSE)) {
            LogWrite(L"restored %s from self image", dst);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL StartRole(const WCHAR *role, const WCHAR *exeName)
{
    WCHAR exe[PATHCH], args[96];
    DWORD pid = 0;

    WStrCpy(exe, PATHCH, g_bin);
    WStrCat(exe, PATHCH, L"\\");
    WStrCat(exe, PATHCH, exeName);
    if (GetFileAttributesW(exe) == INVALID_FILE_ATTRIBUTES) {
        if (!RestoreCopy(exe)) {
            LogWrite(L"cannot start %s: image missing (%s)", role, exe);
            return FALSE;
        }
    }
    WPrintf(args, 96, L"--role %s", role);
    if (!SpawnDetached(exe, args, g_bin, &pid)) {
        LogWrite(L"cannot start %s: %lu", role, (unsigned long)GetLastError());
        return FALSE;
    }
    LogWrite(L"started %s pid=%lu", role, (unsigned long)pid);
    return TRUE;
}

void EnsurePeer(const WCHAR *peerRole, const WCHAR *peerExe)
{
    DWORD pid = 0;
    ULONGLONG ts = 0;
    ULONGLONG timeout = (ULONGLONG)g_cfg.peerTimeoutSec * 1000;

    if (StateRead(peerRole, &pid, &ts) && pid && ProcExists(pid)) {
        ULONGLONG age = (ts && UnixMs() > ts) ? UnixMs() - ts : 0;
        if (ts == 0 || age <= timeout) return;   /* alive is alive */
        LogWrite(L"peer %s pid=%lu heartbeat %lus stale, recycling",
                 peerRole, (unsigned long)pid, (unsigned long)(age / 1000));
        KillPid(pid);
        Sleep(120);
    }
    StartRole(peerRole, peerExe);
}

int EnsureNodes(void)
{
    DWORD sess[8];
    int n, i, started = 0;

    n = ActiveSessions(sess, 8);
    for (i = 0; i < n; i++) {
        WCHAR key[64], exe[PATHCH];
        DWORD pid = 0, npid = 0;
        ULONGLONG ts = 0;

        WPrintf(key, 64, L"node-%lu", (unsigned long)sess[i]);
        if (StateRead(key, &pid, &ts) && pid && ProcExists(pid)) {
            ULONGLONG age = UnixMs() > ts ? UnixMs() - ts : 0;
            if (age <= (ULONGLONG)g_cfg.peerTimeoutSec * 1000) continue;
            if (age > 60000) {
                KillPid(pid);
                Sleep(150);
            }
        }
        WStrCpy(exe, PATHCH, g_bin);
        WStrCat(exe, PATHCH, L"\\" EXE_NODE);
        if (GetFileAttributesW(exe) == INVALID_FILE_ATTRIBUTES && !RestoreCopy(exe)) continue;

        if (!SpawnInSession(sess[i], exe, L"--role node", g_bin, &npid)) {
            if (!IsSystemUser()) {
                /* running as the logged-on user already */
                if (sess[i] == CurrentSession() &&
                    SpawnDetached(exe, L"--role node", g_bin, &npid)) {
                    LogWrite(L"node started in session %lu pid=%lu (same-session)",
                             (unsigned long)sess[i], (unsigned long)npid);
                    started++;
                }
                continue;
            }
            LogWrite(L"node spawn failed in session %lu err=%lu",
                     (unsigned long)sess[i], (unsigned long)GetLastError());
            continue;
        }
        LogWrite(L"node started in session %lu pid=%lu",
                 (unsigned long)sess[i], (unsigned long)npid);
        started++;
    }
    return started;
}

void SelfAuditElevation(void)
{
    DWORD rc = 1;

    if (IsSystemUser()) return;
    if (!RunHidden(L"schtasks.exe /query /tn \"\\MythwareGuard\\Core\"", 20000, &rc))
        return;
    if (rc != 0) return;
    LogWrite(L"elevation lost, handing over to the SYSTEM scheduled task");
    RunHidden(L"schtasks.exe /run /tn \"\\MythwareGuard\\Core\"", 20000, NULL);
    Sleep(1200);
    ExitProcess(0);
}
