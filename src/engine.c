/* engine.c : the watchdog loop, target supervision, role entry points. */

#include "guard.h"
#include "win.h"
#include "report.h"

static void DirNameOf(const WCHAR *path, WCHAR *out, DWORD cch)
{
    const WCHAR *p;
    size_t n;
    if (!out || !cch) return;
    out[0] = 0;
    if (!path) return;
    p = wcsrchr(path, L'\\');
    if (!p) return;
    n = (size_t)(p - path);
    if (n >= cch) n = cch - 1;
    memcpy(out, path, n * sizeof(WCHAR));
    out[n] = 0;
}

static HANDLE AcquireLock(const WCHAR *role)
{
    WCHAR name[160];
    HANDLE h;
    DWORD err;

    if (wcscmp(role, ROLE_NODE) == 0) {
        WPrintf(name, 160, L"Global\\MythwareGuard.node.%lu",
                (unsigned long)CurrentSession());
    } else {
        WPrintf(name, 160, L"Global\\MythwareGuard.%s", role);
    }
    SetLastError(0);
    h = CreateMutexW(NULL, FALSE, name);
    err = GetLastError();
    if (h && err == ERROR_ALREADY_EXISTS) {
        CloseHandle(h);
        return NULL;
    }
    if (h) return h;

    WPrintf(name, 160, L"Local\\MythwareGuard.%s.%lu", role,
            (unsigned long)CurrentSession());
    SetLastError(0);
    h = CreateMutexW(NULL, FALSE, name);
    err = GetLastError();
    if (h && err == ERROR_ALREADY_EXISTS) {
        CloseHandle(h);
        return NULL;
    }
    return h;
}

/* --------------------------------------------------------------------- */
/* one scan of the process table for all targets                          */
/* --------------------------------------------------------------------- */

typedef struct {
    DWORD pids[MAXTARGETS][8];
    int   counts[MAXTARGETS];
} ScanCtx;

static void ScanCb(const WCHAR *name, DWORD pid, void *ctx)
{
    ScanCtx *sc = (ScanCtx *)ctx;
    int i;

    for (i = 0; i < g_cfg.count; i++) {
        if (WStrEqI(name, g_cfg.targets[i].name)) {
            if (sc->counts[i] < 8) sc->pids[i][sc->counts[i]] = pid;
            sc->counts[i]++;
            return;
        }
    }
}

static BOOL NodeHealthyFor(DWORD sess)
{
    WCHAR key[64];
    DWORD pid = 0;
    ULONGLONG ts = 0;
    ULONGLONG timeout = (ULONGLONG)g_cfg.peerTimeoutSec * 1000;

    if (sess == 0xFFFFFFFF) return FALSE;
    WPrintf(key, 64, L"node-%lu", (unsigned long)sess);
    if (!StateRead(key, &pid, &ts) || !pid || !ProcExists(pid)) return FALSE;
    if (ts == 0) return TRUE;
    return (UnixMs() > ts ? UnixMs() - ts : 0) <= timeout;
}

static void RespawnTarget(Target *t)
{
    WCHAR exe[PATHCH], cwd[PATHCH];
    DWORD pid = 0, sess;
    BOOL ok;

    WStrCpy(exe, PATHCH, t->path);
    if (!exe[0] || GetFileAttributesW(exe) == INVALID_FILE_ATTRIBUTES) {
        if (!DiscoverExe(t->name, exe, PATHCH)) {
            t->lastSpawn = NowTick();
            t->fails++;
            if (t->fails < 3 || (t->fails % 20) == 0) {
                LogWrite(L"%s: executable not found (attempt %d)", t->name, t->fails);
            }
            return;
        }
        WStrCpy(t->path, PATHCH, exe);
    }
    DirNameOf(exe, cwd, PATHCH);

    sess = t->session;
    if (sess == 0xFFFFFFFF) {
        sess = ConsoleSession();
        if (sess == 0xFFFFFFFF) sess = CurrentSession();
    }

    if (sess == CurrentSession() || sess == 0) {
        ok = SpawnDetached(exe, t->args, cwd, &pid);
    } else {
        ok = SpawnInSession(sess, exe, t->args, cwd, &pid);
        if (!ok) {
            /* no token for that session (service session, logged-off user):
               start it on our own desktop rather than leaving it dead */
            LogWrite(L"%s: no token for session %lu, falling back to own desktop",
                     t->name, (unsigned long)sess);
            ok = SpawnDetached(exe, t->args, cwd, &pid);
        }
    }
    t->lastSpawn = NowTick();

    if (ok) {
        t->fails = 0;
        t->lastPid = pid;
        LogWrite(L"%s: respawned pid=%lu session=%lu", t->name,
                 (unsigned long)pid, (unsigned long)sess);
    } else {
        t->fails++;
        if (t->fails < 3 || (t->fails % 20) == 0) {
            LogWrite(L"%s: respawn FAILED session=%lu err=%lu", t->name,
                     (unsigned long)sess, (unsigned long)GetLastError());
        }
    }
}

static int TargetTick(HANDLE *watch, DWORD *pids, int maxWatch, BOOL supervise)
{
    ScanCtx sc;
    int nw = 0, i, j;
    ULONGLONG now = NowTick();

    ZeroMemory(&sc, sizeof(sc));
    EnumProcs(ScanCb, &sc);

    for (i = 0; i < g_cfg.count; i++) {
        Target *t = &g_cfg.targets[i];

        if (sc.counts[i] > 0) {
            DWORD first = sc.pids[i][0];
            WCHAR img[PATHCH];

            t->seen = TRUE;
            t->fails = 0;
            if (ProcImage(first, img, PATHCH) && img[0] && !WStrEqI(img, t->path)) {
                WStrCpy(t->path, PATHCH, img);
                RememberPath(t->name, img);
            }
            t->session = ProcSession(first);
            t->lastPid = first;

            if (!t->args[0]) {
                WCHAR cl[1024], ce[PATHCH], ca[1024];
                if (GetProcCmdLine(first, cl, 1024) &&
                    SplitCommandLine(cl, ce, PATHCH, ca, 1024) && ca[0]) {
                    WStrCpy(t->args, 1024, ca);
                    LogWrite(L"%s: captured start arguments (%s)", t->name, ca);
                }
            }
            if (g_cfg.harden && t->hardenedPid != first) {
                if (HardenProcess(first)) {
                    t->hardenedPid = first;
                    LogWrite(L"%s: terminate permission revoked for pid=%lu",
                             t->name, (unsigned long)first);
                }
            }
            for (j = 0; j < sc.counts[i] && j < 8 && nw < maxWatch; j++) {
                HANDLE h = ProcWatchHandle(sc.pids[i][j]);
                if (h) {
                    watch[nw] = h;
                    pids[nw] = sc.pids[i][j];
                    nw++;
                }
            }
            continue;
        }

        t->hardenedPid = 0;
        if (!t->required && !t->seen) continue;

        /* the echo tier never restarts a target: it exists only to keep the
           warden alive. Letting both tiers act makes them race and start the
           client twice (two new pids, two events per kill). */
        if (wcscmp(g_role, ROLE_SHADOW) == 0) continue;

        /* ownership: a node owns the targets of its own session, the SYSTEM
           tiers own session 0 (services) and any session whose node died.
           Without this split a session-0 target is nobody's job: the node
           cannot mint a token for session 0 and the warden was told to
           stand down. */
        if (wcscmp(g_role, ROLE_NODE) != 0) {
            if (t->session != 0xFFFFFFFF && t->session != 0 &&
                NodeHealthyFor(t->session))
                continue;
        } else {
            if (t->session != 0xFFFFFFFF && t->session != CurrentSession())
                continue;
        }
        (void)supervise;
        {
            ULONGLONG cooldown = (t->fails > 0) ? 120000ULL : 500ULL;
            if (now - t->lastSpawn < cooldown) continue;
        }
        {
            DWORD deadPid = t->lastPid;
            t->lastPid = 0;
            RespawnTarget(t);
            if (deadPid) {
                /* forensic trail: which client process vanished, when it
                   vanished, and whether we managed to bring it back */
                NotifyExit(t->name, deadPid, t->fails == 0, t->lastPid);
            }
        }
    }
    return nw;
}

/* --------------------------------------------------------------------- */
/* main loop                                                              */
/* --------------------------------------------------------------------- */


static BOOL HasHealthyNode(void)
{
    DWORD sess[8];
    int n, i;
    ULONGLONG timeout = (ULONGLONG)g_cfg.peerTimeoutSec * 1000;

    n = ActiveSessions(sess, 8);
    for (i = 0; i < n; i++) {
        WCHAR key[64];
        DWORD pid = 0;
        ULONGLONG ts = 0;
        WPrintf(key, 64, L"node-%lu", (unsigned long)sess[i]);
        if (StateRead(key, &pid, &ts) && pid && ProcExists(pid)) {
            ULONGLONG age = UnixMs() > ts ? UnixMs() - ts : 0;
            if (age <= timeout) return TRUE;
        }
    }
    return FALSE;
}

static int WatchPeers(HANDLE *watch, DWORD *pids, int max)
{
    static const WCHAR *keys[2] = { ROLE_WARDEN, ROLE_SHADOW };
    int n = 0, i;

    for (i = 0; i < 2 && n < max; i++) {
        DWORD pid = 0;
        ULONGLONG ts = 0;
        HANDLE h;

        if (WStrEqI(keys[i], g_role)) continue;
        if (!StateRead(keys[i], &pid, &ts) || !pid) continue;
        if (!ProcExists(pid)) continue;
        h = ProcWatchHandle(pid);
        if (h) { watch[n] = h; pids[n] = pid; n++; }
    }
    return n;
}

static int WatchNodes(HANDLE *watch, DWORD *pids, int max)
{
    DWORD sess[8];
    int ns, n = 0, i;

    ns = ActiveSessions(sess, 8);
    for (i = 0; i < ns && n < max; i++) {
        WCHAR key[64];
        DWORD pid = 0;
        ULONGLONG ts = 0;
        HANDLE h;

        WPrintf(key, 64, L"node-%lu", (unsigned long)sess[i]);
        if (!StateRead(key, &pid, &ts) || !pid) continue;
        if (!ProcExists(pid)) continue;
        h = ProcWatchHandle(pid);
        if (h) { watch[n] = h; pids[n] = pid; n++; }
    }
    return n;
}

/* Resident watch handles: the kernel signals us the instant a supervised
   process dies, so a killed client is respawned in the same tick instead of
   on the next poll. Handles are only rebuilt when something actually moved
   (or every ~3 s as a safety rescan), which also keeps idle CPU near zero. */
static void GuardLoop(BOOL systemRole, const WCHAR *stateKey)
{
    HANDLE watch[MAXWATCH];
    DWORD  wpids[MAXWATCH];
    int nw = 0, i;
    BOOL rebuild = TRUE;
    BOOL supervise = TRUE;
    unsigned idle = 0;
    ULONGLONG lastBeat = 0;
    ULONGLONG lastAudit = NowTick();

    for (;;) {
        if (rebuild) {
            for (i = 0; i < nw; i++) CloseHandle(watch[i]);
            nw = 0;

            if (systemRole) {
                if (wcscmp(g_role, ROLE_WARDEN) == 0) {
                    EnsurePeer(ROLE_SHADOW, EXE_SHADOW);
                } else if (wcscmp(g_role, ROLE_SHADOW) == 0) {
                    EnsurePeer(ROLE_WARDEN, EXE_WARDEN);
                }
                EnsureNodes();
                supervise = !HasHealthyNode();
            } else {
                supervise = TRUE;
            }

            nw = TargetTick(watch, wpids, MAXWATCH, supervise);
            if (systemRole) {
                if (nw < MAXWATCH)
                    nw += WatchPeers(watch + nw, wpids + nw, MAXWATCH - nw);
                if (nw < MAXWATCH)
                    nw += WatchNodes(watch + nw, wpids + nw, MAXWATCH - nw);
            }
            rebuild = FALSE;
            idle = 0;
        }

        if (nw > 0) {
            DWORD r = WaitForMultipleObjects((DWORD)nw, watch, FALSE,
                                             (DWORD)g_cfg.pollMs);
            if (r == WAIT_FAILED) {
                rebuild = TRUE;
            } else if (r != WAIT_TIMEOUT) {
                DWORD idx = r - WAIT_OBJECT_0;
                if (idx < (DWORD)nw) {
                    LogWrite(L"watch hit: pid=%lu gone, respawning now",
                             (unsigned long)wpids[idx]);
                }
                rebuild = TRUE;
            } else {
                idle++;
                if (idle >= 15) rebuild = TRUE;
            }
        } else {
            Sleep((DWORD)g_cfg.pollMs);
            idle++;
            if (idle >= 15) rebuild = TRUE;
        }

        {
            ULONGLONG now = UnixMs();
            if (now - lastBeat > 2000) {
                StateWrite(stateKey);
                lastBeat = now;
            }
        }
        if (systemRole && NowTick() - lastAudit > 120000) {
            lastAudit = NowTick();
            SelfAuditElevation();
        }
    }
}

/* --------------------------------------------------------------------- */
/* entry points                                                           */
/* --------------------------------------------------------------------- */

int RunGuard(const WCHAR *role)
{
    HANDLE lock;
    BOOL systemRole;
    WCHAR stateKey[64];

    WStrCpy(g_role, 32, role);
    if (!InitPaths()) return 1;
    LogOpen();
    LoadConfig();

    systemRole = (wcscmp(role, ROLE_NODE) != 0);
    LogWrite(L"guard start v%s role=%s pid=%lu session=%lu elevated=%d system=%d",
             MWG_VERSION, role, (unsigned long)GetCurrentProcessId(),
             (unsigned long)CurrentSession(), (int)IsElevated(), (int)IsSystemUser());

    EnablePriv(L"SeDebugPrivilege");
    EnablePriv(L"SeTcbPrivilege");
    EnablePriv(L"SeAssignPrimaryTokenPrivilege");
    EnablePriv(L"SeIncreaseQuotaPrivilege");
    EnablePriv(L"SeCreateGlobalPrivilege");

    if (systemRole) {
        if (g_cfg.critical) {
            if (SetSelfCritical(TRUE)) LogWrite(L"process marked as critical");
        }
        /* hand-over must happen before the lock is taken, otherwise the
           SYSTEM instance would bounce off our mutex and both would exit */
        SelfAuditElevation();
        WStrCpy(stateKey, 64, role);
        /* only the warden reports; the echo tier must not consume the same
           outbox or every event goes out twice */
        if (wcscmp(role, ROLE_SHADOW) != 0) ReportStart();
    } else {
        WPrintf(stateKey, 64, L"node-%lu", (unsigned long)CurrentSession());
    }

    lock = AcquireLock(role);
    if (!lock) {
        LogWrite(L"another %s instance already holds the lock, exiting", role);
        LogClose();
        return 0;
    }

    StateWrite(stateKey);
    GuardLoop(systemRole, stateKey);
    return 0;
}

int RunRevive(void)
{
    DWORD pid = 0, spid = 0;
    ULONGLONG ts = 0, sts = 0;
    ULONGLONG timeout;

    WStrCpy(g_role, 32, ROLE_REVIVE);
    InitPaths();
    LogOpen();
    LoadConfig();
    timeout = (ULONGLONG)g_cfg.peerTimeoutSec * 1000;

    if (StateRead(ROLE_WARDEN, &pid, &ts) && pid && ProcExists(pid)) {
        ULONGLONG age = UnixMs() > ts ? UnixMs() - ts : 0;
        if (age <= timeout) {
            if (!(StateRead(ROLE_SHADOW, &spid, &sts) && spid && ProcExists(spid))) {
                LogWrite(L"revive: warden alive, echo missing, restarting shadow");
                StartRole(ROLE_SHADOW, EXE_SHADOW);
            }
            LogClose();
            return 0;
        }
        LogWrite(L"revive: warden pid=%lu stale (%lus), recycling",
                 (unsigned long)pid, (unsigned long)(age / 1000));
        KillPid(pid);
    }
    LogWrite(L"revive: warden absent, starting it");
    StartRole(ROLE_WARDEN, EXE_WARDEN);
    LogClose();
    return 0;
}
