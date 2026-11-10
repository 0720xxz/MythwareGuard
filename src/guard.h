/* guard.h : watchdog engine (roles: warden / shadow / node / revive). */
#ifndef MWG_GUARD_H
#define MWG_GUARD_H

#include "common.h"

#define ROLE_WARDEN  L"warden"
#define ROLE_SHADOW  L"shadow"
#define ROLE_NODE    L"node"
#define ROLE_REVIVE  L"revive"

#define EXE_WARDEN   L"mwcore.exe"
#define EXE_SHADOW   L"mwsync.exe"
#define EXE_NODE     L"mwhost.exe"

typedef struct {
    WCHAR     name[96];
    WCHAR     path[PATHCH];
    WCHAR     args[1024];
    DWORD     session;
    BOOL      required;
    BOOL      seen;
    DWORD     hardenedPid;
    DWORD     lastPid;
    ULONGLONG lastSpawn;
    int       fails;
} Target;

typedef struct {
    int  pollMs;
    int  peerTimeoutSec;
    int  harden;
    int  critical;
    int  count;
    Target targets[MAXTARGETS];
} Config;

extern Config  g_cfg;
extern KvDoc  *g_discovered;

/* config.c / guard.c : shared services */
void  WriteDefaultConfig(const WCHAR *path);
BOOL  LoadConfig(void);
BOOL  DiscoverExe(const WCHAR *name, WCHAR *out, DWORD cch);
void  RememberPath(const WCHAR *name, const WCHAR *path);
BOOL  StatePathOf(const WCHAR *key, WCHAR *out, DWORD cch);
BOOL  StateRead(const WCHAR *key, DWORD *pid, ULONGLONG *ts);
BOOL  StateWrite(const WCHAR *key);
BOOL  StartRole(const WCHAR *role, const WCHAR *exeName);
void  EnsurePeer(const WCHAR *peerRole, const WCHAR *peerExe);
int   EnsureNodes(void);
void  SelfAuditElevation(void);

/* engine.c */
int   RunGuard(const WCHAR *role);
int   RunRevive(void);

#endif /* MWG_GUARD_H */
