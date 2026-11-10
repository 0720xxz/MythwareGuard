/* win.h : thin Win32 layer - processes, sessions, spawning, ACL, privileges. */
#ifndef MWG_WIN_H
#define MWG_WIN_H

#include "common.h"

/* ---- process inspection ---- */
typedef void (*ProcCb)(const WCHAR *name, DWORD pid, void *ctx);

BOOL  ProcExists(DWORD pid);
BOOL  ProcImage(DWORD pid, WCHAR *buf, DWORD cch);
DWORD ProcSession(DWORD pid);
int   ProcsByName(const WCHAR *name, DWORD *pids, int max);
int   EnumProcs(ProcCb cb, void *ctx);
BOOL  GetProcCmdLine(DWORD pid, WCHAR *out, DWORD cch);
HANDLE ProcWatchHandle(DWORD pid);          /* SYNCHRONIZE handle or NULL */
BOOL  KillPid(DWORD pid);

/* ---- sessions ---- */
int   ActiveSessions(DWORD *out, int max);  /* interactive sessions only   */
DWORD CurrentSession(void);
DWORD ConsoleSession(void);

/* ---- privileges / identity ---- */
BOOL  IsElevated(void);
BOOL  IsSystemUser(void);
BOOL  EnablePriv(const WCHAR *name);

/* ---- spawning ---- */
BOOL  SpawnDetached(const WCHAR *exe, const WCHAR *args, const WCHAR *cwd,
                    DWORD *outPid);
BOOL  SpawnInSession(DWORD session, const WCHAR *exe, const WCHAR *args,
                     const WCHAR *cwd, DWORD *outPid);
BOOL  RunHidden(const WCHAR *cmdline, DWORD timeoutMs, DWORD *exitCode);

/* ---- hardening ---- */
BOOL  HardenProcess(DWORD pid);
BOOL  SetSelfCritical(BOOL on);
BOOL  DenyTerminateToUsers(DWORD pid);

/* ---- misc ---- */
void  GetOwnImage(WCHAR *buf, DWORD cch);
BOOL  SplitCommandLine(const WCHAR *cmd, WCHAR *exe, DWORD ecc,
                       WCHAR *args, DWORD acch);

#endif /* MWG_WIN_H */
