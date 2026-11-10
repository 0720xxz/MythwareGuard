/* MythwareGuard - layered anti-kill watchdog for the classroom client.
 * common.h : shared declarations, tiny containers, logging, path helpers.
 */
#ifndef MWG_COMMON_H
#define MWG_COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define MWG_VERSION  L"1.0.0"
#define MWG_APPNAME  L"MythwareGuard"
#define PATHCH       1024
#define MAXTARGETS   16
#define MAXWATCH     64

/* ---------------- global paths (filled by InitPaths) ---------------- */
extern WCHAR g_root[PATHCH];    /* %ProgramData%\MythwareGuard        */
extern WCHAR g_bin[PATHCH];     /* ...\bin                            */
extern WCHAR g_state[PATHCH];   /* ...\state                          */
extern WCHAR g_logdir[PATHCH];  /* ...\logs                           */
extern WCHAR g_mirror[PATHCH];  /* ...\mirror                         */
extern WCHAR g_cfgpath[PATHCH];     /* ...\config.ini                     */
extern WCHAR g_self[PATHCH];    /* full path of the running image     */
extern WCHAR g_role[32];        /* role name of this process          */

BOOL  InitPaths(void);
BOOL  EnsureDir(const WCHAR *path);
BOOL  WriteTextFile(const WCHAR *path, const WCHAR *text);

/* ---------------- string helpers ---------------- */
int   WPrintf(WCHAR *buf, size_t cch, const WCHAR *fmt, ...);
WCHAR *WStrCpy(WCHAR *dst, size_t cch, const WCHAR *src);
WCHAR *WStrCat(WCHAR *dst, size_t cch, const WCHAR *src);
BOOL  WStrEqI(const WCHAR *a, const WCHAR *b);
BOOL  WStrStartsI(const WCHAR *s, const WCHAR *prefix);
void  WStrTrim(WCHAR *s);
BOOL  WCharIsSpace(WCHAR c);

/* ---------------- key/value document ---------------- */
typedef struct {
    WCHAR key[128];
    WCHAR val[PATHCH];
} KvItem;

typedef struct {
    KvItem *items;
    int     count;
    int     cap;
} KvDoc;

KvDoc *KvLoad(const WCHAR *path);
void   KvFree(KvDoc *doc);
const WCHAR *KvGet(KvDoc *doc, const WCHAR *key, const WCHAR *def);
int    KvGetInt(KvDoc *doc, const WCHAR *key, int def);
BOOL   KvSet(KvDoc *doc, const WCHAR *key, const WCHAR *val);
BOOL   KvSave(KvDoc *doc, const WCHAR *path);
int    KvCountPrefix(KvDoc *doc, const WCHAR *prefix);
BOOL   KvGetPrefixAt(KvDoc *doc, const WCHAR *prefix, int idx,
                     WCHAR *keyout, size_t kcch, WCHAR *valout, size_t vcch);

/* ---------------- time ---------------- */
ULONGLONG NowTick(void);      /* monotonic ms        */
ULONGLONG UnixMs(void);       /* wall clock ms       */

/* ---------------- logging ---------------- */
void LogOpen(void);
void LogWrite(const WCHAR *fmt, ...);
void LogClose(void);

#endif /* MWG_COMMON_H */
