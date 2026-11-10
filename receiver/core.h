/* core.h : exit-event store for the LAN collector. */
#ifndef MWG_CORE_H
#define MWG_CORE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAXEVENTS 8000
#define RECV_APP  L"MwReceiver"
#define RECV_VER  L"1.0.0"

/* one "classroom client process was killed" record */
typedef struct {
    ULONGLONG ts;         /* when it happened on the client (ms)   */
    ULONGLONG recvAt;     /* when we received it (ms)              */
    char      id[80];     /* machine guid                          */
    char      host[128];
    char      user[128];
    char      group[64];
    char      ip[64];
    char      name[96];   /* killed process, e.g. TopDomain.exe    */
    DWORD     pid;
    DWORD     newPid;     /* 0 = we could not bring it back        */
    int       ok;
} Event;

extern Event            g_events[MAXEVENTS];
extern int              g_evCount;
extern CRITICAL_SECTION g_cs;
extern CRITICAL_SECTION g_logcs;
extern volatile LONG    g_dirty;
extern volatile LONG    g_total;
extern volatile LONG    g_today;

void  TableInit(void);
void  HistoryLoad(void);
int   EventsSnapshot(Event *out, int max);       /* time ascending */
void  RecvLogInit(void);
void  RecvLog(const char *fmt, ...);
void  ToWide(const char *s, WCHAR *w, int cch);
void  FormatTs(ULONGLONG ms, WCHAR *out, int cch);
void  FormatTsA(ULONGLONG ms, char *out, int cch);
BOOL  ExportCsv(const Event *ev, int n, const char *keyword,
                WCHAR *outPath, int cch);
BOOL  ClearHistory(WCHAR *msg, int cch);

BOOL  NetStart(int port);
void  NetStop(void);
int   NetPort(void);

#endif /* MWG_CORE_H */
