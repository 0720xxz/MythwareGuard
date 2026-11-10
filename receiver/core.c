/* core.c : event store (JSONL, one file per day) + LAN listener. */

#include "core.h"
#include "../src/crypto.h"
#include <stdarg.h>
#include <stdint.h>

Event            g_events[MAXEVENTS];
int              g_evCount = 0;
CRITICAL_SECTION g_cs;
CRITICAL_SECTION g_logcs;
volatile LONG    g_dirty = 0;
volatile LONG    g_total = 0;
volatile LONG    g_today = 0;

static int           g_port = 17800;
static volatile LONG g_stop = 0;
static HANDLE        g_thread = NULL;
static HANDLE        g_logh = INVALID_HANDLE_VALUE;
static WCHAR         g_base[512];
static WCHAR         g_evdir[600];

/* --------------------------------------------------------------------- */
/* helpers                                                               */
/* --------------------------------------------------------------------- */

void ToWide(const char *s, WCHAR *w, int cch)
{
    if (!w || cch <= 0) return;
    w[0] = 0;
    if (!s) return;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, cch);
}

static ULONGLONG NowMs(void)
{
    FILETIME ft;
    ULARGE_INTEGER li;
    GetSystemTimeAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    return (li.QuadPart - 116444736000000000ULL) / 10000ULL;
}

void FormatTs(ULONGLONG ms, WCHAR *out, int cch)
{
    time_t t = (time_t)(ms / 1000);
    struct tm tmv;
    if (!out || cch <= 0) return;
    out[0] = 0;
    ZeroMemory(&tmv, sizeof(tmv));
    if (localtime_s(&tmv, &t) != 0) return;
    wsprintfW(out, L"%04d-%02d-%02d %02d:%02d:%02d",
              tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
              tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
}

void FormatTsA(ULONGLONG ms, char *out, int cch)
{
    time_t t = (time_t)(ms / 1000);
    struct tm tmv;
    if (!out || cch <= 0) return;
    ZeroMemory(&tmv, sizeof(tmv));
    if (localtime_s(&tmv, &t) != 0) { out[0] = 0; return; }
    snprintf(out, cch, "%04d-%02d-%02d %02d:%02d:%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
}

static BOOL EnsureDir(const WCHAR *p)
{
    DWORD a = GetFileAttributesW(p);
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) return TRUE;
    return CreateDirectoryW(p, NULL) != 0;
}

/* --------------------------------------------------------------------- */
/* logging                                                               */
/* --------------------------------------------------------------------- */

void RecvLogInit(void)
{
    WCHAR file[600];

    InitializeCriticalSection(&g_logcs);
    if (GetEnvironmentVariableW(L"ProgramData", g_base, 512) == 0)
        lstrcpyW(g_base, L"C:\\ProgramData");
    wsprintfW(g_evdir, L"%s\\MwReceiver\\events", g_base);
    {
        WCHAR dir[512];
        wsprintfW(dir, L"%s\\MwReceiver", g_base);
        EnsureDir(dir);
        EnsureDir(g_evdir);
    }
    wsprintfW(file, L"%s\\MwReceiver\\receiver.log", g_base);

    g_logh = CreateFileW(file, FILE_APPEND_DATA,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logh != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz;
        if (GetFileSizeEx(g_logh, &sz) && sz.QuadPart == 0) {
            const char bom[3] = { (char)0xEF, (char)0xBB, (char)0xBF };
            DWORD w;
            WriteFile(g_logh, bom, 3, &w, NULL);
        }
    }
}

void RecvLog(const char *fmt, ...)
{
    SYSTEMTIME st;
    char line[1024], stamp[64];
    va_list ap;
    int n;
    DWORD written = 0;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    GetLocalTime(&st);
    n = sprintf(stamp, "%04d-%02d-%02d %02d:%02d:%02d  ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    EnterCriticalSection(&g_logcs);
    if (g_logh != INVALID_HANDLE_VALUE) {
        WriteFile(g_logh, stamp, (DWORD)n, &written, NULL);
        WriteFile(g_logh, line, (DWORD)strlen(line), &written, NULL);
        WriteFile(g_logh, "\r\n", 2, &written, NULL);
    }
    LeaveCriticalSection(&g_logcs);
}

/* --------------------------------------------------------------------- */
/* storage                                                               */
/* --------------------------------------------------------------------- */

static void DayFile(ULONGLONG ms, WCHAR *out, int cch)
{
    SYSTEMTIME st;
    FILETIME ft, lf;
    ULARGE_INTEGER li;

    li.QuadPart = ms * 10000ULL + 116444736000000000ULL;
    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = li.HighPart;
    FileTimeToLocalFileTime(&ft, &lf);
    (void)cch;
    FileTimeToSystemTime(&lf, &st);
    wsprintfW(out, L"%s\\%04d-%02d-%02d.jsonl", g_evdir,
              st.wYear, st.wMonth, st.wDay);
}

static void AppendToDisk(const Event *e)
{
    WCHAR path[600];
    char line[1024];
    HANDLE h;
    DWORD written = 0;
    int n;

    DayFile(e->ts, path, 600);
    h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    n = snprintf(line, sizeof(line),
        "{\"v\":1,\"ev\":\"exit\",\"ts\":%lld,\"id\":\"%s\",\"host\":\"%s\","
        "\"user\":\"%s\",\"group\":\"%s\",\"ip\":\"%s\","
        "\"name\":\"%s\",\"pid\":%lu,\"ok\":%d,\"newpid\":%lu,\"recv\":%lld}\n",
        (long long)(e->ts / 1000), e->id, e->host, e->user, e->group, e->ip,
        e->name, (unsigned long)e->pid, e->ok, (unsigned long)e->newPid,
        (long long)(e->recvAt / 1000));
    WriteFile(h, line, (DWORD)n, &written, NULL);
    CloseHandle(h);
}

static void PushEvent(const Event *e, BOOL persist)
{
    EnterCriticalSection(&g_cs);
    if (g_evCount >= MAXEVENTS) {
        memmove(&g_events[0], &g_events[1],
                (SIZE_T)(MAXEVENTS - 1) * sizeof(Event));
        g_evCount = MAXEVENTS - 1;
    }
    g_events[g_evCount++] = *e;
    LeaveCriticalSection(&g_cs);

    InterlockedIncrement(&g_total);
    if (persist) AppendToDisk(e);
    InterlockedExchange(&g_dirty, 1);
}

void TableInit(void)
{
    InitializeCriticalSection(&g_cs);
    ZeroMemory(g_events, sizeof(g_events));
    g_evCount = 0;
}

int EventsSnapshot(Event *out, int max)
{
    int n = 0;
    EnterCriticalSection(&g_cs);
    n = (g_evCount < max) ? g_evCount : max;
    if (n > 0) memcpy(out, g_events, (SIZE_T)n * sizeof(Event));
    LeaveCriticalSection(&g_cs);
    return n;
}

/* --------------------------------------------------------------------- */
/* JSON field extraction (our own payload)                               */
/* --------------------------------------------------------------------- */

static BOOL JsonStr(const char *json, const char *key, char *out, int cch)
{
    char pat[96];
    const char *p, *q;
    int o = 0;

    if (!out || cch <= 0) return FALSE;
    out[0] = 0;
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = strstr(json, pat);
    if (!p) return FALSE;
    p += strlen(pat);
    q = p;
    while (*q && *q != '"' && o + 1 < cch) {
        if (*q == '\\' && q[1]) q++;
        out[o++] = *q++;
    }
    out[o] = 0;
    return TRUE;
}

static long long JsonNum(const char *json, const char *key)
{
    char pat[96];
    const char *p;
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(json, pat);
    if (!p) return 0;
    return _atoi64(p + strlen(pat));
}

static void ParseLine(const char *line, Event *e)
{
    char tsbuf[64];
    ZeroMemory(e, sizeof(*e));

    JsonStr(line, "id", e->id, sizeof(e->id));
    JsonStr(line, "host", e->host, sizeof(e->host));
    JsonStr(line, "user", e->user, sizeof(e->user));
    JsonStr(line, "group", e->group, sizeof(e->group));
    JsonStr(line, "ip", e->ip, sizeof(e->ip));
    JsonStr(line, "name", e->name, sizeof(e->name));
    if (JsonStr(line, "ts", tsbuf, sizeof(tsbuf)) && tsbuf[0])
        e->ts = (ULONGLONG)_atoi64(tsbuf) * 1000ULL;
    else
        e->ts = (ULONGLONG)JsonNum(line, "ts") * 1000ULL;
    e->pid = (DWORD)JsonNum(line, "pid");
    e->ok = (int)JsonNum(line, "ok");
    e->newPid = (DWORD)JsonNum(line, "newpid");
    e->recvAt = (ULONGLONG)JsonNum(line, "recv") * 1000ULL;
    if (!e->recvAt) e->recvAt = NowMs();
    if (!e->ts) e->ts = e->recvAt;
}

/* --------------------------------------------------------------------- */
/* history load                                                          */
/* --------------------------------------------------------------------- */

static int CmpEvent(const void *a, const void *b)
{
    const Event *x = (const Event *)a;
    const Event *y = (const Event *)b;
    if (x->ts < y->ts) return -1;
    if (x->ts > y->ts) return 1;
    return 0;
}

static int CmpW(const void *a, const void *b)
{
    return lstrcmpiW((const WCHAR *)a, (const WCHAR *)b);
}

void HistoryLoad(void)
{
    WIN32_FIND_DATAW fd;
    HANDLE h;
    WCHAR pattern[600];
    WCHAR files[400][260];
    int nf = 0, i;
    int total = 0;

    wsprintfW(pattern, L"%s\\*.jsonl", g_evdir);
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        RecvLog("history dir is empty");
        return;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (nf < 400) lstrcpynW(files[nf++], fd.cFileName, 260);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (!nf) return;

    qsort(files, (size_t)nf, sizeof(files[0]), CmpW);

    /* newest files first, stop once MAXEVENTS records are collected */
    for (i = nf - 1; i >= 0 && total < MAXEVENTS; i--) {
        WCHAR path[600];
        HANDLE f;
        LARGE_INTEGER li;
        char *buf;
        char *p, *nl;
        DWORD sz = 0, got = 0;
        int lines = 0;

        wsprintfW(path, L"%s\\%s", g_evdir, files[i]);
        f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) continue;
        if (!GetFileSizeEx(f, &li) || li.QuadPart <= 0) { CloseHandle(f); continue; }
        sz = (li.QuadPart > (16 << 20)) ? (16u << 20) : (DWORD)li.QuadPart;
        buf = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)sz + 2);
        if (!buf) { CloseHandle(f); continue; }
        ReadFile(f, buf, sz, &got, NULL);
        buf[got] = 0;
        CloseHandle(f);

        p = buf;
        while (p && *p && total < MAXEVENTS) {
            nl = strchr(p, '\n');
            if (nl) *nl = 0;
            if (strlen(p) > 8) {
                Event ev;
                ParseLine(p, &ev);
                PushEvent(&ev, FALSE);
                total++;
                lines++;
            }
            p = nl ? nl + 1 : NULL;
        }
        HeapFree(GetProcessHeap(), 0, buf);
        if (lines) RecvLog("loaded %d records from a day file", lines);
    }

    /* files were pushed newest-first; restore chronological order */
    EnterCriticalSection(&g_cs);
    if (g_evCount > 1) qsort(g_events, (size_t)g_evCount, sizeof(Event), CmpEvent);
    LeaveCriticalSection(&g_cs);

    InterlockedExchange(&g_total, (LONG)g_evCount);
    RecvLog("history load done, %d records", g_evCount);
}

/* --------------------------------------------------------------------- */
/* export / clear                                                        */
/* --------------------------------------------------------------------- */

BOOL ExportCsv(const Event *ev, int n, const char *keyword,
               WCHAR *outPath, int cch)
{
    SYSTEMTIME st;
    WCHAR path[600];
    HANDLE h;
    DWORD written = 0;
    int i;

    GetLocalTime(&st);
    wsprintfW(path, L"%s\\MwReceiver\\export-%04d%02d%02d-%02d%02d%02d.csv",
              g_base, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    {
        const char bom[3] = { (char)0xEF, (char)0xBB, (char)0xBF };
        WriteFile(h, bom, 3, &written, NULL);
    }
    {
        const char *hdr = "time,host,user,group,ip,process,pid,respawn_ok,new_pid,machine_id\r\n";
        WriteFile(h, hdr, (DWORD)strlen(hdr), &written, NULL);
    }
    for (i = 0; i < n; i++) {
        char ts[32], line[1024];
        int len;
        if (keyword && keyword[0]) {
            if (!strstr(ev[i].host, keyword) && !strstr(ev[i].user, keyword) &&
                !strstr(ev[i].ip, keyword) && !strstr(ev[i].name, keyword))
                continue;
        }
        FormatTsA(ev[i].ts, ts, sizeof(ts));
        len = snprintf(line, sizeof(line),
                       "%s,%s,%s,%s,%s,%s,%lu,%d,%lu,%s\r\n",
                       ts, ev[i].host, ev[i].user, ev[i].group, ev[i].ip,
                       ev[i].name, (unsigned long)ev[i].pid, ev[i].ok,
                       (unsigned long)ev[i].newPid, ev[i].id);
        WriteFile(h, line, (DWORD)len, &written, NULL);
    }
    CloseHandle(h);
    if (outPath && cch) lstrcpynW(outPath, path, cch);
    RecvLog("CSV exported (%d rows)", n);
    return TRUE;
}

BOOL ClearHistory(WCHAR *msg, int cch)
{
    WIN32_FIND_DATAW fd;
    HANDLE h;
    WCHAR pattern[600];
    int n = 0;

    wsprintfW(pattern, L"%s\\*.jsonl", g_evdir);
    h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            WCHAR path[600];
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            wsprintfW(path, L"%s\\%s", g_evdir, fd.cFileName);
            if (DeleteFileW(path)) n++;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    EnterCriticalSection(&g_cs);
    g_evCount = 0;
    LeaveCriticalSection(&g_cs);
    InterlockedExchange(&g_dirty, 1);
    RecvLog("已清空 %d 个历史文件", n);
    if (msg && cch) wsprintfW(msg, L"已删除 %d 个存储文件，内存记录已清空。", n);
    return TRUE;
}

/* --------------------------------------------------------------------- */
/* RSA keypair                                                           */
/* --------------------------------------------------------------------- */

static BYTE  *g_priv = NULL;
static DWORD  g_privLen = 0;
static BYTE  *g_pub = NULL;
static DWORD  g_pubLen = 0;
static WCHAR  g_keydir[600];

static BOOL BlobLoad(const WCHAR *name, BYTE **out, DWORD *outLen)
{
    WCHAR path[700];
    HANDLE h;
    LARGE_INTEGER sz;
    DWORD got = 0;
    BYTE *buf;

    wsprintfW(path, L"%s\\%s", g_keydir, name);
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 64 || sz.QuadPart > 8192) {
        CloseHandle(h);
        return FALSE;
    }
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)sz.QuadPart);
    if (!buf) { CloseHandle(h); return FALSE; }
    ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL);
    CloseHandle(h);
    *out = buf;
    *outLen = got;
    return got > 0;
}

static void BlobSave(const WCHAR *name, const BYTE *data, DWORD len)
{
    WCHAR path[700];
    HANDLE h;
    DWORD written = 0;

    wsprintfW(path, L"%s\\%s", g_keydir, name);
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, data, len, &written, NULL);
    CloseHandle(h);
}

static void KeysInit(void)
{
    wsprintfW(g_keydir, L"%s\\MwReceiver\\keys", g_base);
    EnsureDir(g_keydir);

    if (BlobLoad(L"private.blob", &g_priv, &g_privLen) &&
        BlobLoad(L"public.blob", &g_pub, &g_pubLen)) {
        RecvLog("RSA keypair loaded (%lu bytes private)", (unsigned long)g_privLen);
        return;
    }
    if (RsaGenerateKeyPair(&g_pub, &g_pubLen, &g_priv, &g_privLen)) {
        BlobSave(L"private.blob", g_priv, g_privLen);
        BlobSave(L"public.blob", g_pub, g_pubLen);
        RecvLog("RSA-2048 keypair generated for this collector");
    } else {
        RecvLog("RSA keypair generation FAILED - encrypted reports will be rejected");
    }
}

/* --------------------------------------------------------------------- */
/* HTTP                                                                  */
/* --------------------------------------------------------------------- */

static void SendResp(SOCKET c, int code, const char *ctype, const char *body)
{
    char hdr[320];
    int n;
    const char *reason = (code == 200) ? "OK" :
                         (code == 400) ? "Bad Request" :
                         (code == 404) ? "Not Found" :
                         (code == 413) ? "Payload Too Large" :
                         (code == 415) ? "Unsupported Media Type" : "Error";

    n = snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
                 "Connection: close\r\n\r\n",
                 code, reason, ctype, (int)strlen(body));
    send(c, hdr, n, 0);
    send(c, body, (int)strlen(body), 0);
}

static int ReadRequest(SOCKET c, char *buf, int cch, int *bodyOff, int *bodyLen)
{
    int total = 0, n;
    char *hdrEnd, *cl;

    *bodyOff = 0;
    *bodyLen = 0;
    for (;;) {
        n = recv(c, buf + total, cch - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = 0;
        hdrEnd = strstr(buf, "\r\n\r\n");
        if (hdrEnd) {
            int need = 0;
            cl = strstr(buf, "Content-Length:");
            if (!cl) cl = strstr(buf, "content-length:");
            if (cl) need = atoi(cl + 15);
            *bodyOff = (int)(hdrEnd + 4 - buf);
            *bodyLen = need;
            if (total - *bodyOff >= need || need == 0) return total;
        }
        if (total >= cch - 1) break;
    }
    return total;
}

static void HandleEventBody(const char *body, int len, const char *ctype,
                            const char *peer, SOCKET c)
{
    char plain[8192];

    plain[0] = 0;
    if (strstr(ctype, "application/json")) {
        int n = (len < (int)sizeof(plain) - 1) ? len : (int)sizeof(plain) - 1;
        memcpy(plain, body, (size_t)n);
        plain[n] = 0;
    } else {
        DWORD encLen = 0;
        BYTE *enc;
        BYTE *dec = NULL;
        DWORD decLen = 0;

        if (!g_priv) { SendResp(c, 415, "text/plain", "no key"); return; }
        enc = B64Decode(body, &encLen);
        if (!enc || !encLen) { CryptoFree(enc); SendResp(c, 400, "text/plain", "bad base64"); return; }
        if (!RsaDecrypt(g_priv, g_privLen, enc, encLen, &dec, &decLen)) {
            CryptoFree(enc);
            RecvLog("RSA decrypt failed from %s", peer);
            SendResp(c, 400, "text/plain", "decrypt failed");
            return;
        }
        CryptoFree(enc);
        if (decLen >= sizeof(plain)) decLen = sizeof(plain) - 1;
        memcpy(plain, dec, decLen);
        plain[decLen] = 0;
        CryptoFree(dec);
    }

    {
        Event e;
        ParseLine(plain, &e);
        if (!e.host[0]) lstrcpynA(e.host, peer, sizeof(e.host));
        if (!e.ip[0]) lstrcpynA(e.ip, peer, sizeof(e.ip));
        PushEvent(&e, TRUE);
        RecvLog("exit event: %s user=%s proc=%s pid=%lu respawn=%s newpid=%lu",
                e.host, e.user, e.name, (unsigned long)e.pid,
                e.ok ? "ok" : "FAILED", (unsigned long)e.newPid);
    }
    SendResp(c, 200, "application/json", "{\"ok\":true}");
}

static void HandleTcp(SOCKET listenSock)
{
    struct sockaddr_in from;
    int fl = sizeof(from);
    SOCKET c;
    DWORD tv = 3000;
    static char buf[32768];
    char peer[64];
    int total, bodyOff, bodyLen;
    char method[16], path[256], ctype[128];
    char *p, *sp;

    c = accept(listenSock, (struct sockaddr *)&from, &fl);
    if (c == INVALID_SOCKET) return;
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    inet_ntop(AF_INET, &from.sin_addr, peer, sizeof(peer));

    total = ReadRequest(c, buf, (int)sizeof(buf), &bodyOff, &bodyLen);
    if (total <= 0) { closesocket(c); return; }

    method[0] = path[0] = ctype[0] = 0;
    p = strchr(buf, ' ');
    if (p) {
        int n = (int)(p - buf);
        if (n > 0 && n < (int)sizeof(method)) {
            memcpy(method, buf, (size_t)n);
            method[n] = 0;
        }
        sp = strchr(p + 1, ' ');
        if (sp) {
            n = (int)(sp - (p + 1));
            if (n > 0 && n < (int)sizeof(path)) {
                memcpy(path, p + 1, (size_t)n);
                path[n] = 0;
            }
        }
    }
    p = strstr(buf, "Content-Type:");
    if (p) {
        char *e = strstr(p, "\r\n");
        int n = e ? (int)(e - (p + 13)) : 0;
        if (n > 0 && n < (int)sizeof(ctype)) {
            memcpy(ctype, p + 13, (size_t)n);
            ctype[n] = 0;
        }
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/pubkey") == 0) {
        char *b64;
        if (!g_pub) { SendResp(c, 415, "text/plain", "no key"); closesocket(c); return; }
        b64 = B64Encode(g_pub, g_pubLen);
        SendResp(c, 200, "text/plain", b64 ? b64 : "");
        CryptoFree(b64);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/health") == 0) {
        char body[256];
        snprintf(body, sizeof(body),
                 "{\"ok\":true,\"app\":\"MwReceiver\",\"ver\":\"1.0.0\",\"events\":%d}",
                 g_evCount);
        SendResp(c, 200, "application/json", body);
    } else if (strcmp(method, "GET") == 0 && strncmp(path, "/api/v1/events", 14) == 0) {
        static Event snap[MAXEVENTS];
        char *out;
        int n, i, limit = 100, used = 0;
        char *q = strstr(path, "limit=");
        if (q) limit = atoi(q + 6);
        if (limit < 1) limit = 1;
        if (limit > 1000) limit = 1000;
        n = EventsSnapshot(snap, MAXEVENTS);
        if (n > limit) { memmove(snap, snap + (n - limit), (SIZE_T)limit * sizeof(Event)); n = limit; }
        out = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)n * 800 + 64);
        if (!out) { SendResp(c, 400, "text/plain", "oom"); closesocket(c); return; }
        used += snprintf(out + used, 32, "[");
        for (i = 0; i < n; i++) {
            used += snprintf(out + used, 800,
                "%s{\"ts\":%lld,\"host\":\"%s\",\"user\":\"%s\",\"group\":\"%s\","
                "\"ip\":\"%s\",\"name\":\"%s\",\"pid\":%lu,\"ok\":%d,\"newpid\":%lu,\"id\":\"%s\"}",
                i ? "," : "", (long long)(snap[i].ts / 1000), snap[i].host,
                snap[i].user, snap[i].group, snap[i].ip, snap[i].name,
                (unsigned long)snap[i].pid, snap[i].ok,
                (unsigned long)snap[i].newPid, snap[i].id);
        }
        used += snprintf(out + used, 8, "]");
        SendResp(c, 200, "application/json", out);
        HeapFree(GetProcessHeap(), 0, out);
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/events") == 0) {
        int off = bodyOff;
        if (bodyLen <= 0 || off + bodyLen > total) {
            SendResp(c, 400, "text/plain", "empty body");
        } else {
            buf[off + bodyLen] = 0;
            HandleEventBody(buf + off, bodyLen, ctype, peer, c);
        }
    } else {
        SendResp(c, 404, "text/plain", "not found");
    }
    closesocket(c);
}

static void HandleUdp(SOCKET udpSock)
{
    struct sockaddr_in from;
    int fl = sizeof(from);
    char buf[256];
    int n;

    n = recvfrom(udpSock, buf, sizeof(buf) - 1, 0,
                 (struct sockaddr *)&from, &fl);
    if (n >= 6 && memcmp(buf, "MWGD?1", 6) == 0) {
        sendto(udpSock, "MWGD!1", 6, 0, (struct sockaddr *)&from, fl);
    }
}

static DWORD WINAPI NetThread(LPVOID param)
{
    SOCKET udp = INVALID_SOCKET, tcp = INVALID_SOCKET;
    struct sockaddr_in addr;

    (void)param;
    KeysInit();

    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((u_short)g_port);

    udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) return 0;
    {
        int yes = 1;
        setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    }
    if (bind(udp, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        RecvLog("UDP %d bind failed (%d)", g_port, WSAGetLastError());
        closesocket(udp);
        return 0;
    }

    tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp == INVALID_SOCKET) { closesocket(udp); return 0; }
    if (bind(tcp, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(tcp, 32) != 0) {
        RecvLog("TCP %d bind failed (%d)", g_port, WSAGetLastError());
        closesocket(udp);
        closesocket(tcp);
        return 0;
    }
    RecvLog("HTTP service on 0.0.0.0:%d (GET pubkey/health/events, POST events)", g_port);

    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        fd_set rd;
        struct timeval tv;
        int r;

        FD_ZERO(&rd);
        FD_SET(udp, &rd);
        FD_SET(tcp, &rd);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        r = select(0, &rd, NULL, NULL, &tv);
        if (r <= 0) continue;
        if (FD_ISSET(udp, &rd)) HandleUdp(udp);
        if (FD_ISSET(tcp, &rd)) HandleTcp(tcp);
    }

    closesocket(udp);
    closesocket(tcp);
    return 0;
}

BOOL NetStart(int port)
{
    WSADATA wsa;

    g_port = port;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        RecvLog("WSAStartup failed");
        return FALSE;
    }
    g_thread = CreateThread(NULL, 0, NetThread, NULL, 0, NULL);
    return g_thread != NULL;
}

void NetStop(void)
{
    InterlockedExchange(&g_stop, 1);
    if (g_thread) {
        WaitForSingleObject(g_thread, 2000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    WSACleanup();
}

int NetPort(void)
{
    return g_port;
}
