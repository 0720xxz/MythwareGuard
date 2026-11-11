/* report.c : durable exit-event outbox + RSA-protected delivery.
 *
 * Reliability: an event is first appended to a local on-disk queue
 * (%ProgramData%\MythwareGuard\queue\*.json). A worker drains that queue in
 * timestamp order and only deletes a file after the collector answered
 * HTTP 200. Anything that fails (cable pulled, Wi-Fi flap, collector down)
 * stays on disk and is retried with exponential backoff, so nothing is lost
 * across network outages or reboots.
 *
 * Transport: HTTP/1.1 on port 17800 (never 80/443) - GET for discovery of the
 * collector public key, POST for the event itself.
 * Confidentiality: the JSON body is RSA-2048/OAEP-SHA256 encrypted with the
 * collector's public key, split into 190-byte chunks, base64 on the wire.
 */

#include "report.h"
#include "guard.h"
#include "win.h"
#include "crypto.h"
#include <iphlpapi.h>
#include <wtsapi32.h>
#include <stdlib.h>

#define EVQ_MAX      2000
#define BACKOFF_MIN  1000
#define BACKOFF_MAX  30000

typedef struct {
    int  enable;
    int  crypto;
    int  port;
    char server[64];
    char group[128];
} RepCfg;

static RepCfg  g_rc;
static HANDLE  g_sem = NULL;
static volatile LONG g_stop = 0;
static BOOL    g_wsa = FALSE;
static char    g_machineId[80];
static char    g_host[128];
static char    g_user[128];
static char    g_os[64];
static WCHAR   g_qdir[600];

static BYTE   *g_pub = NULL;
static DWORD   g_pubLen = 0;

/* --------------------------------------------------------------------- */

static void ToUtf8(const WCHAR *w, char *out, int cch)
{
    out[0] = 0;
    if (!w || !w[0] || cch <= 0) return;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cch, NULL, NULL);
}

static void JsonEsc(char *dst, int cch, const char *src)
{
    int o = 0;
    if (!dst || cch <= 0) return;
    for (; src && *src && o + 8 < cch; src++) {
        unsigned char c = (unsigned char)*src;
        if (c == '"' || c == '\\') { dst[o++] = '\\'; dst[o++] = (char)c; }
        else if (c < 0x20) { dst[o++] = ' '; }
        else { dst[o++] = (char)c; }
    }
    dst[o] = 0;
}

/* --------------------------------------------------------------------- */
/* configuration / identity                                              */
/* --------------------------------------------------------------------- */

static void RepLoadCfg(void)
{
    KvDoc *d = KvLoad(g_cfgpath);

    g_rc.enable = 1;
    g_rc.crypto = 1;
    g_rc.port = REPORT_DEFAULT_PORT;
    g_rc.server[0] = 0;
    g_rc.group[0] = 0;
    if (!d) return;

    g_rc.enable = KvGetInt(d, L"report_enable", 1);
    g_rc.crypto = KvGetInt(d, L"report_crypto", 1);
    g_rc.port = KvGetInt(d, L"report_port", REPORT_DEFAULT_PORT);
    if (g_rc.port < 1024 || g_rc.port > 65535) g_rc.port = REPORT_DEFAULT_PORT;
    ToUtf8(KvGet(d, L"report_server", L""), g_rc.server, 64);
    ToUtf8(KvGet(d, L"report_group", L""), g_rc.group, 128);
    KvFree(d);
}

static void LoadIdentity(void)
{
    WCHAR w[256], cb2[512];
    DWORD cch, cb = sizeof(w), type = 0;
    HKEY hk;

    cch = 256;
    if (GetComputerNameW(w, &cch)) ToUtf8(w, g_host, 128);
    else lstrcpynA(g_host, "unknown", 128);

    g_user[0] = 0;
    {
        DWORD sess = ConsoleSession();
        LPWSTR name = NULL;
        DWORD bytes = 0;
        if (sess != 0xFFFFFFFF &&
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sess,
                                        WTSUserName, &name, &bytes) &&
            name && name[0]) {
            ToUtf8(name, g_user, 128);
            WTSFreeMemory(name);
        }
    }
    if (!g_user[0]) {
        cch = 256;
        if (GetUserNameW(w, &cch)) ToUtf8(w, g_user, 128);
        else lstrcpynA(g_user, "unknown", 128);
    }

    g_machineId[0] = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hk, L"MachineGuid", NULL, &type, (LPBYTE)cb2,
                             &cb) == ERROR_SUCCESS && type == REG_SZ) {
            ToUtf8((WCHAR *)cb2, g_machineId, 80);
        }
        RegCloseKey(hk);
    }
    if (!g_machineId[0]) lstrcpynA(g_machineId, g_host, 80);
}

typedef struct {
    ULONG dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
} MWG_OSVI;

static void LoadOs(void)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    LONG (WINAPI *fn)(MWG_OSVI *) = NULL;
    MWG_OSVI vi;

    if (nt) fn = (LONG (WINAPI *)(MWG_OSVI *))(void *)GetProcAddress(nt, "RtlGetVersion");
    if (fn) {
        ZeroMemory(&vi, sizeof(vi));
        vi.dwOSVersionInfoSize = sizeof(vi);
        if (fn(&vi) == 0) {
            sprintf(g_os, "%lu.%lu.%lu", (unsigned long)vi.dwMajorVersion,
                    (unsigned long)vi.dwMinorVersion, (unsigned long)vi.dwBuildNumber);
            return;
        }
    }
    lstrcpynA(g_os, "unknown", 64);
}

/* --------------------------------------------------------------------- */
/* disk queue                                                            */
/* --------------------------------------------------------------------- */

static void QueueInit(void)
{
    WCHAR base[600];

    wsprintfW(base, L"%s\\queue", g_root);
    CreateDirectoryW(base, NULL);
    wsprintfW(g_qdir, L"%s\\%s", base, g_role);
    CreateDirectoryW(g_qdir, NULL);
}

static int QueueCount(void)
{
    WIN32_FIND_DATAW fd;
    HANDLE h;
    WCHAR pattern[620];
    int n = 0;

    wsprintfW(pattern, L"%s\\*.json", g_qdir);
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) n++;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
}

static BOOL QueueOldest(WCHAR *nameOut, int cch)
{
    WIN32_FIND_DATAW fd;
    HANDLE h;
    WCHAR pattern[620], best[MAX_PATH];
    BOOL found = FALSE;

    wsprintfW(pattern, L"%s\\*.json", g_qdir);
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!found || lstrcmpiW(fd.cFileName, best) < 0) {
            lstrcpynW(best, fd.cFileName, MAX_PATH);
            found = TRUE;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (found && nameOut) lstrcpynW(nameOut, best, cch);
    return found;
}

static void QueueDrop(const WCHAR *name)
{
    WCHAR path[700];
    wsprintfW(path, L"%s\\%s", g_qdir, name);
    DeleteFileW(path);
}

static BOOL QueuePush(const char *json)
{
    SYSTEMTIME st;
    static LONG seq = 0;
    WCHAR path[700], tmp[700], name[MAX_PATH];
    HANDLE h;
    DWORD written = 0;

    if (QueueCount() >= EVQ_MAX) {
        WCHAR oldest[MAX_PATH];
        if (QueueOldest(oldest, MAX_PATH)) {
            QueueDrop(oldest);
            LogWrite(L"outbox full, oldest event discarded");
        }
    }
    GetLocalTime(&st);
    wsprintfW(name, L"%04d%02d%02d%02d%02d%02d-%06d.json",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
              (int)(InterlockedIncrement(&seq) & 0xFFFFF));
    wsprintfW(path, L"%s\\%s", g_qdir, name);
    wsprintfW(tmp, L"%s.tmp", path);

    h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        /* the spool directory can vanish underneath us (uninstall, cleanup,
           pending-delete from an earlier deployment) - rebuild and retry */
        WCHAR base[600];
        wsprintfW(base, L"%s\\queue", g_root);
        CreateDirectoryW(base, NULL);
        CreateDirectoryW(g_qdir, NULL);
        h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            LogWrite(L"outbox path unusable: %s", tmp);
            return FALSE;
        }
    }
    WriteFile(h, json, (DWORD)strlen(json), &written, NULL);
    CloseHandle(h);
    return MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING) != 0;
}

static BOOL QueueRead(const WCHAR *name, char *buf, int cch)
{
    WCHAR path[700];
    HANDLE h;
    DWORD got = 0;
    LARGE_INTEGER sz;

    buf[0] = 0;
    wsprintfW(path, L"%s\\%s", g_qdir, name);
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart >= cch || sz.QuadPart <= 0) {
        CloseHandle(h);
        return FALSE;
    }
    ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL);
    buf[got] = 0;
    CloseHandle(h);
    return TRUE;
}

/* --------------------------------------------------------------------- */
/* HTTP                                                                  */
/* --------------------------------------------------------------------- */

static int HttpRequest(const char *ip, const char *method, const char *path,
                       const char *ctype, const char *body,
                       char *resp, int respCch)
{
    SOCKET s;
    struct sockaddr_in to;
    DWORD tv = 4000;
    char head[600], buf[16384];
    int hl, n, total = 0, code = 0;
    char *p;

    if (resp && respCch) resp[0] = 0;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    ZeroMemory(&to, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons((u_short)g_rc.port);
    if (inet_pton(AF_INET, ip, &to.sin_addr) != 1) { closesocket(s); return -1; }
    if (connect(s, (struct sockaddr *)&to, sizeof(to)) != 0) { closesocket(s); return -1; }

    hl = snprintf(head, sizeof(head),
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: MythwareGuard/1.1\r\n"
        "Accept: text/plain\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        method, path, ip, g_rc.port, ctype ? ctype : "text/plain",
        body ? (int)strlen(body) : 0);
    if (send(s, head, hl, 0) <= 0) { closesocket(s); return -1; }
    if (body && body[0]) {
        if (send(s, body, (int)strlen(body), 0) <= 0) { closesocket(s); return -1; }
    }

    while (total < (int)sizeof(buf) - 1) {
        n = recv(s, buf + total, (int)sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = 0;
    closesocket(s);

    if (strncmp(buf, "HTTP/1.", 7) == 0) {
        p = strchr(buf, ' ');
        if (p) code = atoi(p + 1);
    }
    if (resp && respCch) {
        p = strstr(buf, "\r\n\r\n");
        if (p) lstrcpynA(resp, p + 4, respCch);
    }
    return code;
}

/* --------------------------------------------------------------------- */
/* collector public key                                                  */
/* --------------------------------------------------------------------- */

static void PubKeyPath(WCHAR *out, int cch)
{
    (void)cch;
    wsprintfW(out, L"%s\\keys\\collector.pub", g_root);
}

static BOOL PubKeyLoadCached(void)
{
    WCHAR path[600], dir[600];
    HANDLE h;
    DWORD got = 0;
    LARGE_INTEGER sz;
    BYTE *buf;

    if (g_pub) return TRUE;
    PubKeyPath(path, 600);
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 64 || sz.QuadPart > 4096) {
        CloseHandle(h);
        return FALSE;
    }
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)sz.QuadPart);
    if (!buf) { CloseHandle(h); return FALSE; }
    ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL);
    CloseHandle(h);
    (void)dir;
    g_pub = buf;
    g_pubLen = got;
    return TRUE;
}

static BOOL PubKeyFetch(const char *server)
{
    char resp[4096];
    DWORD len = 0;
    BYTE *raw;
    int code;
    WCHAR path[600], dir[600];
    HANDLE h;
    DWORD written = 0;

    code = HttpRequest(server, "GET", "/api/v1/pubkey", "text/plain", NULL,
                       resp, sizeof(resp));
    if (code != 200 || !resp[0]) return FALSE;

    raw = B64Decode(resp, &len);
    if (!raw || len < 64) { CryptoFree(raw); return FALSE; }
    g_pub = raw;
    g_pubLen = len;

    wsprintfW(dir, L"%s\\keys", g_root);
    CreateDirectoryW(dir, NULL);
    PubKeyPath(path, 600);
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        WriteFile(h, g_pub, g_pubLen, &written, NULL);
        CloseHandle(h);
    }
    LogWrite(L"collector public key fetched (%lu bytes)", (unsigned long)g_pubLen);
    return TRUE;
}

/* --------------------------------------------------------------------- */
/* discovery                                                             */
/* --------------------------------------------------------------------- */

static int SendToBroadcasts(SOCKET s, const char *msg, int len)
{
    ULONG size = 16384;
    IP_ADAPTER_ADDRESSES *addrs, *a;
    int sent = 0;

    addrs = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!addrs) return 0;
    if (GetAdaptersAddresses(AF_INET,
                             GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                             GAA_FLAG_SKIP_DNS_SERVER,
                             NULL, addrs, &size) == NO_ERROR) {
        for (a = addrs; a; a = a->Next) {
            IP_ADAPTER_UNICAST_ADDRESS *ua;
            if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (a->OperStatus != IfOperStatusUp) continue;
            for (ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                struct sockaddr_in sa, to;
                DWORD ipn, mask, bc;
                unsigned prefix;

                if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                sa = *(struct sockaddr_in *)ua->Address.lpSockaddr;
                prefix = ua->OnLinkPrefixLength;
                if (prefix == 0 || prefix > 32) continue;
                ipn = ntohl(sa.sin_addr.s_addr);
                mask = (prefix >= 32) ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - prefix));
                bc = ipn | ~mask;
                if (bc == ipn) continue;
                ZeroMemory(&to, sizeof(to));
                to.sin_family = AF_INET;
                to.sin_port = htons((u_short)g_rc.port);
                to.sin_addr.s_addr = htonl(bc);
                if (sendto(s, msg, len, 0, (struct sockaddr *)&to, sizeof(to)) > 0) sent++;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, addrs);
    return sent;
}

static int Discover(char *out, int cch)
{
    SOCKET s;
    int yes = 1;
    DWORD tv = 700;
    struct sockaddr_in to, from;
    char buf[64];
    int fl, n;

    out[0] = 0;
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char *)&yes, sizeof(yes));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    ZeroMemory(&to, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons((u_short)g_rc.port);
    to.sin_addr.s_addr = INADDR_BROADCAST;
    sendto(s, "MWGD?1", 6, 0, (struct sockaddr *)&to, sizeof(to));
    SendToBroadcasts(s, "MWGD?1", 6);

    fl = sizeof(from);
    n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
    if (n >= 6 && memcmp(buf, "MWGD!1", 6) == 0) {
        inet_ntop(AF_INET, &from.sin_addr, out, cch);
        closesocket(s);
        return 1;
    }
    closesocket(s);
    return 0;
}

/* --------------------------------------------------------------------- */
/* payload                                                               */
/* --------------------------------------------------------------------- */

static int BuildEventJson(char *out, int cch, const WCHAR *name, DWORD pid,
                          BOOL respawned, DWORD newPid)
{
    char ip[64], mac[64], host[160], user[160], group[160], id[160], nm[160];
    ULONG size = 16384;
    IP_ADAPTER_ADDRESSES *addrs;

    ip[0] = 0;
    mac[0] = 0;
    addrs = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (addrs) {
        int got = 0;
        if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST |
                                 GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                 NULL, addrs, &size) == NO_ERROR) {
            IP_ADAPTER_ADDRESSES *a;
            for (a = addrs; a && !got; a = a->Next) {
                IP_ADAPTER_UNICAST_ADDRESS *ua;
                if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
                if (a->OperStatus != IfOperStatusUp) continue;
                for (ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                    struct sockaddr_in *sa;
                    if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                    sa = (struct sockaddr_in *)ua->Address.lpSockaddr;
                    inet_ntop(AF_INET, &sa->sin_addr, ip, 64);
                    got = 1;
                    break;
                }
                if (a->PhysicalAddressLength == 6) {
                    sprintf(mac, "%02X-%02X-%02X-%02X-%02X-%02X",
                            a->PhysicalAddress[0], a->PhysicalAddress[1],
                            a->PhysicalAddress[2], a->PhysicalAddress[3],
                            a->PhysicalAddress[4], a->PhysicalAddress[5]);
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, addrs);
    }

    JsonEsc(host, sizeof(host), g_host);
    JsonEsc(user, sizeof(user), g_user);
    JsonEsc(group, sizeof(group), g_rc.group);
    JsonEsc(id, sizeof(id), g_machineId);
    ToUtf8(name, nm, sizeof(nm));

    return snprintf(out, cch,
        "{\"v\":1,\"ev\":\"exit\",\"ts\":%lld,\"id\":\"%s\",\"host\":\"%s\","
        "\"user\":\"%s\",\"group\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"os\":\"%s\","
        "\"name\":\"%s\",\"pid\":%lu,\"ok\":%d,\"newpid\":%lu}\n",
        (long long)(UnixMs() / 1000), id, host, user, group, ip, mac, g_os,
        nm, (unsigned long)pid, respawned ? 1 : 0, (unsigned long)newPid);
}

/* --------------------------------------------------------------------- */
/* worker                                                                */
/* --------------------------------------------------------------------- */

static void Deliver(ULONGLONG *backoff)
{
    WCHAR name[MAX_PATH];
    char body[4096], server[64], resp[512];
    int code;

    if (!QueueOldest(name, MAX_PATH)) {
        WaitForSingleObject(g_sem, 1500);
        return;
    }
    if (!QueueRead(name, body, sizeof(body))) {
        QueueDrop(name);
        return;
    }

    server[0] = 0;
    if (g_rc.server[0]) lstrcpynA(server, g_rc.server, 64);
    if (!server[0] && !Discover(server, 64)) {
        goto retry;
    }

    if (g_rc.crypto && !PubKeyLoadCached() && !PubKeyFetch(server)) {
        server[0] = 0;
        goto retry;
    }

    if (g_rc.crypto) {
        BYTE *enc = NULL;
        DWORD encLen = 0;
        char *b64;

        if (!RsaEncrypt(g_pub, g_pubLen, (BYTE *)body, (DWORD)strlen(body),
                        &enc, &encLen)) {
            LogWrite(L"rsa encrypt failed, dropping cached public key");
            CryptoFree(g_pub);
            g_pub = NULL;
            goto retry;
        }
        b64 = B64Encode(enc, encLen);
        CryptoFree(enc);
        if (!b64) goto retry;
        code = HttpRequest(server, "POST", "/api/v1/events", "text/plain",
                           b64, resp, sizeof(resp));
        CryptoFree(b64);
    } else {
        code = HttpRequest(server, "POST", "/api/v1/events", "application/json",
                           body, resp, sizeof(resp));
    }

    LogDebug(L"deliver %s -> http %d", name, code);
    if (code == 200) {
        QueueDrop(name);
        *backoff = BACKOFF_MIN;
        LogWrite(L"event delivered (queue drained by one)");
        return;
    }

    if (code == 415 || code == 400) {
        /* key mismatch - force a refetch next round */
        CryptoFree(g_pub);
        g_pub = NULL;
    }
    if (code <= 0) server[0] = 0;

retry:
    {
        DWORD wait = (DWORD)(*backoff > BACKOFF_MAX ? BACKOFF_MAX : *backoff);
        LogWrite(L"delivery postponed (backoff %lums)", (unsigned long)wait);
        Sleep(wait);
        *backoff = (*backoff * 2 > BACKOFF_MAX) ? BACKOFF_MAX : (*backoff * 2);
    }
}

static DWORD WINAPI RepThread(LPVOID param)
{
    ULONGLONG backoff = BACKOFF_MIN;
    (void)param;

    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        Deliver(&backoff);
    }
    return 0;
}

/* --------------------------------------------------------------------- */
/* public                                                                */
/* --------------------------------------------------------------------- */

void NotifyExit(const WCHAR *name, DWORD pid, BOOL respawned, DWORD newPid)
{
    char body[4096];

    LogWrite(L"EVENT %s exited pid=%lu respawn=%s newpid=%lu", name,
             (unsigned long)pid, respawned ? L"ok" : L"failed",
             (unsigned long)newPid);

    if (!g_rc.enable) return;
    if (BuildEventJson(body, sizeof(body), name, pid, respawned, newPid) <= 0)
        return;
    if (!QueuePush(body)) {
        LogWrite(L"outbox write failed, event lost");
        return;
    }
    LogDebug(L"outbox +%d bytes (%s)", (int)strlen(body), name);
    if (g_sem) ReleaseSemaphore(g_sem, 1, NULL);
}

void ReportStart(void)
{
    WSADATA wsa;

    RepLoadCfg();
    QueueInit();
    g_sem = CreateSemaphoreW(NULL, 0, 1024, NULL);

    if (!g_rc.enable) {
        LogWrite(L"event reporting disabled by config");
        return;
    }
    if (!g_wsa) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            LogWrite(L"report: WSAStartup failed");
            return;
        }
        g_wsa = TRUE;
    }
    LoadIdentity();
    LoadOs();
    CreateThread(NULL, 0, RepThread, NULL, 0, NULL);
    LogWrite(L"outbox armed -> HTTP %d, crypto=%s, pending=%d, group '%s'",
             g_rc.port, g_rc.crypto ? L"RSA-2048/OAEP" : L"off",
             QueueCount(), g_rc.group);
}
