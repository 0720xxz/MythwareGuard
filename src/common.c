/* common.c : paths, string helpers, key/value documents, logging. */

#include "common.h"
#include <stdarg.h>

WCHAR g_root[PATHCH];
WCHAR g_bin[PATHCH];
WCHAR g_state[PATHCH];
WCHAR g_logdir[PATHCH];
WCHAR g_mirror[PATHCH];
WCHAR g_cfgpath[PATHCH];
WCHAR g_self[PATHCH];
WCHAR g_role[32] = L"init";

/* ===================================================================== */
/* strings                                                               */
/* ===================================================================== */

BOOL WCharIsSpace(WCHAR c)
{
    return (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n');
}

int WPrintf(WCHAR *buf, size_t cch, const WCHAR *fmt, ...)
{
    va_list ap;
    int r;
    if (!buf || cch == 0) return 0;
    va_start(ap, fmt);
    r = vswprintf(buf, cch, fmt, ap);
    va_end(ap);
    if (r < 0) { buf[0] = 0; return 0; }
    return r;
}

WCHAR *WStrCpy(WCHAR *dst, size_t cch, const WCHAR *src)
{
    size_t i = 0;
    if (!dst || cch == 0) return dst;
    if (src) {
        while (src[i] && i + 1 < cch) { dst[i] = src[i]; i++; }
    }
    dst[i] = 0;
    return dst;
}

WCHAR *WStrCat(WCHAR *dst, size_t cch, const WCHAR *src)
{
    size_t n = wcslen(dst);
    if (n < cch) WStrCpy(dst + n, cch - n, src);
    return dst;
}

BOOL WStrEqI(const WCHAR *a, const WCHAR *b)
{
    if (!a || !b) return a == b;
    return CompareStringOrdinal(a, -1, b, -1, TRUE) == CSTR_EQUAL;
}

BOOL WStrStartsI(const WCHAR *s, const WCHAR *prefix)
{
    size_t n;
    if (!s || !prefix) return FALSE;
    n = wcslen(prefix);
    if (wcslen(s) < n) return FALSE;
    return CompareStringOrdinal(s, (int)n, prefix, (int)n, TRUE) == CSTR_EQUAL;
}

void WStrTrim(WCHAR *s)
{
    WCHAR *p = s;
    size_t n;
    if (!s) return;
    while (*p && WCharIsSpace(*p)) p++;
    if (p != s) memmove(s, p, (wcslen(p) + 1) * sizeof(WCHAR));
    n = wcslen(s);
    while (n > 0 && WCharIsSpace(s[n - 1])) s[--n] = 0;
}

/* ===================================================================== */
/* time                                                                  */
/* ===================================================================== */

ULONGLONG NowTick(void)
{
    return (ULONGLONG)GetTickCount64();
}

ULONGLONG UnixMs(void)
{
    FILETIME ft;
    ULARGE_INTEGER li;
    GetSystemTimeAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    /* 100ns since 1601 -> ms since 1970 */
    return (li.QuadPart - 116444736000000000ULL) / 10000ULL;
}

/* ===================================================================== */
/* paths                                                                 */
/* ===================================================================== */

BOOL EnsureDir(const WCHAR *path)
{
    DWORD a;
    if (!path || !path[0]) return FALSE;
    a = GetFileAttributesW(path);
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) return TRUE;
    if (CreateDirectoryW(path, NULL)) return TRUE;
    /* parents may be missing - walk up */
    {
        WCHAR tmp[PATHCH];
        WCHAR *p;
        WStrCpy(tmp, PATHCH, path);
        p = wcsrchr(tmp, L'\\');
        if (p && p != tmp) {
            *p = 0;
            EnsureDir(tmp);
        }
        return CreateDirectoryW(path, NULL) != 0;
    }
}

BOOL InitPaths(void)
{
    WCHAR base[PATHCH];
    DWORD n = GetEnvironmentVariableW(L"ProgramData", base, PATHCH);
    if (n == 0 || n >= PATHCH) {
        WStrCpy(base, PATHCH, L"C:\\ProgramData");
    }
    WStrCpy(g_root, PATHCH, base);
    WStrCat(g_root, PATHCH, L"\\MythwareGuard");
    WStrCpy(g_bin, PATHCH, g_root);      WStrCat(g_bin, PATHCH, L"\\bin");
    WStrCpy(g_state, PATHCH, g_root);    WStrCat(g_state, PATHCH, L"\\state");
    WStrCpy(g_logdir, PATHCH, g_root);   WStrCat(g_logdir, PATHCH, L"\\logs");
    WStrCpy(g_mirror, PATHCH, g_root);   WStrCat(g_mirror, PATHCH, L"\\mirror");
    WStrCpy(g_cfgpath, PATHCH, g_root); WStrCat(g_cfgpath, PATHCH, L"\\config.ini");

    if (!EnsureDir(g_root)) return FALSE;
    EnsureDir(g_bin);
    EnsureDir(g_state);
    EnsureDir(g_logdir);
    EnsureDir(g_mirror);
    return TRUE;
}

/* ===================================================================== */
/* key/value documents (UTF-8 on disk, UTF-16 in memory)                 */
/* ===================================================================== */

static WCHAR *ReadTextFile(const WCHAR *path)
{
    HANDLE h;
    LARGE_INTEGER size;
    char *raw;
    DWORD got = 0, i;
    WCHAR *out;
    int cch;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > (4 << 20)) {
        CloseHandle(h);
        return NULL;
    }
    raw = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)size.QuadPart + 1);
    if (!raw) { CloseHandle(h); return NULL; }
    if (!ReadFile(h, raw, (DWORD)size.QuadPart, &got, NULL)) got = 0;
    CloseHandle(h);
    raw[got] = 0;

    i = 0;
    if (got >= 3 && (unsigned char)raw[0] == 0xEF &&
        (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF) {
        i = 3;
    }
    cch = MultiByteToWideChar(CP_UTF8, 0, raw + i, (int)(got - i), NULL, 0);
    out = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                             ((SIZE_T)cch + 2) * sizeof(WCHAR));
    if (out && cch > 0) {
        MultiByteToWideChar(CP_UTF8, 0, raw + i, (int)(got - i), out, cch);
    }
    HeapFree(GetProcessHeap(), 0, raw);
    return out;
}

BOOL WriteTextFile(const WCHAR *path, const WCHAR *text)
{
    HANDLE h;
    BOOL ok;
    int bytes;
    char *utf8;

    if (!text || !text[0]) return FALSE;   /* never truncate a file to 0 bytes */
    bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (bytes <= 1) return FALSE;
    utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)bytes);
    if (!utf8) return FALSE;
    WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, bytes, NULL, NULL);

    h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, utf8);
        return FALSE;
    }
    ok = WriteFile(h, utf8, (DWORD)(bytes - 1), NULL, NULL);
    CloseHandle(h);
    HeapFree(GetProcessHeap(), 0, utf8);
    return ok;
}

KvDoc *KvLoad(const WCHAR *path)
{
    KvDoc *doc = (KvDoc *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KvDoc));
    WCHAR *text, *line, *next, *eq, *k, *v;
    if (!doc) return NULL;
    text = path ? ReadTextFile(path) : NULL;
    if (!text) return doc;  /* empty document */

    line = text;
    while (line && *line) {
        next = wcschr(line, L'\n');
        if (next) *next = 0;
        WStrTrim(line);
        if (*line && *line != L'#' && *line != L';') {
            eq = wcschr(line, L'=');
            if (eq) {
                *eq = 0;
                k = line;
                v = eq + 1;
                WStrTrim(k);
                WStrTrim(v);
                if (!KvSet(doc, k, v)) break;
            }
        }
        line = next ? next + 1 : NULL;
    }
    HeapFree(GetProcessHeap(), 0, text);
    return doc;
}

void KvFree(KvDoc *doc)
{
    if (!doc) return;
    if (doc->items) HeapFree(GetProcessHeap(), 0, doc->items);
    HeapFree(GetProcessHeap(), 0, doc);
}

static KvItem *KvFind(KvDoc *doc, const WCHAR *key)
{
    int i;
    if (!doc) return NULL;
    for (i = 0; i < doc->count; i++) {
        if (WStrEqI(doc->items[i].key, key)) return &doc->items[i];
    }
    return NULL;
}

const WCHAR *KvGet(KvDoc *doc, const WCHAR *key, const WCHAR *def)
{
    KvItem *it = KvFind(doc, key);
    return it ? it->val : def;
}

int KvGetInt(KvDoc *doc, const WCHAR *key, int def)
{
    const WCHAR *v = KvGet(doc, key, NULL);
    if (!v || !*v) return def;
    return _wtoi(v);
}

BOOL KvSet(KvDoc *doc, const WCHAR *key, const WCHAR *val)
{
    KvItem *it;
    if (!doc) return FALSE;
    it = KvFind(doc, key);
    if (it) {
        WStrCpy(it->val, PATHCH, val ? val : L"");
        return TRUE;
    }
    if (doc->count >= doc->cap) {
        int ncap = doc->cap ? doc->cap * 2 : 16;
        KvItem *ni;
        /* HeapReAlloc(NULL) does not behave like HeapAlloc here - it fails,
           which silently left every KvDoc at count==0 and made KvSave write
           nothing at all. Allocate the first block explicitly. */
        if (doc->items) {
            ni = (KvItem *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                       doc->items, (SIZE_T)ncap * sizeof(KvItem));
        } else {
            ni = (KvItem *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                     (SIZE_T)ncap * sizeof(KvItem));
        }
        if (!ni) return FALSE;
        doc->items = ni;
        doc->cap = ncap;
    }
    it = &doc->items[doc->count++];
    WStrCpy(it->key, 128, key);
    WStrCpy(it->val, PATHCH, val ? val : L"");
    return TRUE;
}

BOOL KvSave(KvDoc *doc, const WCHAR *path)
{
    WCHAR *buf;
    size_t need, used = 0;
    int i;
    BOOL ok;

    if (!doc || doc->count <= 0) return FALSE;
    need = ((size_t)doc->count * (128 + PATHCH + 4)) + 16;
    buf = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need * sizeof(WCHAR));
    if (!buf) return FALSE;
    for (i = 0; i < doc->count; i++) {
        size_t l1 = wcslen(doc->items[i].key);
        size_t l2 = wcslen(doc->items[i].val);
        if (used + l1 + l2 + 4 >= need) break;
        memcpy(buf + used, doc->items[i].key, l1 * sizeof(WCHAR));
        used += l1;
        buf[used++] = L'=';
        memcpy(buf + used, doc->items[i].val, l2 * sizeof(WCHAR));
        used += l2;
        buf[used++] = L'\r';
        buf[used++] = L'\n';
    }
    buf[used] = 0;
    ok = WriteTextFile(path, buf);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

int KvCountPrefix(KvDoc *doc, const WCHAR *prefix)
{
    int i, n = 0;
    if (!doc) return 0;
    for (i = 0; i < doc->count; i++) {
        if (WStrStartsI(doc->items[i].key, prefix)) n++;
    }
    return n;
}

BOOL KvGetPrefixAt(KvDoc *doc, const WCHAR *prefix, int idx,
                   WCHAR *keyout, size_t kcch, WCHAR *valout, size_t vcch)
{
    int i, n = 0;
    if (!doc) return FALSE;
    for (i = 0; i < doc->count; i++) {
        if (!WStrStartsI(doc->items[i].key, prefix)) continue;
        if (n == idx) {
            WStrCpy(keyout, kcch, doc->items[i].key);
            WStrCpy(valout, vcch, doc->items[i].val);
            return TRUE;
        }
        n++;
    }
    return FALSE;
}

/* ===================================================================== */
/* logging                                                               */
/* ===================================================================== */

static HANDLE           g_logh = INVALID_HANDLE_VALUE;
static WCHAR            g_logpath[PATHCH];
static CRITICAL_SECTION g_logcs;
static BOOL             g_logcsReady = FALSE;
static DWORD            g_logBytes = 0;

static void LogWriteBom(void)
{
    LARGE_INTEGER sz;
    const char bom[3] = { (char)0xEF, (char)0xBB, (char)0xBF };
    DWORD written = 0;

    sz.QuadPart = 0;
    if (g_logh == INVALID_HANDLE_VALUE) return;
    if (GetFileSizeEx(g_logh, &sz) && sz.QuadPart == 0) {
        WriteFile(g_logh, bom, 3, &written, NULL);
    }
    g_logBytes = (sz.QuadPart > 0 && sz.QuadPart < 0x7FFFFFFF) ? (DWORD)sz.QuadPart : 0;
}

static void LogReopen(void)
{
    g_logh = CreateFileW(g_logpath, FILE_APPEND_DATA,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    g_logBytes = 0;
    LogWriteBom();
}

static void LogRotate(void)
{
    WCHAR old[PATHCH];

    if (g_logh != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logh);
        g_logh = INVALID_HANDLE_VALUE;
    }
    WStrCpy(old, PATHCH, g_logpath);
    WStrCat(old, PATHCH, L".1");
    DeleteFileW(old);
    MoveFileW(g_logpath, old);
    LogReopen();
}

void LogOpen(void)
{
    WCHAR name[64];

    if (!g_logcsReady) {
        InitializeCriticalSection(&g_logcs);
        g_logcsReady = TRUE;
    }
    WPrintf(name, 64, L"\\%s.log", g_role);
    WStrCpy(g_logpath, PATHCH, g_logdir);
    WStrCat(g_logpath, PATHCH, name);

    EnterCriticalSection(&g_logcs);
    if (g_logh == INVALID_HANDLE_VALUE) LogReopen();
    if (g_logh != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz;
        if (GetFileSizeEx(g_logh, &sz) && sz.QuadPart > (2 << 20)) LogRotate();
    }
    LeaveCriticalSection(&g_logcs);
}

void LogWrite(const WCHAR *fmt, ...)
{
    SYSTEMTIME st;
    WCHAR line[2048];
    WCHAR msg[1536];
    va_list ap;
    int m, bytes;
    char *u8;
    DWORD written = 0;

    if (!g_logcsReady) return;
    va_start(ap, fmt);
    m = vswprintf(msg, 1536, fmt, ap);
    va_end(ap);
    if (m < 0) msg[0] = 0;

    GetLocalTime(&st);
    WPrintf(line, 2048, L"%04d-%02d-%02d %02d:%02d:%02d.%03d [%s] %s\r\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            st.wMilliseconds, g_role, msg);

    OutputDebugStringW(line);

    bytes = WideCharToMultiByte(CP_UTF8, 0, line, -1, NULL, 0, NULL, NULL);
    if (bytes <= 1) return;
    u8 = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)bytes);
    if (!u8) return;
    WideCharToMultiByte(CP_UTF8, 0, line, -1, u8, bytes, NULL, NULL);

    EnterCriticalSection(&g_logcs);
    if (g_logh != INVALID_HANDLE_VALUE) {
        WriteFile(g_logh, u8, (DWORD)(bytes - 1), &written, NULL);
        g_logBytes += written;
        if (g_logBytes > (2u << 20)) LogRotate();
    }
    LeaveCriticalSection(&g_logcs);
    HeapFree(GetProcessHeap(), 0, u8);
}

void LogClose(void)
{
    if (!g_logcsReady) return;
    EnterCriticalSection(&g_logcs);
    if (g_logh != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logh);
        g_logh = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_logcs);
}
