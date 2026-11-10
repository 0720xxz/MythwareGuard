/* gui.c : collector window - forensic log of classroom-client kills. */

#include "core.h"
#include <shellapi.h>

#define IDC_LIST    1001
#define IDC_FILTER  1002
#define IDC_EXPORT  1003
#define IDC_CLEAR   1004
#define IDC_STATS   1005
#define IDT_REFRESH 1

static HWND g_hwnd = NULL;
static HWND g_list = NULL;
static HWND g_filter = NULL;
static HWND g_export = NULL;
static HWND g_clear = NULL;
static HFONT g_font = NULL;

static const WCHAR *kCols[] = {
    L"时间", L"电脑", L"用户", L"IP", L"分组",
    L"被退出的进程", L"PID", L"自动恢复"
};
static const int kWidths[] = { 150, 150, 110, 120, 80, 170, 70, 90 };
#define NCOLS ((int)(sizeof(kCols) / sizeof(kCols[0])))

/* --------------------------------------------------------------------- */

static BOOL ContainsI(const char *hay, const char *needle)
{
    size_t nh, nn, i, j;

    if (!hay || !needle || !needle[0]) return TRUE;
    nh = strlen(hay);
    nn = strlen(needle);
    if (nh < nn) return FALSE;
    for (i = 0; i + nn <= nh; i++) {
        for (j = 0; j < nn; j++) {
            char a = hay[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (j == nn) return TRUE;
    }
    return FALSE;
}

static void GetFilter(char *out, int cch)
{
    WCHAR w[256];
    out[0] = 0;
    if (!g_filter) return;
    GetWindowTextW(g_filter, w, 256);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cch, NULL, NULL);
}

static BOOL Matches(const Event *e, const char *key)
{
    if (!key[0]) return TRUE;
    return ContainsI(e->host, key) || ContainsI(e->user, key) ||
           ContainsI(e->ip, key) || ContainsI(e->name, key) ||
           ContainsI(e->group, key);
}

static void SetCellText(int row, int col, const WCHAR *text)
{
    ListView_SetItemText(g_list, row, col, (LPWSTR)text);
}

static const WCHAR *ResultText(int ok)
{
    return ok ? L"已恢复" : L"失败";
}

static void RebuildList(void)
{
    static Event snap[MAXEVENTS];
    char key[256];
    WCHAR ts[64], num[32];
    int n, i, row = 0, shown = 0, failed = 0;

    n = EventsSnapshot(snap, MAXEVENTS);
    GetFilter(key, sizeof(key));

    SendMessage(g_list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_list);

    for (i = n - 1; i >= 0; i--) {
        LVITEMW it;
        WCHAR host[256], user[256], ip[128], grp[128], name[192];

        if (!Matches(&snap[i], key)) continue;

        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = row;
        FormatTs(snap[i].ts, ts, 64);
        it.pszText = ts;
        ListView_InsertItem(g_list, &it);

        ToWide(snap[i].host, host, 256);
        ToWide(snap[i].user, user, 256);
        ToWide(snap[i].ip, ip, 128);
        ToWide(snap[i].group, grp, 128);
        ToWide(snap[i].name, name, 192);

        SetCellText(row, 1, host);
        SetCellText(row, 2, user);
        SetCellText(row, 3, ip);
        SetCellText(row, 4, grp);
        SetCellText(row, 5, name);
        wsprintfW(num, L"%lu", (unsigned long)snap[i].pid);
        SetCellText(row, 6, num);
        SetCellText(row, 7, ResultText(snap[i].ok));

        if (!snap[i].ok) failed++;
        row++;
        shown++;
    }

    SendMessage(g_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list, NULL, TRUE);

    {
        WCHAR title[320];
        wsprintfW(title,
                  L"MwReceiver  |  退出事件 %d 条  |  当前显示 %d 条  |  恢复失败 %d 条  |  监听 %d",
                  n, shown, failed, NetPort());
        SetWindowTextW(g_hwnd, title);
    }
    InterlockedExchange(&g_dirty, 0);
}

/* --------------------------------------------------------------------- */

static void DoExport(void)
{
    static Event snap[MAXEVENTS];
    char key[256];
    WCHAR path[600], msg[700];
    int n;

    n = EventsSnapshot(snap, MAXEVENTS);
    GetFilter(key, sizeof(key));

    if (ExportCsv(snap, n, key, path, 600)) {
        wsprintfW(msg, L"已导出当前视图到：\r\n%s\r\n\r\n是否打开所在目录？", path);
        if (MessageBoxW(g_hwnd, msg, L"MwReceiver",
                        MB_YESNO | MB_ICONINFORMATION) == IDYES) {
            WCHAR dir[600];
            WCHAR *p;
            lstrcpynW(dir, path, 600);
            p = wcsrchr(dir, L'\\');
            if (p) *p = 0;
            ShellExecuteW(NULL, L"open", dir, NULL, NULL, SW_SHOWNORMAL);
        }
    } else {
        MessageBoxW(g_hwnd, L"导出失败，请检查目录权限。", L"MwReceiver",
                    MB_OK | MB_ICONERROR);
    }
}

static void DoClear(void)
{
    WCHAR msg[256];

    if (MessageBoxW(g_hwnd,
                    L"确认清空全部历史记录？\r\n\r\n这会删除本地存储的所有事件文件，不可恢复。\r\n建议先导出 CSV 备份。",
                    L"MwReceiver",
                    MB_YESNO | MB_ICONWARNING) != IDYES) return;

    ClearHistory(msg, 256);
    MessageBoxW(g_hwnd, msg, L"MwReceiver", MB_OK | MB_ICONINFORMATION);
    RebuildList();
}

/* --------------------------------------------------------------------- */

static void CreateColumns(void)
{
    int i;
    LVCOLUMNW col;

    for (i = 0; i < NCOLS; i++) {
        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.iSubItem = i;
        col.pszText = (LPWSTR)kCols[i];
        col.cx = kWidths[i];
        ListView_InsertColumn(g_list, i, &col);
    }
    ListView_SetExtendedListViewStyle(g_list,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_font = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");

        g_filter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                   8, 8, 260, 26, hwnd, (HMENU)IDC_FILTER,
                                   GetModuleHandleW(NULL), NULL);
        if (g_font) SendMessage(g_filter, WM_SETFONT, (WPARAM)g_font, TRUE);

        g_export = CreateWindowExW(0, L"BUTTON", L"导出 CSV",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                   276, 8, 110, 26, hwnd, (HMENU)IDC_EXPORT,
                                   GetModuleHandleW(NULL), NULL);
        g_clear = CreateWindowExW(0, L"BUTTON", L"清空历史",
                                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  392, 8, 110, 26, hwnd, (HMENU)IDC_CLEAR,
                                  GetModuleHandleW(NULL), NULL);
        if (g_font) {
            SendMessage(g_export, WM_SETFONT, (WPARAM)g_font, TRUE);
            SendMessage(g_clear, WM_SETFONT, (WPARAM)g_font, TRUE);
        }

        g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT |
                                 LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                 0, 40, 100, 100, hwnd, (HMENU)IDC_LIST,
                                 GetModuleHandleW(NULL), NULL);
        CreateColumns();
        if (g_font) SendMessage(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);

        SetTimer(hwnd, IDT_REFRESH, 2000, NULL);
        return 0;

    case WM_SIZE:
        if (g_list) {
            MoveWindow(g_list, 0, 40, LOWORD(lp), HIWORD(lp) - 40 > 0 ? HIWORD(lp) - 40 : 0, TRUE);
        }
        return 0;

    case WM_TIMER:
        if (wp == IDT_REFRESH && InterlockedCompareExchange(&g_dirty, 0, 0))
            RebuildList();
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_EXPORT: DoExport(); return 0;
        case IDC_CLEAR:  DoClear();  return 0;
        case IDC_FILTER:
            if (HIWORD(wp) == EN_CHANGE) {
                InterlockedExchange(&g_dirty, 1);
                RebuildList();
            }
            return 0;
        }
        return 0;

    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == IDC_LIST && nh->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lp;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT)
                return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                WCHAR buf[64];
                ListView_GetItemText(g_list, (int)cd->nmcd.dwItemSpec, 7, buf, 64);
                if (lstrcmpW(buf, L"失败") == 0)
                    cd->clrText = RGB(190, 20, 20);
                return CDRF_DODEFAULT;
            }
        }
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hwnd, IDT_REFRESH);
        NetStop();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int show)
{
    WNDCLASSEXW wc;
    MSG msg;
    INITCOMMONCONTROLSEX icc;
    int port = 17800;
    int argc = 0;
    LPWSTR *argv;

    (void)hPrev;
    (void)cmdLine;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        int i;
        for (i = 1; i < argc; i++) {
            if (lstrcmpiW(argv[i], L"--port") == 0 && i + 1 < argc)
                port = _wtoi(argv[i + 1]);
        }
        LocalFree(argv);
    }
    if (port < 1024 || port > 65535) port = 17800;

    TableInit();
    RecvLogInit();
    RecvLog("MwReceiver %d 启动，端口 %d", 1000, port);
    HistoryLoad();

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"MwReceiverWnd";
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    if (!RegisterClassExW(&wc)) return 1;

    g_hwnd = CreateWindowExW(0, L"MwReceiverWnd",
                             L"MwReceiver  |  极域退出记录",
                             WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 1080, 620,
                             NULL, NULL, hInst, NULL);
    if (!g_hwnd) return 1;

    {
        HMENU menu = CreateMenu();
        HMENU file = CreatePopupMenu();
        AppendMenuW(file, MF_STRING, IDC_EXPORT, L"导出 CSV");
        AppendMenuW(file, MF_STRING, IDC_CLEAR, L"清空历史");
        AppendMenuW(file, MF_SEPARATOR, 0, NULL);
        AppendMenuW(file, MF_STRING, 1099, L"退出");
        AppendMenuW(menu, MF_POPUP, (UINT_PTR)file, L"文件");
        SetMenu(g_hwnd, menu);
    }

    if (!NetStart(port)) {
        MessageBoxW(g_hwnd, L"网络监听启动失败，请查看日志。",
                    L"MwReceiver", MB_OK | MB_ICONERROR);
    }

    ShowWindow(g_hwnd, show);
    UpdateWindow(g_hwnd);
    RebuildList();

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_F5) {
            RebuildList();
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
