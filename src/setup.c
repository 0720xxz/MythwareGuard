/* setup.c : deployment (scheduled task + run key) and removal. */

#include "setup.h"
#include "guard.h"
#include "win.h"
#include <shellapi.h>

#define TASK_NAME L"\\MythwareGuard\\Core"

static const WCHAR *kXmlHead =
L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
L"  <RegistrationInfo>\r\n"
L"    <Author>MythwareGuard</Author>\r\n"
L"    <Description>Keeps the classroom client resident.</Description>\r\n"
L"  </RegistrationInfo>\r\n"
L"  <Triggers>\r\n"
L"    <BootTrigger><Enabled>true</Enabled><Delay>PT20S</Delay></BootTrigger>\r\n"
L"    <TimeTrigger>\r\n"
L"      <StartBoundary>2020-01-01T00:00:00</StartBoundary>\r\n"
L"      <Enabled>true</Enabled>\r\n"
L"      <Repetition>\r\n"
L"        <Interval>PT1M</Interval>\r\n"
L"        <Duration>P3650D</Duration>\r\n"
L"        <StopAtDurationEnd>false</StopAtDurationEnd>\r\n"
L"      </Repetition>\r\n"
L"    </TimeTrigger>\r\n"
L"  </Triggers>\r\n"
L"  <Principals>\r\n"
L"    <Principal id=\"Author\">\r\n"
L"      <UserId>S-1-5-18</UserId>\r\n"
L"      <RunLevel>HighestAvailable</RunLevel>\r\n"
L"    </Principal>\r\n"
L"  </Principals>\r\n"
L"  <Settings>\r\n"
L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
L"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
L"    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\r\n"
L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
L"    <Enabled>true</Enabled>\r\n"
L"    <Hidden>true</Hidden>\r\n"
L"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n"
L"    <WakeToRun>false</WakeToRun>\r\n"
L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n"
L"    <Priority>4</Priority>\r\n"
L"    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>\r\n"
L"  </Settings>\r\n"
L"  <Actions Context=\"Author\">\r\n"
L"    <Exec>\r\n"
L"      <Command>%s</Command>\r\n"
L"      <Arguments>--role revive</Arguments>\r\n"
L"    </Exec>\r\n"
L"  </Actions>\r\n"
L"</Task>\r\n";

/* --------------------------------------------------------------------- */

void RelaunchElevated(const WCHAR *arg)
{
    HINSTANCE r;
    WCHAR args[64];

    WStrCpy(args, 64, (arg && arg[0]) ? arg : L"--install");
    r = ShellExecuteW(NULL, L"runas", g_self, args, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32) {
        MessageBoxW(NULL,
                    L"\x9700\x8981\x7ba1\x7406\x5458\x6743\x9650\x624d\x80fd\x5b8c\x6210"
                    L"\x8be5\x64cd\x4f5c\x3002",
                    MWG_APPNAME, MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    }
}

BOOL NeedElevation(void)
{
    return !IsElevated();
}

BOOL TaskInstalled(void)
{
    DWORD rc = 1;
    if (!RunHidden(L"schtasks.exe /query /tn \"" TASK_NAME L"\"", 20000, &rc))
        return FALSE;
    return rc == 0;
}

/* --------------------------------------------------------------------- */

static void EscapeXml(const WCHAR *in, WCHAR *out, DWORD cch)
{
    DWORD o = 0;
    while (*in && o + 8 < cch) {
        switch (*in) {
        case L'&':  WStrCat(out + o, cch - o, L"&amp;");  o += 5; break;
        case L'<':  WStrCat(out + o, cch - o, L"&lt;");   o += 4; break;
        case L'>':  WStrCat(out + o, cch - o, L"&gt;");   o += 4; break;
        case L'"':  WStrCat(out + o, cch - o, L"&quot;"); o += 6; break;
        default:    out[o++] = *in; out[o] = 0; break;
        }
        in++;
    }
    out[o] = 0;
}

static BOOL RegisterTask(const WCHAR *exe)
{
    WCHAR esc[PATHCH * 2], *xml, tmp[MAX_PATH];
    DWORD tmpLen;
    HANDLE h;
    WORD bom = 0xFEFF;
    DWORD rc = 1;
    BOOL ok;

    esc[0] = 0;
    EscapeXml(exe, esc, PATHCH * 2);

    xml = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 16384 * sizeof(WCHAR));
    if (!xml) return FALSE;
    WPrintf(xml, 16384, kXmlHead, esc);

    tmpLen = GetTempPathW(MAX_PATH, tmp);
    if (tmpLen == 0 || tmpLen >= MAX_PATH) {
        WStrCpy(tmp, MAX_PATH, L"C:\\Windows\\Temp\\");
    }
    WStrCat(tmp, MAX_PATH, L"mwguard_task.xml");

    h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, xml);
        return FALSE;
    }
    WriteFile(h, &bom, sizeof(bom), NULL, NULL);
    WriteFile(h, xml, (DWORD)(wcslen(xml) * sizeof(WCHAR)), NULL, NULL);
    CloseHandle(h);
    HeapFree(GetProcessHeap(), 0, xml);

    {
        WCHAR cmd[PATHCH * 3];
        WPrintf(cmd, PATHCH * 3,
                L"schtasks.exe /create /tn \"" TASK_NAME L"\" /xml \"%s\" /f", tmp);
        ok = RunHidden(cmd, 60000, &rc) && rc == 0;
    }
    DeleteFileW(tmp);
    LogWrite(L"register task: %s (rc=%lu)", ok ? L"ok" : L"failed",
             (unsigned long)rc);
    return ok;
}

static BOOL WriteRunKey(const WCHAR *exe)
{
    HKEY hk;
    WCHAR val[PATHCH * 2];
    LONG r;

    r = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL);
    if (r != ERROR_SUCCESS) return FALSE;
    WPrintf(val, PATHCH * 2, L"\"%s\" --role node", exe);
    r = RegSetValueExW(hk, L"MythwareGuardNode", 0, REG_SZ,
                       (const BYTE *)val,
                       (DWORD)((wcslen(val) + 1) * sizeof(WCHAR)));
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static void DeleteRunKey(void)
{
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueW(hk, L"MythwareGuardNode");
        RegCloseKey(hk);
    }
}

static void KillNames(void)
{
    static const WCHAR *names[3] = { EXE_WARDEN, EXE_SHADOW, EXE_NODE };
    int i, j;

    for (i = 0; i < 3; i++) {
        DWORD pids[8];
        int n = ProcsByName(names[i], pids, 8);
        for (j = 0; j < n; j++) {
            if (pids[j] == GetCurrentProcessId()) continue;
            if (KillPid(pids[j])) {
                LogWrite(L"stopped %s pid=%lu", names[i], (unsigned long)pids[j]);
            }
        }
    }
}

static BOOL DeployCopies(void)
{
    static const WCHAR *names[3] = { EXE_WARDEN, EXE_SHADOW, EXE_NODE };
    int i;
    BOOL ok = TRUE;

    for (i = 0; i < 3; i++) {
        WCHAR dst[PATHCH], bak[PATHCH];
        int attempt;
        BOOL copied = FALSE;

        WStrCpy(dst, PATHCH, g_bin);
        WStrCat(dst, PATHCH, L"\\");
        WStrCat(dst, PATHCH, names[i]);
        if (WStrEqI(dst, g_self)) continue;

        /* A running image cannot be overwritten, but it CAN be renamed.
           Rotating it aside first is the only reliable way to upgrade while
           the old guard is still alive (mutual supervision revives it within
           ~200 ms, so waiting for it to die never works). */
        WStrCpy(bak, PATHCH, dst);
        WStrCat(bak, PATHCH, L".old");
        DeleteFileW(bak);
        if (!MoveFileW(dst, bak)) {
            DWORD e = GetLastError();
            if (e != ERROR_FILE_NOT_FOUND) {
                LogWrite(L"deploy: cannot rotate %s (err=%lu)", dst, (unsigned long)e);
            }
        }
        for (attempt = 0; attempt < 4 && !copied; attempt++) {
            if (attempt) Sleep(400);
            copied = CopyFileW(g_self, dst, FALSE) != 0;
        }
        if (!copied) {
            LogWrite(L"deploy %s failed err=%lu", dst, (unsigned long)GetLastError());
            ok = FALSE;
        }
    }
    {
        WCHAR bak2[PATHCH];
        WStrCpy(bak2, PATHCH, g_mirror);
        WStrCat(bak2, PATHCH, L"\\bin.dat");
        if (!WStrEqI(bak2, g_self)) CopyFileW(g_self, bak2, FALSE);
    }
    return ok;
}

/* --------------------------------------------------------------------- */

static void GrantUserWrite(void)
{
    WCHAR cmd[PATHCH + 160];
    WPrintf(cmd, PATHCH + 160,
            L"icacls.exe \"%s\" /grant *S-1-5-32-545:(OI)(CI)M /T /C /Q", g_root);
    RunHidden(cmd, 30000, NULL);
}

int DoInstall(void)
{
    WCHAR msg[2048], cmd[PATHCH + 128], core[PATHCH];
    DWORD rc = 1;
    int fails = 0;

    GetOwnImage(g_self, PATHCH);
    if (!IsElevated()) {
        RelaunchElevated(L"--install");
        return 0;
    }
    WStrCpy(g_role, 32, L"install");
    InitPaths();
    LogOpen();
    LogWrite(L"install from %s", g_self);

    KillNames();
    Sleep(300);

    if (!DeployCopies()) fails++;
    if (GetFileAttributesW(g_cfgpath) == INVALID_FILE_ATTRIBUTES) WriteDefaultConfig(g_cfgpath);
    GrantUserWrite();

    WStrCpy(core, PATHCH, g_bin);
    WStrCat(core, PATHCH, L"\\" EXE_WARDEN);
    if (GetFileAttributesW(core) == INVALID_FILE_ATTRIBUTES) WStrCpy(core, PATHCH, g_self);

    if (!RegisterTask(core)) fails++;

    {
        WCHAR nodeExe[PATHCH];
        WStrCpy(nodeExe, PATHCH, g_bin);
        WStrCat(nodeExe, PATHCH, L"\\" EXE_NODE);
        if (!WriteRunKey(nodeExe)) fails++;
    }

    WPrintf(cmd, PATHCH + 128, L"schtasks.exe /run /tn \"" TASK_NAME L"\"");
    if (!RunHidden(cmd, 30000, &rc) || rc != 0) {
        LogWrite(L"task run rc=%lu, falling back to direct start", (unsigned long)rc);
        StartRole(ROLE_WARDEN, EXE_WARDEN);
    }

    WPrintf(msg, 2048,
            L"\x6781\x57df\x5b88\x62a4\x5df2\x5b89\x88c5\x3002\r\n\r\n"
            L"\x5b88\x62a4\x76ee\x5f55\xff1a%s\r\n"
            L"\x65e5\x5fd7\xff1a%s\\logs\\warden.log\r\n"
            L"\x8ba1\x5212\x4efb\x52a1\xff1aMythwareGuard\\Core (SYSTEM, \x6bcf\x5206\x949f\x81ea\x68c0)\r\n"
            L"\x9a71\x52a8\x5c42\x7ea7\xff1awarden + shadow \x53cc\x8fdb\x7a0b\x4e92\x4fdd + node \x7528\x6237\x6001\r\n"
            L"\x4e0a\x62a5\xff1a\x9ed8\x8ba4\x5f00\x542f\xff0c\x63a5\x6536\x7aef UDP/TCP 17800\r\n\r\n"
            L"\x5378\x8f7d\xff1a\x91cd\x65b0\x8fd0\x884c\x672c\x7a0b\x5e8f\x5e76\x9009\x62e9\x5378\x8f7d\x3002",
            g_root, g_root);
    if (fails) {
        WStrCat(msg, 2048, L"\r\n\r\n(\x90e8\x5206\x6b65\x9aa4\x5931\x8d25\xff0c\x8be6\x89c1\x65e5\x5fd7)");
    }
    MessageBoxW(NULL, msg, MWG_APPNAME,
                MB_OK | (fails ? MB_ICONWARNING : MB_ICONINFORMATION) | MB_SETFOREGROUND);
    return 0;
}

int DoUninstall(void)
{
    WCHAR cmd[PATHCH + 128];

    GetOwnImage(g_self, PATHCH);
    if (!IsElevated()) {
        RelaunchElevated(L"--uninstall");
        return 0;
    }
    WStrCpy(g_role, 32, L"install");
    InitPaths();
    LogOpen();
    LogWrite(L"uninstall begin");

    WPrintf(cmd, PATHCH + 128, L"schtasks.exe /end /tn \"" TASK_NAME L"\"");
    RunHidden(cmd, 20000, NULL);
    WPrintf(cmd, PATHCH + 128, L"schtasks.exe /delete /tn \"" TASK_NAME L"\" /f");
    RunHidden(cmd, 20000, NULL);
    DeleteRunKey();
    KillNames();
    Sleep(500);
    KillNames();

    if (MessageBoxW(NULL,
                    L"\x662f\x5426\x540c\x65f6\x5220\x9664\x914d\x7f6e\x76ee\x5f55\x548c\x65e5\x5fd7\xff1f",
                    MWG_APPNAME,
                    MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND) == IDYES) {
        WPrintf(cmd, PATHCH + 128, L"cmd.exe /c rmdir /s /q \"%s\"", g_root);
        RunHidden(cmd, 30000, NULL);
    }
    MessageBoxW(NULL,
                L"\x5df2\x5378\x8f7d\xff0c\x6781\x57df\x5ba2\x6237\x7aef\x4e0d\x518d\x53d7\x5b88\x62a4\x3002",
                MWG_APPNAME, MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    return 0;
}

int DoStatus(void)
{
    WCHAR msg[2048];
    WCHAR roleState[256];
    DWORD pid = 0;
    ULONGLONG ts = 0;
    int i;

    WStrCpy(g_role, 32, L"install");
    InitPaths();
    LoadConfig();

    msg[0] = 0;
    roleState[0] = 0;
    if (StateRead(ROLE_WARDEN, &pid, &ts) && pid && ProcExists(pid)) {
        WPrintf(roleState, 256, L"warden: 运行中 (pid %lu)\r\n", (unsigned long)pid);
    } else {
        WPrintf(roleState, 256, L"warden: 未运行\r\n");
    }
    WStrCat(msg, 2048, roleState);
    if (StateRead(ROLE_SHADOW, &pid, &ts) && pid && ProcExists(pid)) {
        WPrintf(roleState, 256, L"shadow: 运行中 (pid %lu)\r\n", (unsigned long)pid);
    } else {
        WPrintf(roleState, 256, L"shadow: 未运行\r\n");
    }
    WStrCat(msg, 2048, roleState);
    WStrCat(msg, 2048, TaskInstalled() ? L"计划任务: 已注册\r\n" : L"计划任务: 未注册\r\n");
    WStrCat(msg, 2048, L"\r\n目标进程:\r\n");
    for (i = 0; i < g_cfg.count; i++) {
        DWORD pids[4];
        int n = ProcsByName(g_cfg.targets[i].name, pids, 4);
        WPrintf(roleState, 256, L"  %s : %s\r\n", g_cfg.targets[i].name,
                n > 0 ? L"运行中" : L"未运行");
        WStrCat(msg, 2048, roleState);
    }
    MessageBoxW(NULL, msg, MWG_APPNAME, MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    return 0;
}
