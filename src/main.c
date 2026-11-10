/* main.c : entry point and command line dispatch (GUI subsystem). */

#include "common.h"
#include "guard.h"
#include "setup.h"
#include "win.h"
#include <shellapi.h>

static void ParseAndRun(void)
{
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    WCHAR role[32];
    WCHAR action[32];
    int i;

    role[0] = 0;
    action[0] = 0;

    if (argv) {
        for (i = 1; i < argc; i++) {
            if (WStrEqI(argv[i], L"--role") && i + 1 < argc) {
                WStrCpy(role, 32, argv[++i]);
            } else if (WStrEqI(argv[i], L"--install")) {
                WStrCpy(action, 32, L"install");
            } else if (WStrEqI(argv[i], L"--uninstall")) {
                WStrCpy(action, 32, L"uninstall");
            } else if (WStrEqI(argv[i], L"--status")) {
                WStrCpy(action, 32, L"status");
            }
        }
        LocalFree(argv);
    }

    if (role[0]) {
        if (WStrEqI(role, ROLE_REVIVE)) RunRevive();
        else RunGuard(role);
        ExitProcess(0);
    }
    if (WStrEqI(action, L"install")) { DoInstall(); ExitProcess(0); }
    if (WStrEqI(action, L"uninstall")) { DoUninstall(); ExitProcess(0); }
    if (WStrEqI(action, L"status")) { DoStatus(); ExitProcess(0); }

    GetOwnImage(g_self, PATHCH);
    if (!InitPaths()) return;

    if (TaskInstalled()) {
        DoStatus();
    } else if (MessageBoxW(NULL,
                           L"\x662f\x5426\x5b89\x88c5\x6781\x57df\x5b88\x62a4\xff1f\r\n\r\n"
                           L"\x5b89\x88c5\x540e\xff1aSYSTEM \x8ba1\x5212\x4efb\x52a1\x5e38\x9a7b\xff0c"
                           L"\x53cc\x8fdb\x7a0b\x4e92\x4fdd\xff0c\x6781\x57df\x5ba2\x6237\x7aef"
                           L"\x88ab\x7ed3\x675f\x540e\x81ea\x52a8\x91cd\x542f\x3002",
                           MWG_APPNAME,
                           MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND) == IDYES) {
        DoInstall();
    }
    ExitProcess(0);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int show)
{
    (void)hInst;
    (void)hPrev;
    (void)cmdLine;
    (void)show;
    ParseAndRun();
    return 0;
}
