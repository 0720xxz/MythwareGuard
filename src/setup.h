/* setup.h : install / uninstall / status entry points. */
#ifndef MWG_SETUP_H
#define MWG_SETUP_H

#include "common.h"

int  DoInstall(void);
int  DoUninstall(void);
int  DoStatus(void);
BOOL TaskInstalled(void);
BOOL NeedElevation(void);
void RelaunchElevated(const WCHAR *arg);

#endif /* MWG_SETUP_H */
