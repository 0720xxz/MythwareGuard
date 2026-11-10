/* report.h : LAN telemetry - discovery + periodic status push. */
#ifndef MWG_REPORT_H
#define MWG_REPORT_H

#include "common.h"

#define REPORT_DEFAULT_PORT 17800

void ReportStart(void);
/* Called when a supervised client process disappears. */
void NotifyExit(const WCHAR *name, DWORD pid, BOOL respawned, DWORD newPid);

#endif /* MWG_REPORT_H */
