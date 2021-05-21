#pragma once
#include <windows.h>
#include "Server.h"

#define SVCNAME TEXT("Denisovich Anti-Virus")
#define SVC_ERROR                        ((DWORD)0xC0020001L)

class ServiceManager
{
public:
	static void process(int argc, TCHAR* argv[]);
	static void install();
	static void uninstall();
	static void serviceMain();
	static void startService();
	static void init();
	static void reportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
	static void SvcReportEvent(LPTSTR szFunction);
	static void WINAPI svcCtrlHandler(DWORD dwCtrl);
	static void createRegistryRecord();
	static void setWorkingDirectory();
	static void deleteRegistryRecord();
	static void WINAPI DoUpdateSvcDacl();
private:
	static SERVICE_STATUS gSvcStatus;
	static SERVICE_STATUS_HANDLE gSvcStatusHandle;
	static Server server;
	static TCHAR WorkingDirectory[MAX_PATH];
	static void seBackupPrivilege();
};
