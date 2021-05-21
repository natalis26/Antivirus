#include "ServiceManager.h"
#include <iostream>
#include <strsafe.h>
#include <filesystem>
#include <WtsApi32.h>
#include <userenv.h>
#include "Scanner.h"
#include <aclapi.h>
#include <tchar.h>

#pragma comment(lib,"wtsapi32.lib")
#pragma comment(lib,"userenv.lib")
#pragma comment(lib, "advapi32.lib")

#define TOTAL_BYTES_READ 1024
#define OFFSET_BYTES 1024

void ServiceManager::process(int argc, TCHAR* argv[])
{
	if (lstrcmp(argv[1], TEXT("install")) == 0)
	{
		install();
	}
	if (lstrcmp(argv[1], TEXT("uninstall")) == 0)
	{
		uninstall();
		return;
	}
	DoUpdateSvcDacl();
	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{(TCHAR*)SVCNAME,(LPSERVICE_MAIN_FUNCTION)ServiceManager::serviceMain},
		{NULL,NULL}
	};
	startService();
	if (!StartServiceCtrlDispatcher(DispatchTable))
	{
		SvcReportEvent(TEXT("StartServiceCtrlDispatcher"));
	}
}

void ServiceManager::install()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	TCHAR szPath[MAX_PATH];
	if (!GetModuleFileName(NULL, szPath, MAX_PATH))
	{
		printf("Cannot install service (%d)\n", GetLastError());
		return;
	}
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	schService = CreateService(schSCManager, SVCNAME, SVCNAME,
		SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
	if (schService == NULL)
	{
		printf("CreateService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}
	else printf("Service installed successfully\n");

	createRegistryRecord();

	
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

void ServiceManager::uninstall()
{
	DWORD dwBytesNeeded;
	SERVICE_STATUS_PROCESS ssp;

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		SVCNAME,            // name of service 
		SERVICE_ALL_ACCESS |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}

	DeleteFile(L"Scanners.lsd");
	DeleteFile(L"Monitors.lsd");
	DeleteFile(L"Threats.lsd");
	

	DeleteService(schService);
	deleteRegistryRecord();

}

void ServiceManager::serviceMain()
{
	gSvcStatusHandle = RegisterServiceCtrlHandler(SVCNAME, (LPHANDLER_FUNCTION)ServiceManager::svcCtrlHandler);
	if (!gSvcStatusHandle)
	{
		SvcReportEvent(TEXT("RegisterServiceCtrlHandler"));
		return;
	}
	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	gSvcStatus.dwServiceSpecificExitCode = 0;
	SetServiceStatus(gSvcStatusHandle, &(gSvcStatus));
	reportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
	init();
}

void ServiceManager::startService()
{
	SERVICE_STATUS_PROCESS ssStatus;
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	schService = OpenService(schSCManager, SVCNAME, SERVICE_ALL_ACCESS);


	StartServiceA(schService, NULL, NULL);

	CloseServiceHandle(schSCManager);
	CloseServiceHandle(schService);
}

void ServiceManager::init()
{
	//Sleep(20000);
	setWorkingDirectory();
	reportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

	seBackupPrivilege();
	// TO_DO Perform work
	server.startUp();
}

void ServiceManager::reportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;
	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		gSvcStatus.dwControlsAccepted = 0;
	else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN;
	if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
		gSvcStatus.dwCheckPoint = 0;
	else gSvcStatus.dwCheckPoint = dwCheckPoint++;
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

void ServiceManager::SvcReportEvent(LPTSTR szFunction)
{
	HANDLE hEventSource;
	LPCTSTR lpszStrings[2];
	TCHAR buffer[80];
	hEventSource = RegisterEventSource(NULL, SVCNAME);
	if (NULL != hEventSource)
	{
		StringCchPrintf(buffer, 80, TEXT("%s failed with %d"), szFunction, GetLastError());
		lpszStrings[0] = SVCNAME;
		lpszStrings[1] = buffer;
		ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, SVC_ERROR, NULL, 2, 0, lpszStrings, NULL);
		DeregisterEventSource(hEventSource);
	}
}


void WINAPI ServiceManager::svcCtrlHandler(DWORD dwCtrl)
{
	switch (dwCtrl)
	{ 
	case SERVICE_CONTROL_SHUTDOWN:
		server.shutDown();
		break;
	default:
		break;
	}
}

void ServiceManager::createRegistryRecord()
{
	TCHAR buffer[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, buffer);
	DWORD dwDisposition; 
	HKEY  hKey;
	DWORD Ret;
	Ret =
		RegCreateKeyEx(
			HKEY_LOCAL_MACHINE,
			TEXT("SOFTWARE\\Denisovich Anti-Virus"),
			0,
			NULL,
			REG_OPTION_NON_VOLATILE,
			KEY_ALL_ACCESS | KEY_WOW64_64KEY,
			NULL,
			&hKey,
			&dwDisposition);

	if (Ret != ERROR_SUCCESS)
	{
		printf("Error opening or creating new key\n");
		return;
	}

	RegSetValueEx (hKey,
		TEXT("Working Directory"),
		0,
		REG_SZ,
		(LPBYTE)(buffer),
		((((DWORD)lstrlen(buffer) + 1)) * sizeof(TCHAR)));

	RegCloseKey(hKey);

}



void ServiceManager::setWorkingDirectory()
{
	DWORD len = TOTAL_BYTES_READ;
	DWORD readDataLen = len;

	DWORD Ret;
	HKEY hKey;
	
	Ret = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Denisovich Anti-Virus"),
		0,
		KEY_READ | KEY_WOW64_64KEY,
		&hKey
	);

	Ret = RegQueryValueEx(
		hKey,
		TEXT("Working Directory"),
		NULL,
		NULL,
		(BYTE*)WorkingDirectory,
		&readDataLen
	);
	if (Ret != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return;
	}
	RegCloseKey(hKey);
	
	_tcscat(WorkingDirectory, TEXT("\\"));
	SetCurrentDirectory(WorkingDirectory);

	TCHAR buffer[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, buffer);
}

void ServiceManager::deleteRegistryRecord()
{
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Denisovich Anti-Virus"),
		0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		//RegDeleteKey(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Denisovich Anti-Virus"));

		RegDeleteTree(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Denisovich Anti-Virus"));
	}
}


void WINAPI ServiceManager::DoUpdateSvcDacl()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	EXPLICIT_ACCESS      ea;
	SECURITY_DESCRIPTOR  sd;
	PSECURITY_DESCRIPTOR psd = NULL;
	PACL                 pacl = NULL;
	PACL                 pNewAcl = NULL;
	BOOL                 bDaclPresent = FALSE;
	BOOL                 bDaclDefaulted = FALSE;
	DWORD                dwError = 0;
	DWORD                dwSize = 0;
	DWORD                dwBytesNeeded = 0;
	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the service

	schService = OpenService(
		schSCManager,              // SCManager database 
		SVCNAME,                 // name of service 
		READ_CONTROL | WRITE_DAC); // access

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}

	// Get the current security descriptor.

	if (!QueryServiceObjectSecurity(schService,
		DACL_SECURITY_INFORMATION,
		&psd,           // using NULL does not work on all versions
		0,
		&dwBytesNeeded))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			dwSize = dwBytesNeeded;
			psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY, dwSize);
			if (psd == NULL)
			{
				// Note: HeapAlloc does not support GetLastError.
				printf("HeapAlloc failed\n");
				goto dacl_cleanup;
			}

			if (!QueryServiceObjectSecurity(schService,
				DACL_SECURITY_INFORMATION, psd, dwSize, &dwBytesNeeded))
			{
				printf("QueryServiceObjectSecurity failed (%d)\n", GetLastError());
				goto dacl_cleanup;
			}
		}
		else
		{
			printf("QueryServiceObjectSecurity failed (%d)\n", GetLastError());
			goto dacl_cleanup;
		}
	}

	// Get the DACL.

	if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl,
		&bDaclDefaulted))
	{
		printf("GetSecurityDescriptorDacl failed(%d)\n", GetLastError());
		goto dacl_cleanup;
	}

	// Build the ACE.
	memset(&ea, 0, sizeof(ea));
	BuildExplicitAccessWithName(&ea, TEXT("CURRENT_USER"),
		SERVICE_START,
		SET_ACCESS, NO_INHERITANCE);

	dwError = SetEntriesInAcl(1, &ea, pacl, &pNewAcl);
	if (dwError != ERROR_SUCCESS)
	{
		printf("SetEntriesInAcl failed(%d)\n", dwError);
		goto dacl_cleanup;
	}

	// Initialize a new security descriptor.

	if (!InitializeSecurityDescriptor(&sd,
		SECURITY_DESCRIPTOR_REVISION))
	{
		printf("InitializeSecurityDescriptor failed(%d)\n", GetLastError());
		goto dacl_cleanup;
	}

	// Set the new DACL in the security descriptor.

	if (!SetSecurityDescriptorDacl(&sd, TRUE, pNewAcl, FALSE))
	{
		printf("SetSecurityDescriptorDacl failed(%d)\n", GetLastError());
		goto dacl_cleanup;
	}

	// Set the new DACL for the service object.

	if (!SetServiceObjectSecurity(schService,
		DACL_SECURITY_INFORMATION, &sd))
	{
		printf("SetServiceObjectSecurity failed(%d)\n", GetLastError());
		goto dacl_cleanup;
	}
	else printf("Service DACL updated successfully\n");

dacl_cleanup:
	CloseServiceHandle(schSCManager);
	CloseServiceHandle(schService);

	if (NULL != pNewAcl)
		LocalFree((HLOCAL)pNewAcl);
	if (NULL != psd)
		HeapFree(GetProcessHeap(), 0, (LPVOID)psd);
}

SERVICE_STATUS ServiceManager::gSvcStatus;

SERVICE_STATUS_HANDLE ServiceManager::gSvcStatusHandle;

Server ServiceManager::server;

TCHAR ServiceManager::WorkingDirectory[MAX_PATH];

void ServiceManager::seBackupPrivilege()
{
	HANDLE hAccessToken = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	LUID luidPrivilege;
	DWORD dwErrorCode;
	BY_HANDLE_FILE_INFORMATION fiFileInfo;

	// -----------------------------------------------------
	// first of all we need anable SE_BACKUP_NAME privilege
	// -----------------------------------------------------
	OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hAccessToken);

	LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luidPrivilege);

	TOKEN_PRIVILEGES tpPrivileges;
	tpPrivileges.PrivilegeCount = 2;
	tpPrivileges.Privileges[0].Luid = luidPrivilege;
	tpPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &luidPrivilege);

	tpPrivileges.Privileges[1].Luid = luidPrivilege;
	tpPrivileges.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hAccessToken, FALSE, &tpPrivileges, 0, NULL, NULL);
}
