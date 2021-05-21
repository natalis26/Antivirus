#include "Monitor.h"

extern HANDLE mutex;

Monitor::Monitor(const std::u16string& path, const std::shared_ptr<Base>& base, 
	const std::shared_ptr<ThreatList>& threats)
	: scanner(base, threats)
{
	this->dirPath = path;
}



Monitor::Monitor()
{

}

Monitor& Monitor::operator=(const Monitor& other)
{
	dirPath = other.dirPath;
	scanner = other.scanner;
	shouldStop = other.shouldStop;
	shouldPause = other.shouldPause;
	changeHandle = other.changeHandle;

	return *this;
}

void Monitor::start()
{
	shouldStop = false;
	shouldPause = false;

	changeHandle = CreateFile((wchar_t*)dirPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	HRESULT error = GetLastError();
	run();
}

void Monitor::resume()
{
	shouldPause = false;	
}

void Monitor::pause()
{
	shouldPause = true;
}

void Monitor::stop()
{
	shouldStop = true;
}

struct DirectoryInfo
{
	DWORD NextEntryOffset;
	DWORD Action;
	DWORD FileNameLength;
	WCHAR FileName[4000];
};

void Monitor::run()
{
	while (TRUE)
	{
		DirectoryInfo info;
		DWORD bytesReturned;
		int result = ReadDirectoryChangesW(changeHandle, &info, sizeof(info), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &bytesReturned, NULL, NULL);
		HRESULT error = GetLastError();

		while (shouldPause)
			Sleep(1);

		if (shouldStop)
		{
			CloseHandle(changeHandle);
			return;
		}

		Sleep(1000);

		DirectoryInfo* pinfo = &info;
		while (true)
		{
			uint32_t length = pinfo->FileNameLength / sizeof(WCHAR);
			
			std::u16string path((char16_t*)pinfo->FileName);
			path[length] = u'\0';

			std::u16string monitoringPath = dirPath;
			monitoringPath.append(u"/").append(path);

			scanner.startScan(monitoringPath);

			if (pinfo->NextEntryOffset == 0)
				break;
			
			pinfo = (DirectoryInfo*)((char*)pinfo + pinfo->NextEntryOffset);
		}
	}
}

