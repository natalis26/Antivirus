#include <thread>
#include <IPCMailslot.h>
#include <BinaryReader.h>
#include <BinaryWriter.h>

#include "Server.h"
#include "Scanner.h"
#include "BaseLoader.h"
#include "Monitor.h"


HANDLE mutex;

Server::Server()
{
	mutex = CreateMutex(NULL, FALSE, L"Mutex");
	monitors.reserve(100);
	scheduleScanners.reserve(100);
}


Server::~Server()
{
	CloseHandle(mutex);
}

void Server::startReading()
{
	ipc = IPC::Mailslots(u"\\\\.\\mailslot\\server", u"\\\\.\\mailslot\\client");

	while (true)
	{
		ipc->connect();

		while (!clientShutdown)
		{
			processRequest();
		}

		clientShutdown = false;
	}
}


void Server::processRequest()
{
	BinaryReader reader(ipc);

	uint8_t cmdCode = reader.readUInt8();

	if (cmdCode == (uint8_t)CMDCODE::SERVERSHUTDOWN)
	{
		shutDown();
	}
	else if (cmdCode == (uint8_t)CMDCODE::CLIENTSHUTDOWN)
	{
		saveMonitors();
		saveScheduleScanners();
		clientShutdown = true;
	}
	else if (cmdCode == (uint8_t)CMDCODE::SCAN) 
	{
		startScan();
	}
	else if (cmdCode == (uint8_t)CMDCODE::DELETETHREAT)
	{
		deleteRequest();
	}
	else if (cmdCode == (uint8_t)CMDCODE::QUARANTINE || cmdCode == (uint8_t)CMDCODE::UNQUARANTINE)
	{
		quarantine();
	}
	else if (cmdCode == (uint8_t)CMDCODE::MONITOR)
	{
		BinaryReader reader(ipc);
		std::u16string path = reader.readU16String();
		monitors.push_back(Monitor(path, base, threats));

		std::thread monitorThread(&Monitor::start, std::ref(monitors[monitors.size() - 1]));
		monitorThread.detach();
	}
	else if (cmdCode == (uint8_t)CMDCODE::STOPMONITOR)
	{
		BinaryReader reader(ipc);
		uint64_t index = reader.readUInt64();
		monitors[index].stop();

		monitors.erase(monitors.begin() + index);
	}
	else if (cmdCode == (uint8_t)CMDCODE::STOPSCAN)
	{
		scanner.stopScan();
		while (!scanner.scanStopped()) 
		{ 
			Sleep(1); 
		}

		BinaryWriter writer(ipc);
		bool success = true;

		writer.writeUInt8((uint8_t)success);
	}
	else if (cmdCode == (uint8_t)CMDCODE::SCHEDULESCAN)
	{
		scheduleScan();
	}
	else if (cmdCode == (uint8_t)CMDCODE::CANCELSCHEDULESCAN)
	{
		BinaryReader reader(ipc);
		uint64_t index = reader.readUInt64();
		scheduleScanners[index].cancel();

		scheduleScanners.erase(scheduleScanners.begin() + index);
	}
}


void Server::deleteRequest()
{
	// check if file exists
	BinaryReader reader(ipc);
	uint64_t threatIndex = reader.readUInt64();
	std::u16string threatPath = threats->get(threatIndex);

	BinaryWriter writer(ipc);
	bool success = false;

	WaitForSingleObject(mutex, INFINITE);

	if (DeleteFile((wchar_t*)threatPath.c_str()))
	{
		threats->remove(threatIndex);
		threats->save();
		success = true;
	}
	else if (GetLastError() == 2)
	{
		threats->remove(threatIndex);
		threats->save();
		success = true;
	}

	ReleaseMutex(mutex);

	writer.writeUInt8((uint8_t)success);
}

void Server::quarantine()
{
	// check if file exists
	BinaryReader reader(ipc);
	uint64_t threatIndex = reader.readUInt64();
	std::u16string threatPath = threats->get(threatIndex);

	std::fstream file((wchar_t*)threatPath.c_str());

	uint32_t header = 0;

	file.read((char*)&header, sizeof(uint32_t));
	header = ~header;
	file.seekg(0);
	file.write((char*)&header, sizeof(uint32_t));
	file.close();
}

void Server::startScan()
{
	BinaryReader reader(ipc);
	std::u16string path = reader.readU16String();
	std::u16string reportPath = reader.readU16String();

	hReportAddress = INVALID_HANDLE_VALUE;

	hReportAddress = CreateFile((LPCWSTR)reportPath.c_str(),
		GENERIC_WRITE,
		FILE_SHARE_READ,
		(LPSECURITY_ATTRIBUTES)NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		(HANDLE)NULL);

	scanner.startScan(path, hReportAddress);
}

void Server::scheduleScan()
{
	BinaryReader reader(ipc);

	std::u16string scanPath = reader.readU16String();
	uint32_t hours = reader.readUInt32();
	uint32_t minutes = reader.readUInt32();

	scheduleScanners.push_back(ScheduleScanner(base, threats, scanPath, hours, minutes));

	std::thread scheduleThread(&ScheduleScanner::start, std::ref(scheduleScanners[scheduleScanners.size() - 1]));
	scheduleThread.detach();
}

void Server::shutDown()
{
	saveMonitors();
	saveScheduleScanners();
	ExitProcess(0);
}

void Server::loadMonitors()
{
	std::u16string filePath = u"Monitors.lsd";
	BinaryReader reader(filePath);
	if (!reader.isOpen())
		return;

	std::u16string header = reader.readU16String();
	if (header != u"Denisovich")
	{
		reader.close();
		return;
	}
	uint64_t recordNumber = reader.readUInt64();

	for (size_t i = 0; i < recordNumber; i++)
	{
		std::u16string scanPath = reader.readU16String();

		monitors.push_back(Monitor(scanPath, base, threats));

		std::thread monitorThread(&Monitor::start, std::ref(monitors[monitors.size() - 1]));
		monitorThread.detach();
	}

	reader.close();

}

void Server::saveMonitors()
{
	std::u16string filePath = u"Monitors.lsd";
	BinaryWriter writer(filePath);
	writer.writeU16String(u"Denisovich");
	writer.writeUInt64(monitors.size());

	for (auto& el : monitors)
	{
		writer.writeU16String(el.getPath());
	}

	writer.close();
}

void Server::loadScheduleScanners()
{
	std::u16string filePath = u"Scanners.lsd";
	BinaryReader reader(filePath);
	if (!reader.isOpen())
		return;

	std::u16string header = reader.readU16String();
	if (header != u"Denisovich")
	{
		reader.close();
		return;
	}
	uint64_t recordNumber = reader.readUInt64();

	for (size_t i = 0; i < recordNumber; i++)
	{
		std::u16string scanPath = reader.readU16String();
		uint32_t hours = reader.readUInt32();
		uint32_t minutes = reader.readUInt32();

		scheduleScanners.push_back(ScheduleScanner(base, threats, scanPath, hours, minutes));

		std::thread monitorThread(&ScheduleScanner::start, std::ref(scheduleScanners[scheduleScanners.size() - 1]));
		monitorThread.detach();
	}

	reader.close();
}

void Server::saveScheduleScanners()
{
	std::u16string filePath = u"Scanners.lsd";
	BinaryWriter writer(filePath);

	writer.writeU16String(u"Denisovich");
	writer.writeUInt64(scheduleScanners.size());

	for (auto& el : scheduleScanners)
	{
		writer.writeU16String(el.getPath());
		writer.writeUInt32(el.getHours());
		writer.writeUInt32(el.getMinutes());
	}

	writer.close();
}

void Server::startUp()
{
	base = std::shared_ptr<Base>(BaseLoader::load(u"Base.lsd"));
	threats = std::make_shared<ThreatList>(u"Threats.lsd");
	threats->load();

	scanner = Scanner(base, threats);

	loadMonitors();
	loadScheduleScanners();
	
	std::thread ipcThread(&Server::startReading, this);
	ipcThread.join();
}
