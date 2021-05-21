#pragma once
#include <IPC.h>
#include <memory>
#include "Base.h"
#include "ThreatList.h"
#include "Monitor.h"
#include <ctime>
#include "ScheduleScanner.h"

class Server
{
public:
	Server();
	~Server();

	void startUp();
	void shutDown();

private:
	void startReading();
	void processRequest();
	void deleteRequest();
	void quarantine();
	void startScan();
	void scheduleScan();

	void loadMonitors();
	void saveMonitors();
	void loadScheduleScanners();
	void saveScheduleScanners();
private:
	std::shared_ptr<Base> base;
	std::shared_ptr<IPC> ipc;
	std::shared_ptr<ThreatList> threats;

	Scanner scanner;
	
	std::vector<Monitor> monitors;
	std::vector<ScheduleScanner> scheduleScanners;

	HANDLE hReportAddress;
	bool clientShutdown = false;
};
