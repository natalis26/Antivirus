#pragma once
#include <string>
#include <memory>
#include <fstream>
#include <Windows.h>

#include "Base.h"
#include "ScanObject.h"
#include "ScanEngine.h"
#include "ThreatList.h"

class Scanner
{
public:
	Scanner(const std::shared_ptr<Base>& base, 
		const std::shared_ptr<ThreatList>& threats);

	Scanner();

	~Scanner() = default;

	Scanner& operator=(const Scanner& other);

	void startScan(const std::u16string& path, HANDLE hReportAddress, bool async = true);

	void startScan(const std::u16string& path, bool async = false);

	void stopScan();

	inline bool scanStopped() { return stopped; }

private:
	void scanWithReport(const std::u16string& path, HANDLE hReportAddress);
	void scan(const std::u16string& path);

	void scanDirectory(const std::u16string& path, HANDLE hReportAddress);
	void scanFile(const std::u16string& path, HANDLE hReportAddress);

	void scanDirectory(const std::u16string& path);
	void scanFile(const std::u16string& path);

	bool scanZip(const ScanObject& scanObject, std::u16string& virusName);
private:
	std::shared_ptr<Base> base;
	std::shared_ptr<ThreatList> threats;
	ScanEngine engine;

	bool shouldStop = false;
	bool stopped = false;
};