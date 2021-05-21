#pragma once

#include "Scanner.h"
#include "Base.h"

class Monitor
{
public:

	Monitor(const std::u16string& path, const std::shared_ptr<Base>& base,
		const std::shared_ptr<ThreatList>& threats);

	Monitor& operator=(const Monitor& other);

	Monitor();
	~Monitor() = default;

	void start();
	void resume();
	void pause();
	void stop();

	inline std::u16string getPath() { return dirPath; }

private:
	void run();
private:
	Scanner scanner;
	std::u16string dirPath;
	HANDLE changeHandle = INVALID_HANDLE_VALUE;
	bool shouldStop = false;
	bool shouldPause = false;
};