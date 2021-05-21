#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <Windows.h>

extern HANDLE mutex;

class ThreatList
{
public:
	ThreatList(const std::u16string& path);
	~ThreatList();

	void load();
	void save();

	void add(const std::u16string& path);
	void add(uint64_t threatIndex, const std::u16string& threatPath);
	void remove(uint64_t index);
	inline std::u16string get(size_t index) { return threats[index]; }
	inline size_t size() { return threats.size(); }

private:
	std::vector<std::u16string> threats;
	std::u16string path;
	HANDLE mutex;
};
