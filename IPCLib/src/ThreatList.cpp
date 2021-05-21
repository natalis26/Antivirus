#include "ThreatList.h"
#include "BinaryReader.h"
#include "BinaryWriter.h"
#include <algorithm>


ThreatList::ThreatList(const std::u16string& path)
{
	this->path = path;
	mutex = OpenMutex(SYNCHRONIZE, FALSE, L"Mutex");
}

ThreatList::~ThreatList()
{
	CloseHandle(mutex);
}

void ThreatList::load()
{
	WaitForSingleObject(mutex, INFINITE);
	threats.resize(0);

	BinaryReader reader(path);

	if (!reader.isOpen())
	{
		ReleaseMutex(mutex);
		return;
	}

	std::u16string header = reader.readU16String();

	if (header != u"Denisovich")
	{
		reader.close();
		ReleaseMutex(mutex);
		return;
	}

	uint64_t recordCount = reader.readUInt64();

	for (size_t i = 0; i < recordCount; i++)
	{
		threats.push_back(reader.readU16String());
	}


	reader.close();
	ReleaseMutex(mutex);

}

void ThreatList::save()
{
	WaitForSingleObject(mutex, INFINITE);

	BinaryWriter writer(path);

	writer.writeU16String(u"Denisovich");

	writer.writeUInt64((uint64_t)threats.size());

	for (size_t i = 0; i < threats.size(); i++)
	{
		writer.writeU16String(threats[i]);
	}

	writer.close();
	ReleaseMutex(mutex);
}

void ThreatList::add(const std::u16string& threatPath)
{
	std::u16string path = threatPath;

	std::replace(path.begin(), path.end(), u'\\', u'/');
	if (std::find(threats.begin(), threats.end(), path) == threats.end())
		threats.push_back(path);
}

void ThreatList::add(uint64_t threatIndex, const std::u16string& threatPath)
{
	threats.insert(threats.begin() + threatIndex, threatPath);
}

void ThreatList::remove(uint64_t index)
{
	threats.erase(threats.begin() + index);
}


