#include <IPC.h>
#include <BinaryReader.h>

#include "BaseLoader.h"

Base* BaseLoader::load(const std::u16string& path)
{
	BinaryReader reader(path);

	std::u16string header = reader.readU16String();
	if (header != std::u16string(u"Denisovich"))
		return new Base();

	uint64_t rowCount = reader.readUInt64();

	std::unordered_multimap<uint64_t, Record> base;
	Record record;
	for (int i = 0; i < rowCount; i++)
	{
		record.name = reader.readU16String().c_str();
		record.type = reader.readU16String().c_str();
		record.length = reader.readUInt64();

		uint64_t sigStart = reader.readUInt64();
		std::reverse((uint8_t*)&sigStart, ((uint8_t*)&sigStart) + 8);

		record.sigStart = sigStart;
		record.offsetStart = reader.readUInt64();
		record.offsetEnd = reader.readUInt64();
		record.sha256 = reader.readASCIIString().c_str();

		base.insert({record.sigStart, record});
	}

	reader.close();

	return new Base(std::move(base));
}
