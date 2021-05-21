#include "BinaryReader.h"


BinaryReader::BinaryReader(const std::u16string& path)
{
	handle = CreateFile((wchar_t*)path.c_str(), 
		GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	HRESULT error = GetLastError();
}

BinaryReader::BinaryReader(const std::shared_ptr<IPC>& ipc)
{
	handle = ipc->readHandle();
}

void BinaryReader::close()
{
	CloseHandle(handle);
}

int8_t BinaryReader::readInt8()
{
	DWORD bytesRead;
	int8_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

int16_t BinaryReader::readInt16()
{
	DWORD bytesRead;
	int16_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

int32_t BinaryReader::readInt32()
{
	DWORD bytesRead;
	int32_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

int64_t BinaryReader::readInt64()
{
	DWORD bytesRead;
	int64_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

uint8_t BinaryReader::readUInt8()
{
	DWORD bytesRead;
	uint8_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

uint16_t BinaryReader::readUInt16()
{
	DWORD bytesRead;
	uint16_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

uint32_t BinaryReader::readUInt32()
{
	DWORD bytesRead;
	uint32_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

uint64_t BinaryReader::readUInt64()
{
	DWORD bytesRead;
	uint64_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

std::u16string BinaryReader::readU16String()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();
	char16_t result[1024];
	ReadFile(handle, result, size * sizeof(char16_t), &bytesRead, NULL);
	HRESULT error = GetLastError();

	result[size] = u'\0';
	return std::move(std::u16string(result));
}

char16_t BinaryReader::readU16Char()
{
	DWORD bytesRead;
	char16_t result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

std::string BinaryReader::readASCIIString()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();
	char result[1024];
	ReadFile(handle, result, size * sizeof(char), &bytesRead, NULL);

	result[size] = '\0';
	return std::move(std::string(result));
}

char BinaryReader::readASCIIChar()
{
	DWORD bytesRead;
	char result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

float BinaryReader::readFloat32()
{
	DWORD bytesRead;
	float result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

double BinaryReader::readFloat64()
{
	DWORD bytesRead;
	double result;
	ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

	return result;
}

std::vector<int8_t> BinaryReader::readArrayInt8()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<int8_t> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(int8_t) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<int16_t> BinaryReader::readArrayInt16()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<int16_t> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(int16_t) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<int32_t> BinaryReader::readArrayInt32()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<int32_t> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(int32_t) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<int64_t> BinaryReader::readArrayInt64()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<int64_t> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(int64_t) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<uint8_t> BinaryReader::readArrayUInt8()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<uint8_t> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(uint8_t) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<uint16_t> BinaryReader::readArrayUInt16()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<uint16_t> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(uint16_t) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<uint32_t> BinaryReader::readArrayUInt32()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<uint32_t> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(uint32_t) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<uint64_t> BinaryReader::readArrayUInt64()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<uint64_t> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(uint64_t) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<float> BinaryReader::readArrayFloat32()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<float> result;
	result.resize(size);


	ReadFile(handle, result.data(), sizeof(float) * size, &bytesRead, NULL);

	return std::move(result);
}

std::vector<double> BinaryReader::readArrayFloat64()
{
	DWORD bytesRead;
	uint32_t size = readUInt32();

	std::vector<double> result;
	result.resize(size);

	ReadFile(handle, result.data(), sizeof(double) * size, &bytesRead, NULL);

	return std::move(result);
}
