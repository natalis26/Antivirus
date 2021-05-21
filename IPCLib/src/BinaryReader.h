#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <memory>

#include "IPC.h"

class BinaryReader
{
public:
	BinaryReader(const std::u16string& path);
	BinaryReader(const std::shared_ptr<IPC>& ipc);
	BinaryReader(HANDLE handle) { this->handle = handle; }


	~BinaryReader() = default;

	void close();
	inline bool isOpen() { return handle != INVALID_HANDLE_VALUE; }

	// signed integers
	int8_t  readInt8();
	int16_t readInt16();
	int32_t readInt32();
	int64_t readInt64();

	// unsigned integers
	uint8_t readUInt8();
	uint16_t readUInt16();
	uint32_t readUInt32();
	uint64_t readUInt64();

	// string and character
	std::u16string readU16String();
	char16_t readU16Char();

	std::string readASCIIString();
	char readASCIIChar();

	// floats
	float readFloat32();
	double readFloat64();

	// arrays
	std::vector<int8_t> readArrayInt8();
	std::vector<int16_t> readArrayInt16();
	std::vector<int32_t> readArrayInt32();
	std::vector<int64_t> readArrayInt64();

	std::vector<uint8_t> readArrayUInt8();
	std::vector<uint16_t> readArrayUInt16();
	std::vector<uint32_t> readArrayUInt32();
	std::vector<uint64_t> readArrayUInt64();

	std::vector<float> readArrayFloat32();
	std::vector<double> readArrayFloat64();


	// struct
	template<typename T>
	T readStruct()
	{
		DWORD bytesRead;
		T result;
		ReadFile(handle, (void*)&result, sizeof(result), &bytesRead, NULL);

		return result;
	}

private:

	HANDLE handle;
};