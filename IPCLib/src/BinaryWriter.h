#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <memory.h>

#include "IPC.h"

class BinaryWriter
{
public:

	BinaryWriter(const std::u16string& path);
	BinaryWriter(const std::shared_ptr<IPC>& ipc);
	BinaryWriter(HANDLE handle) { this->handle = handle; }

	~BinaryWriter() = default;

	void close();

	// WRITE FUNCTIONS

	//signed integers
	void writeInt8(int8_t value);
	void writeInt16(int16_t value);
	void writeInt32(int32_t value);
	void writeInt64(int64_t value);

	//unsigned integers
	void writeUInt8(uint8_t value);
	void writeUInt16(uint16_t value);
	void writeUInt32(uint32_t value);
	void writeUInt64(uint64_t value);

	// string and character
	void writeU16String(const std::u16string& value);
	void writeU16Char(char16_t value);

	void writeASCIIString(const std::string& value);
	void writeASCIIChar(char value);

	// floats
	void writeFloat32(float value);
	void writeFloat64(double value);

	// arrays
	void writeArrayInt8(int8_t* values, uint32_t size);
	void writeArrayInt16(int16_t* values, uint32_t size);
	void writeArrayInt32(int32_t* values, uint32_t size);
	void writeArrayInt64(int64_t* values, uint32_t size);

	void writeArrayUInt8(uint8_t* values, uint32_t size);
	void writeArrayUInt16(uint16_t* values, uint32_t size);
	void writeArrayUInt32(uint32_t* values, uint32_t size);
	void writeArrayUInt64(uint64_t* values, uint32_t size);

	void writeArrayFloat32(float* values, uint32_t size);
	void writeArrayFloat64(double* values, uint32_t size);


	// struct
	template<typename T>
	void writeStruct(const T& value)
	{
		DWORD bytesWritten;
		WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
	}

private:
	HANDLE handle;
};