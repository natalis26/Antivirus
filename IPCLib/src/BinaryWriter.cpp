#include "BinaryWriter.h"

BinaryWriter::BinaryWriter(const std::u16string& path)
{
	handle = CreateFile((wchar_t*)path.c_str(), GENERIC_WRITE, 0, NULL, 
		TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (handle == INVALID_HANDLE_VALUE)
		handle = CreateFile((wchar_t*)path.c_str(), GENERIC_WRITE, 0, NULL,
			CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
}

BinaryWriter::BinaryWriter(const std::shared_ptr<IPC>& ipc)
{
	handle = ipc->writeHandle();
}

void BinaryWriter::close()
{
	CloseHandle(handle);
}

void BinaryWriter::writeInt8(int8_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeInt16(int16_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeInt32(int32_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeInt64(int64_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeUInt8(uint8_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeUInt16(uint16_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeUInt32(uint32_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeUInt64(uint64_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeU16String(const std::u16string& value)
{
	writeUInt32((uint32_t)value.size());
	DWORD bytesWritten;
	WriteFile(handle, (const void*)value.c_str(), value.size() * sizeof(char16_t), &bytesWritten, NULL);
}

void BinaryWriter::writeU16Char(char16_t value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeASCIIString(const std::string& value)
{
	writeUInt32((uint32_t)value.size());
	DWORD bytesWritten;
	WriteFile(handle, (const void*)value.c_str(), value.size() * sizeof(char), &bytesWritten, NULL);
}

void BinaryWriter::writeASCIIChar(char value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeFloat32(float value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeFloat64(double value)
{
	DWORD bytesWritten;
	WriteFile(handle, (const void*)&value, sizeof(value), &bytesWritten, NULL);
}

void BinaryWriter::writeArrayInt8(int8_t* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(int8_t) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayInt16(int16_t* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(int16_t) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayInt32(int32_t* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(int32_t) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayInt64(int64_t* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(int64_t) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayUInt8(uint8_t* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(uint8_t) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayUInt16(uint16_t* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(uint16_t) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayUInt32(uint32_t* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(uint32_t) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayUInt64(uint64_t* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(uint64_t) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayFloat32(float* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(float) * size, &bytesWritten, NULL);
}

void BinaryWriter::writeArrayFloat64(double* values, uint32_t size)
{
	DWORD bytesWritten;

	writeUInt32(size);
	WriteFile(handle, values, sizeof(double) * size, &bytesWritten, NULL);
}
