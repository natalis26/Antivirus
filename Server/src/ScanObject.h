#pragma once

#include <stdint.h>
#include <string>
#include <zip.h>

enum class OBJTYPE { NONE = 0, DIRENTRY, ZIPENTRY, MEMORY};

struct ScanObject
{
	OBJTYPE objtype = OBJTYPE::NONE;

	// directory entry attributes
	std::u16string fileType = u"";
	std::u16string filePath = u"";

	// archive entry attributes
	zip_t* archive = nullptr;
	zip_int64_t index = 0;

	//memory attributes
	uint8_t* address = nullptr;
	size_t size = 0;

};