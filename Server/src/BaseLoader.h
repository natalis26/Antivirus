#pragma once
#include "Base.h"

class BaseLoader
{
public:
	static Base* load(const std::u16string& path);
};