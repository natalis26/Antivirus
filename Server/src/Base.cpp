#include "Base.h"
#include <picosha2.h>
#include <memory>

Base::Base(std::unordered_multimap<uint64_t, Record>&& base)
{
	this->base = std::move(base);
}

Base::Base(Base&& other)
{
	this->base = std::move(other.base);
}

bool Base::find(char* address, uint64_t offset, const std::u16string& type, std::u16string& name)
{
	
	uint64_t key;
	memcpy((void*)&key, (void*)address, sizeof(key));
	
	auto entries = base.equal_range(key);

	for (auto& it = entries.first; it != entries.second; it++)
	{
		if (it->second.type == type)
		{
			if (offset >= it->second.offsetStart && offset <= it->second.offsetEnd)
			{
				if (it->second.length == 8)
				{
					name = it->second.name;
					return true;
				}
				std::vector<char> bytes(address + 8, address + it->second.length);
				std::string hash_hex_str;
				picosha2::hash256_hex_string(bytes, hash_hex_str);

				if (it->second.sha256 == hash_hex_str)
				{
					name = it->second.name;
					return true;
				}
			}
		}
	}
	return false;
}


Base& Base::operator=(Base&& other)
{
	this->base = std::move(other.base);
	return *this;
}

