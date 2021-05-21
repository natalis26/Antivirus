#pragma once
#include <unordered_map>
#include <string>

struct Record
{
	std::u16string name, type;
	uint64_t length, sigStart, offsetStart, offsetEnd;
	std::string sha256;
};

class Base
{
public:
	Base() = default;
	Base(std::unordered_multimap<uint64_t, Record>&& base);
	Base(Base&& other);
	Base& operator=(Base&& other);


	bool find(char* address, uint64_t offset, const std::u16string& type, std::u16string& name);
	

private:
	std::unordered_multimap<uint64_t, Record> base;
};