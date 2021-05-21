#pragma once
#include <memory>

#include "ScanObject.h"
#include "Base.h"

class ScanEngine
{
public:
	ScanEngine(const std::shared_ptr<Base>& base);
	ScanEngine();
	~ScanEngine() = default;

	ScanEngine& operator=(const ScanEngine& other);

	bool scan(const ScanObject& scanObject, std::u16string& virusName);

private:
	bool scanFile(const ScanObject& scanObject, std::u16string& virusName);
	bool scanMemory(const ScanObject& scanObject, std::u16string& virusName);
	bool scanZipEntry(const ScanObject& scanObject, std::u16string& virusName);
	void updateBufferFromFile(std::ifstream& file);

	void updateBufferFromZipEntry(zip_file* file);
private:
	std::shared_ptr<Base> base;

	// 1 MB buffer
	const size_t bufferSize = 1024 * 1024;
	std::vector<char> buffer;

	// signatures with length less than 8 bytes are not detected
	const size_t minSigLength = 8;
	// signatures with length more than 1 kb are not detected
	const size_t maxSigLength = 1024;
};
