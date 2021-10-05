#pragma once

#include "AStream.h"
#include "DataChunk.h"
#include "MappedFile.h"
#include "pcapper.h"

#include <memory>

class PCapRecordIterator
{
private:
	std::shared_ptr<MappedFile> m_MappedFile;
	std::shared_ptr<AStream> m_Stream;
	pcap_file_header m_FileHeader;
	std::shared_ptr<DataChunk> m_Buffer;

	std::shared_ptr<DataChunk> m_Next;

protected:
public:
	PCapRecordIterator(const std::string &filename);

	pcap_file_header GetFileHeader() {return m_FileHeader;}

	std::shared_ptr<DataChunk> operator()();

};
