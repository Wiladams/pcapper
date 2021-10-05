#include "PCapRecordIterator.h"
#include "MemoryStream.h"

#include <iostream>

PCapRecordIterator::PCapRecordIterator(const std::string &filename)
	: m_MappedFile(nullptr)
	, m_Stream(nullptr)
	, m_Next(nullptr)
	, m_Buffer(nullptr)
{
	m_Buffer = std::make_shared<DataChunk>(64*1024);
	std::cout << "== GetPCapFileIterator ==" << std::endl;

	// Try to mem map the file
	// if that fails, we should return an empty iterator
	m_MappedFile = MappedFile::try_create(filename);
	if (!m_MappedFile) {
		throw;
	}

	m_Stream = std::make_shared<MemoryStream>(m_MappedFile);

	// Read the file header to do any
	// necessary setup
	if (!m_FileHeader.read(*m_Stream)) {
		std::cout << "Unable to read pcap_file_header: " << std::endl;
		throw;
	}

	// Print out file header just to see what we've got
	//m_FileHeader.print();

	// Now we're ready to iterate
}

std::shared_ptr<DataChunk> PCapRecordIterator::operator()()
{
	// Read the individual records
	pcap_record_header rechead;

	int readerror = 0;
	if (!rechead.read(*m_Stream, readerror)) {
		m_Next = nullptr;
	} else {
		size_t bytesRead = 0;
		if (!m_Stream->ReadBytes(m_Buffer->GetData(), rechead.incl_len, &bytesRead, BD_INFINITE, &readerror)) {
			m_Next = nullptr;
		}
		m_Next = std::make_shared<DataChunk>(m_Buffer->GetData(), bytesRead);
	}

	return m_Next;
}

