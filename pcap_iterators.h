#pragma once

#include "bitbang.h"
#include "DataChunk.h"
#include "serresfilter.h"

#include "packet_ethernet.h"
#include "packet_ip.h"
#include "packet_tcp.h"
#include "pcapper.h"
#include "PCapRecordIterator.h"


#include <functional>


// 
// Iterate over a source of datachunks
// return packet_ethernet
class transform_ether_packet
{
	std::function<std::shared_ptr<DataChunk>()> m_RecordIterator;

public:
	transform_ether_packet(std::function<std::shared_ptr<DataChunk>()> iter)
		: m_RecordIterator(iter)
	{
	}

	std::shared_ptr<packet_ethernet> operator()()
	{
		int readerror =0;

		auto record = m_RecordIterator();
		
		if (!record) return nullptr;
	
		auto etherhead = packet_ethernet::try_create(record);
		if (!etherhead) return nullptr;
	
		return etherhead;
	}
};

//
// iterate over packet_ethernet
// return header_ipv4
class filter_ipv4
{
	std::function<std::shared_ptr<packet_ethernet>()> m_EtherIterator;

public:
	filter_ipv4(std::function<std::shared_ptr<packet_ethernet>()> iter)
		: m_EtherIterator(iter)
	{
	}

	std::shared_ptr<header_ipv4> operator()()
	{
		int readerror = 0;

		while (auto etherhead = m_EtherIterator())
		{
			if (!etherhead->isEthernetII()) {
				continue;
			}

			if (etherhead->m_TypeOrLength != ET_IPv4) {
				continue;
			}
			
			auto hdr = header_ipv4::try_create(etherhead);
			if (!hdr) return nullptr;

			return hdr;
		}

		return nullptr;
	}

};

class filter_tcp
{
	std::function<std::shared_ptr<header_ipv4>()> m_ipv4iterator;

public:
	filter_tcp(std::function<std::shared_ptr<header_ipv4>()> iter)
		: m_ipv4iterator(iter)
	{
	}

	std::shared_ptr<packet_header_tcp> operator()()
	{
		while(auto iphead = m_ipv4iterator())
		{
			if (iphead->m_Protocol != IP_PROTO_TCP) {
				continue;
			}

			auto tcphdr = packet_header_tcp::try_create(iphead);
			if (!tcphdr) return nullptr;

			return tcphdr;
		}

		return nullptr;
	}
};


// Turn a regular pcap captured IP V4 packet
// into a Serres TCP/IP V4 packet
class transform_IPV4ToSerresV4
{
	std::function<std::shared_ptr<packet_header_tcp>()> m_Iterator;

public:
	transform_IPV4ToSerresV4(std::function<std::shared_ptr<packet_header_tcp>()> iter)
		: m_Iterator(iter)
	{
	}

	static std::shared_ptr<DataChunk> convertPacket(const std::shared_ptr<packet_header_tcp> &pckt)
	{
		uint64_t ctxt = (pckt->m_IPPacket->m_SourceIPAddress.getNativeValue() + pckt->m_SourcePort) +
					(pckt->m_IPPacket->m_DestinationIPAddress.getNativeValue() + pckt->m_DestinationPort);

		// Allocate a packet to be used
		size_t bufferLength = sizeof(STREAM_DATA_IPV4_HEADER) + pckt->getPayloadLength();
		auto chunk = std::make_shared<DataChunk>(bufferLength);
		STREAM_DATA_IPV4_HEADER *hdr = (STREAM_DATA_IPV4_HEADER *)chunk->GetData();
		hdr->m_type = SERRES_IOCTL_TYPE_STREAM_IPV4;
		hdr->m_contextId = ctxt;
		if ((pckt->m_DestinationPort == 80) || (pckt->m_DestinationPort == 443)) {
			hdr->m_direction = FWP_DIRECTION_OUTBOUND;

			hdr->m_localAddress = pckt->m_IPPacket->m_SourceIPAddress.getNativeValue();
			hdr->m_localPort = pckt->m_SourcePort;	

			hdr->m_remoteAddress = pckt->m_IPPacket->m_DestinationIPAddress.getNativeValue();
			hdr->m_remotePort = pckt->m_DestinationPort;
		} else {
			hdr->m_direction = FWP_DIRECTION_INBOUND;
			hdr->m_localPort = pckt->m_DestinationPort;			
			hdr->m_remotePort = pckt->m_SourcePort;
		}

		hdr->m_ipProto = pckt->m_IPPacket->m_Protocol;
		hdr->m_localAddress = 0xc0a80101;	// 192.168.1.1
		hdr->m_remoteAddress = 0xcc4fc5c8;		// 204.79.197.200
		hdr->m_processId = 0;

		uint8_t *dataptr = chunk->GetData() + sizeof(STREAM_DATA_IPV4_HEADER);
		size_t bytesRead = 0;
		int readerror = 0;
		pckt->GetPayloadStream()->ReadBytes(dataptr, pckt->getPayloadLength(), &bytesRead, BD_INFINITE, &readerror);

		return chunk;
	}

	std::shared_ptr<DataChunk> operator()()
	{
		auto pckt = m_Iterator();
		if (!pckt) {
			return nullptr;
		}

		return convertPacket(pckt);
	}
};
