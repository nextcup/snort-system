#include <deque>
#include <fstream>
#include <iostream>
#include <string>

// We use the BSD primitives throughout as they exist on both BSD and Linux.
#define __FAVOR_BSD
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap.h>

using std::cerr;
using std::cout;
using std::deque;
using std::endl;
using std::ifstream;
using std::string;

/**
 * Helper function to locate the offset of the first byte of the payload in the
 * given ethernet frame. Offset into the packet, and the length of the payload
 * are returned in the arguments @a offset and @a length.
 */
static bool
payloadOffset(const unsigned char *pkt_data, unsigned int *offset,
              unsigned int *length, int *ipproto) {
  const ip *iph = (const ip *)(pkt_data + sizeof(ether_header));
  const tcphdr *th = nullptr;

  // Ignore packets that aren't IPv4
  if (iph->ip_v != 4) {
    return false;
  }

  // Ignore fragmented packets.
  if (iph->ip_off & htons(IP_MF | IP_OFFMASK)) {
    return false;
  }

  // IP header length, and transport header length.
  unsigned int ihlen = iph->ip_hl * 4;
  unsigned int thlen = 0;

  switch (iph->ip_p) {

  case IPPROTO_TCP:
    th = (const tcphdr *)((const char *)iph + ihlen);
    thlen = th->th_off * 4;
    *ipproto = 1;
    break;
  case IPPROTO_UDP:
    thlen = sizeof(udphdr);
    *ipproto = 2;
    break;
// case IPPROTO_ICMP:
//    thlen = 8;
//    break;
  default:
    return false;
  }

  *offset = sizeof(ether_header) + ihlen + thlen;
  *length = sizeof(ether_header) + ntohs(iph->ip_len) - *offset;

  return *length != 0;
}


class Benchmark {
private:
  

public:
  // Packet data to be scanned.
  deque<string> packets;
  deque<int> ipprotos;
  // Count of matches found during scanning
  size_t matchCount;
  
  Benchmark() : matchCount(0) { ; }

  // Read a set of streams from a pcap file
  bool readStreams(const char *pcapFile) {
    // Open PCAP file for input
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcapHandle = pcap_open_offline(pcapFile, errbuf);
    if (pcapHandle == nullptr) {
      cerr << "ERROR: Unable to open pcap file \"" << pcapFile
           << "\": " << errbuf << endl;
      return false;
    }

    struct pcap_pkthdr pktHeader;
    const unsigned char *pktData;
    int ipproto;
    while ((pktData = pcap_next(pcapHandle, &pktHeader)) != nullptr) {
      unsigned int offset = 0, length = 0;
      if (!payloadOffset(pktData, &offset, &length, &ipproto)) {
        continue;
      }

      // Valid TCP or UDP packet
      const char *payload = (const char *)pktData + offset;
      
      packets.push_back(string(payload, length));
      ipprotos.push_back(ipproto);

    }
    pcap_close(pcapHandle);

    return !packets.empty();
  }
  // Return the number of bytes scanned
  size_t bytes() const {
    size_t sum = 0;
    for (const auto &packet : packets) {
      sum += packet.size();
    }
    return sum;
  }
  // Return the number of matches found.
  size_t matches() const { return matchCount; }

  // Clear the number of matches found.
  void clearMatches() { matchCount = 0; }
};


