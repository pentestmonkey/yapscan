// yapscan - Yet Another Port Scanner
// Copyright (C) 2006 pentestmonkey@pentestmonkey.net
// 
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then 
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as 
// published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to 
// you, then do not use this tool.
// 
// You are encouraged to send comments, improvements or suggestions to
// me at yapscan@pentestmonkey.net
//

#ifndef __SCANNER__
#define __SCANNER__
#include "yapscan.h"

struct host_element {
	struct in_addr ip;
	struct port_element *pcurrent_port;
	struct port_element *pfirst_port;
	struct port_element *plast_port;
	struct icmp_element *pcurrent;
	struct host_element *pnext;
	struct host_element *pprev;
	struct timeval rtt_tv;        // udp only
	int inter_packet_interval_us; // udp only. microseconds between packets
	struct timeval next_probe_time_tv;   // udp only
};

class Scanner {
	public:
		Scanner();
		Scanner(const Scanner&);
		~Scanner();
	
		Scanner* operator=(const Scanner&);
		int getPositiveResponseCount();
		void setHwHeadLen(int len);
		int getHwHeadLen();
		void setDebugLevel(int level);
		int getDebugLevel();
		void setVerboseLevel(int level);
		int getVerboseLevel();
		int setHwHeadLenAuto(void);
		void recvPackets();
		void startScan();
		void setRTT(struct timeval *newrtt);
		unsigned int getHostCount();
		void setTries(unsigned int newtries);
		int getTries();
		timeval getRTT();
		int addHostsFromFile(char *filename, unsigned int start, unsigned int count);
		int addHost(char *newhost, unsigned int start, unsigned int count);
		int addHost(char *newhost);
		int deleteHost(host_element *h);
		void dumpHostList();
		void scanningChunk(int yesorno);
		void setInterface(char *newdevice);
		void setDevice(char *newdevice);
		char* getDevice();
		void setSrcIP(char *new_src_ip_str);
		void setSrcMAC(char *new_src_mac_str);
		char* getSourceAddress();
		void setBandwidthMax(unsigned int new_bandwidth_max);
		unsigned int getBandwidthMax();
		char* getPcapFilter();
		void initSrcIP(void);
		int getTTL();
		void setTTL(int);
		void updateCompletionTime(void);
		void setNameResolution(int flag);
		unsigned int getPcapPacketsProcessed(void);
		unsigned int getPcapPacketsDropped(void);

		// Virtuals

		/*
		 * Set pcap filter that matches responses to our probes.
		 *
		 * This MUST be overridden by the inheriting class for the
		 * scanner to work.
		 */
		virtual void setPcapFilter() = 0;
		
		/*
		 * Sends a packet
		 *
		 * Returns:
		 * 1: if there are still more packets to send
		 * 0: if there are no more packets to send
		 * 
		 * This MUST be overridden by the inheriting class for the
		 * scanner to work.
		 */
		virtual int sendPacket() = 0;
		
		/*
		 * Process incomming packets
		 *
		 * This MUST be overridden by the inheriting class for the
		 * scanner to work.
		 */
		virtual void pcapCallback(Scanner *s, const struct pcap_pkthdr *pkthdr, const u_char *pkt) = 0;
	
		// inheriting class must know how to calculate its esitmated completion time
		virtual int getPercentComplete() = 0;
		virtual int getRemainingScanTime() = 0;

	protected:
		char device[10];
		int port_count;
		int host_count;
		unsigned int bandwidth_max;
		char src_ip_str[16];
		int hw_head_len;
		in_addr src_ip;
		char src_mac_str[19];
		char pcap_filter_str[1000];
		unsigned int tries;

		struct host_element *plast_host_element;
		struct host_element *pfirst_host_element;
		struct host_element *pcurrent_host_element;
		pcap_t *sniffer;
		int packet_size;
		int packets_sent;
		int inter_packet_interval_us;
		int debug;
		int verbose;
		struct timeval rtt_tv;
		int positive_response_count;
		char pfilter[PCAP_FILTER_LEN];
		int ttl;
		unsigned int total_bytes_sent;
		int name_resolution;
		int scanning_chunk;
};

#endif // __SCANNER__
