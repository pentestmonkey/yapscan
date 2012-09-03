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
// You are encouraged to send comments, improvements or suggestions to
// me at yapscan@pentestmonkey.net
//

#ifndef __SCANNERICMP__
#define __SCANNERICMP__

#include "yapscan.h"
#include "scanner.h"

struct icmp_element {
	struct icmp_element *pnext;
	struct icmp_element *pprev;
	unsigned char type;
	unsigned char code;
	unsigned int send_count; // count retries
};

struct send_icmp {
	struct iphdr ip;
	struct icmphdr icmp;
};

struct send_icmp_timestamp {
	struct iphdr ip;
	struct icmphdr icmp;
	int originate_ts;
	int receive_ts;
	int transmit_ts;
};

extern const char *icmp_type[];

class IcmpScanner : public Scanner {
	public:
		IcmpScanner(char *device);
		IcmpScanner();
		~IcmpScanner();
		char* getPcapFilter();
		int sendPacket();
		void setPcapFilter();
		void pcapCallback(Scanner *s, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
		int getIcmpProbeType();
		void setIcmpProbeType(int new_probe_type);
		int addIcmpTest(unsigned char type, unsigned char code);
		void noMoreRetries(in_addr ip, unsigned char type, unsigned char code);
		int getPercentComplete();
		int getRemainingScanTime();
		int deleteIcmpTest(host_element *h, icmp_element *i);
		void dumpIcmpList();
		void dumpElement(icmp_element *i);
		void deleteAllHosts();
		void resetCounters();
		
	protected:
		int icmp_probe_type;
		int scan_complete;
		int icmp_test_count;
		int host_test_count;
};

#endif // __SCANNERICMP__
