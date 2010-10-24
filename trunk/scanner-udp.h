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

#ifndef __SCANNERUDP__
#define __SCANNERUDP__

#include "yapscan.h"
#include "scanner-port.h"
#include "scanner-icmp.h" // for icmp type/code names

struct send_udp
{
	struct iphdr ip;
	struct udphdr udp;
};

struct pseudo_hdr_udp
{
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
        struct udphdr udp;
};

class UdpScanner : public PortScanner {
	public:
		UdpScanner(char *device);
		UdpScanner();
		~UdpScanner();
		char* getPcapFilter();
		// void setShowClosedPorts(int newval);
		void setPortClosed(int port);
		void dumpPortListOpen();
		int sendPacket();
		void setPcapFilter();
		void pcapCallback(Scanner *s, const struct pcap_pkthdr *pkthdr, const u_char *pkt);

	protected:
		int icmp_probe_type;
		int src_port;
		int port_count;
		int show_closed_ports;
		//struct port_element *pfirst_port_element;
		//struct port_element *plast_port_element;
		//struct port_element *pcurrent_port_element;
};
#endif // __SCANNERUDP__
