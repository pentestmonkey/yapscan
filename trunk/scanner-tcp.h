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

#ifndef __SCANNERTCP__
#define __SCANNERTCP__

#include "yapscan.h"
#include "scanner-port.h"

struct send_tcp
{
	struct iphdr ip;
	struct tcphdr tcp;
};

class TcpScanner : public PortScanner {
	public:
		TcpScanner(char *device);
		TcpScanner();
		void init();
		~TcpScanner();
		void setResolveServiceNames(int onoff);
		char* getPcapFilter();
		void updateCompletionTime(void);
		int sendPacket();
		void setPcapFilter();
		void sendAck(__u32 src_ip, __u32 dest_ip, int src_port, int dest_port, __u32 seq_no, __u32 ack_no);
		void noMoreRetries(in_addr ip, unsigned short int port);
		void pcapCallback(Scanner *s, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
		void setTcpFlag(int, int);

	protected:
		int icmp_probe_type;
		int src_port;
		int port_count;
		int resolve_service_names;
		int show_closed_ports;
		int syn_flag;
		int ack_flag;
		int urg_flag;
		int fin_flag;
		int rst_flag;
		int psh_flag;
		int ece_flag;
		int cwr_flag;
		struct send_tcp template_packet;
};

#endif // __SCANNERTCP__
