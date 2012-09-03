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

#include "scanner-udp.h"

/*
 * Constructor args:
 *
 * char *device - Device to listen of for returned packets
 * 
 */
UdpScanner::UdpScanner(char *device) {
	if (debug > 2) printf("UdpScanner: Constructing\n");
	src_port = getFirstPID();
	port_count = 0;
	show_closed_ports = 0;
	setDevice(device);
}

UdpScanner::UdpScanner() {
	if (debug > 2) printf("UdpScanner: Constructing\n");
	src_port = getFirstPID();
	port_count = 0;
	show_closed_ports = 0;
}

void UdpScanner::setPcapFilter() {
	snprintf(pfilter, PCAP_FILTER_LEN, "icmp and dst host %s", src_ip_str);
}

// TODO
void UdpScanner::setPortClosed(int port) {
	//struct port_element *p;
	//p = pcurrent_port_element->pnext;
	//int first_port = pcurrent_port_element->port;

	// TODO: This is really inefficient.  Search list backwards, not forwards.
	// printf("Initial port: %d, Target port: %d\n", first_port, port);
	//while(p->port != port) {
		// printf("Current port: %d, Target port: %d\n", p->port, port);
	//	p = p->pnext;
	//}

	//p->status = 0;
}

void UdpScanner::dumpPortListOpen() {
	return; // TODO
	printf("--- Start of portlist dump ---\n");
	struct port_element *pp;
	//pp = pfirst_port_element;
	//while(pp != plast_port_element) {
	//	if (pp->status) {
	//		printf("\t%d\t%d\n", pp->port, pp->status);
	//	}
	//	pp = pp->pnext;
	//}
	printf("\t%d\n", pp->port);
	printf("--- End of portlist dump ---\n");
}

int UdpScanner::sendPacket() {
	if (debug > 2) printf("UdpScanner::sendPacket: Called\n");




	// TODO this "finding" code is used by both scanner-tcp and scanner-udp.  move to scanner-port
	// First check if there's anything left to scan.  Return 0 if not.
	//
	// This involves moving onto the next host/port and checking if we've found
	// something that can be scanned.  It's a bit untidy, but it's important that
	// this func can be called even if nothing needs scanning.

	// Note the current port element
	// We need to note this so we can tell we've been completely round the port list
	struct port_element *pstart_port_element = pcurrent_host_element->pcurrent_port;
	
	// Increment the port pointer on this host
	pcurrent_host_element->pcurrent_port = pcurrent_host_element->pcurrent_port->pnext;
	int more_ports = 0;

	// Move onto next host
	pcurrent_host_element = pcurrent_host_element->pnext;

	// optimisation to avoid too much pointer defrerencing.  Hardly worth it.
	struct port_element *pcurhost_curport = pcurrent_host_element->pcurrent_port;

	while (!more_ports and pcurhost_curport != pstart_port_element) {
		// can we send to the current port in this portlist?
		if (pcurhost_curport->send_count < tries) {
			// we can send to this
			more_ports = 1;
		} else {
			// we can't send.  increment the port pointer on this host
			pcurrent_host_element->pcurrent_port = pcurhost_curport->pnext;

			// change to next host 
			pcurrent_host_element = pcurrent_host_element->pnext;
			pcurhost_curport = pcurrent_host_element->pcurrent_port;
		}
	}

	// Return 0 if there is nothing left to scan
	if (!(more_ports or pcurhost_curport->send_count < tries)) {
		return 0;
	}








	/* vars for sending */
	struct sockaddr_in sin;
	struct send_udp send_udp;
	struct pseudo_hdr_udp pseudo_hdr_udp;
	int send_socket;

	/* craft packet */
	send_udp.ip.ihl = 5;
	send_udp.ip.version = 4;
	send_udp.ip.tos = 0;
	send_udp.ip.tot_len = htons(sizeof(send_udp));
	send_udp.ip.frag_off = 0;
	send_udp.ip.ttl = getTTL();
	send_udp.ip.protocol = IPPROTO_UDP;
	send_udp.ip.check = 0;
	memcpy(&send_udp.ip.saddr, &src_ip, sizeof(src_ip));

	// send_udp.udp.source = htons(src_port);
	send_udp.udp.source = htons(getNextSourcePort());
	send_udp.udp.len = htons(sizeof(send_udp.udp)); // 8 is min length
	send_udp.udp.check = 0;

	send_udp.ip.daddr = pcurrent_host_element->ip.s_addr;
//			printf("saddr: %s\n", ipaddr_to_str(&send_icmp.ip.saddr));
	send_udp.udp.dest = htons(pcurrent_host_element->pcurrent_port->port);

	/* Now open the raw socket for sending */
	sin.sin_family = AF_INET;
	sin.sin_port = send_udp.udp.source;
	sin.sin_addr.s_addr = send_udp.ip.daddr;
	send_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(send_socket < 0)
	{
		perror("send socket cannot be open. Are you root?");
		exit(1);
	}
	
	int options;
	options = O_NONBLOCK | fcntl(send_socket, F_GETFL);
	if(fcntl(send_socket, F_SETFL, options) < 0) {
		perror("FCNTL");
		exit(1);
	}

	int one = 1;
	int *oneptr = &one;

	if (setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, oneptr, sizeof(one)) == -1) {
		printf("setsockopt: set IP_HDRINCL failed\n");
	}

		if (setsockopt(send_socket, SOL_SOCKET, SO_BROADCAST, oneptr, sizeof(one)) == -1)
	{
		printf("libnet_open_raw_sock: set SO_BROADCAST failed\n");
	}

	if(send_socket < 0)
	{
		perror("send socket cannot be open. Are you root?");
			exit(1);
	}

	/* From synhose.c by knight */
	pseudo_hdr_udp.source_address = send_udp.ip.saddr;
	pseudo_hdr_udp.dest_address = send_udp.ip.daddr;
	pseudo_hdr_udp.placeholder = 0;
	pseudo_hdr_udp.protocol = IPPROTO_UDP;
	pseudo_hdr_udp.tcp_length = send_udp.udp.len;
	/* end of sending setup */

	/* recalc checksum */
	send_udp.ip.check = 0;
	send_udp.udp.check = 0;
	send_udp.ip.check = in_cksum((unsigned short *)&send_udp.ip, sizeof(send_udp.ip));
	memcpy((char *)&pseudo_hdr_udp.udp, (char *)&send_udp.udp, sizeof(send_udp.udp));
	send_udp.udp.check = in_cksum((unsigned short *)&pseudo_hdr_udp, sizeof(pseudo_hdr_udp));

	/* send packet */
	if (verbose) printf("Sending packet to %s:%d\n", inet_ntoa(pcurrent_host_element->ip), pcurrent_host_element->pcurrent_port->port);
	sendto(send_socket, &send_udp, sizeof(send_udp), 0, (struct sockaddr *)&sin, sizeof(sin));
	close(send_socket);

	pcurrent_host_element->pcurrent_port->send_count++;
	return sizeof(send_udp);
}

// TODO implement "syncookie" identification of packets so we can run multiple scans at the same time
void UdpScanner::pcapCallback(Scanner *s, const struct pcap_pkthdr *pkthdr, const u_char *pkt) {
	int len = pkthdr->len;

	// static int packet_count = 0;
	struct iphdr* ip_hdr;          /* to get IP protocol data.  */
	struct udphdr* udp_hdr;        /* to get UDP protocol data. */
	struct icmphdr* icmp_hdr;        /* to get ICMP protocol data. */
	char src_ip[100], dst_ip[100];
	int type, code;
	int src_port, dst_port;

	/* strip off MAC header */
	char ip_raw[1500];
	// printf("pcap callback called with len %d\n", hw_head_len);
	// TODO This should work for ppp links when len=0 but doesn't
	// TODO isn't there a min(a,b) function?
	int mcpylen;  // min(1500, len - hw_head_len
	if (len - hw_head_len > 1500) {
		mcpylen = 1500;
	} else {
		mcpylen = len - hw_head_len;
	}
	memcpy(ip_raw, pkt + hw_head_len, mcpylen);
	
	/* we're only interested in UDP packets. */
	ip_hdr = (struct iphdr*)ip_raw;  /* the captured data is an IP packet. */
	/* lets get the src and dst addresses - translate from */
	/* network-byte-order binary data. */
	inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip));
	switch (ip_hdr->protocol) {
		case IPPROTO_UDP:
			/* lets get the port numbers - the payload of the IP packet is UDP.  */
			/* NOTE: in IP, the ihl (IP Header Length) field contains the number */
			/* of 4-octet chunks composing the IP packet's header.               */
			udp_hdr = (struct udphdr*)(ip_raw + ip_hdr->ihl * 4);
			src_port = ntohs(udp_hdr->source);  /* ports are in network byte order. */
			dst_port = ntohs(udp_hdr->dest);
	
			// printf("PACKET: [%d] src %s:%d, dst %s:%d\n", len, src_ip, src_port, dst_ip, dst_port);
			break;

		case IPPROTO_ICMP:
			icmp_hdr = (struct icmphdr*)(ip_raw + ip_hdr->ihl * 4);
			type = icmp_hdr->type;
			code = icmp_hdr->code;

			printf("%s:%d/%d [%s]", src_ip, type, code, icmp_type[type]);
			/* dest unreach */
			if ((code == 3) && (type == 3)) {
				printf(" [PORT_UNREACH]");
				struct iphdr* ip_hdr_embedded;
				ip_hdr_embedded = (struct iphdr*)(ip_raw + ip_hdr->ihl * 4 + 8);
				char src_ip_embedded[100], dst_ip_embedded[100];
				inet_ntop(AF_INET, &ip_hdr_embedded->saddr, src_ip_embedded, sizeof(src_ip_embedded));
				inet_ntop(AF_INET, &ip_hdr_embedded->daddr, dst_ip_embedded, sizeof(dst_ip_embedded));
				
				struct udphdr* udp_hdr_embedded = (struct udphdr*)(ip_raw + ip_hdr->ihl * 4 + 8 + ip_hdr_embedded->ihl * 4);
				printf(" (port %d)", ntohs(udp_hdr_embedded->dest));
				this->setPortClosed(ntohs(udp_hdr_embedded->dest));
				positive_response_count++;
			}
			printf("\n");

			break;

		default:
			printf("protocol in IP packet (0x%x) is not UDP or ICMP\n", ip_hdr->protocol);
			return;
	}
}

UdpScanner::~UdpScanner() {
	if (debug > 2) printf("UdpScanner: Destructing\n");
}
