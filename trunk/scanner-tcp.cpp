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

#include "yapscan.h"
#include "scanner-tcp.h"

struct pseudo_hdr_tcp
{
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
        struct tcphdr tcp;
} pseudo_hdr_tcp;

/*
 * Constructor args:
 *
 * char *device - Device to listen of for returned packets
 * 
 */
TcpScanner::TcpScanner(char *device) {
	if (debug > 2) printf("TcpScanner: Constructing\n");
	setDevice(device);
	init();
}

void TcpScanner::init() {
	src_port = getFirstPID();
	port_count = 0;
	resolve_service_names = 1;

	/* craft template packet */
	template_packet.ip.ihl = 5;
	template_packet.ip.version = 4;
	template_packet.ip.tos = 0;
	template_packet.ip.tot_len = htons(sizeof(template_packet));
	template_packet.ip.frag_off = 0;
	template_packet.ip.ttl = getTTL(); // TODO need to update template after change TTL
	template_packet.ip.protocol = IPPROTO_TCP;
	template_packet.ip.check = 0;
	template_packet.tcp.ack_seq = 0;
	template_packet.tcp.res1 = 0;
	template_packet.tcp.doff = 5;
	template_packet.tcp.fin = 0;  // All TCP flags off by default
	template_packet.tcp.syn = 0;
	template_packet.tcp.rst = 0;
	template_packet.tcp.psh = 0;
	template_packet.tcp.ack = 0;
	template_packet.tcp.urg = 0;
	template_packet.tcp.res2 = 0;
	// template_packet.tcp.ece = 0;
	// template_packet.tcp.cwr = 0;
	template_packet.tcp.window = htons(512);
	template_packet.tcp.check = 0;
	template_packet.tcp.urg_ptr = 0;

	syn_flag = 0;
	rst_flag = 0;
	fin_flag = 0;
	psh_flag = 0;
	ack_flag = 0;
	urg_flag = 0;
	ece_flag = 0;
	cwr_flag = 0;
}

TcpScanner::TcpScanner() {
	if (debug > 2) printf("TcpScanner: Constructing\n");
	init();
}

void TcpScanner::setResolveServiceNames(int onoff) {
	if (onoff) {
		resolve_service_names = 1;
	} else {
		resolve_service_names = 0;
	}
}

void TcpScanner::setPcapFilter() {
	snprintf(pfilter, PCAP_FILTER_LEN, "tcp and dst host %s", src_ip_str);
}

void TcpScanner::setTcpFlag(int flag, int state) {
	switch(flag) {
		case 'N':
			rst_flag = 0;
			fin_flag = 0;
			psh_flag = 0;
			ack_flag = 0;
			urg_flag = 0;
			ece_flag = 0;
			cwr_flag = 0;
			break;
		case 'F':
			fin_flag = 1;
			break;
		case 'X':
			rst_flag = 1;
			fin_flag = 1;
			psh_flag = 1;
			ack_flag = 1;
			urg_flag = 1;
			ece_flag = 1;
			cwr_flag = 1;
			break;
		case 'A':
			ack_flag = 1;
			break;
		case 'S':
			syn_flag = 1;
			break;
		default:
			printf("ERROR: TcpScanner::setTcpFlag was passed a dodgy flag.  Shouldn't happen.\n");
			exit(1);
			break;
	}
}

// TODO
// - Return 0 ONLY when there is no packet to send (not on the last packet)
// - Make a hardcoded template packet to prevent having to craft it each time
int TcpScanner::sendPacket() {
	if (debug > 3) printf("TcpScanner::sendPacket: Called\n");
	// dumpPortList();

	// TODO findNextScannablePort(); // Updates pcurrent_host_element
	// First check if there's anything left to scan.  Return 0 if not.
	//
	// This involves moving onto the next host/port and checking if we've found
	// something that can be scanned.  It's a bit untidy, but it's important that
	// this func can be called even if nothing needs scanning.

#ifdef DEBUG
	if (!pcurrent_host_element) {
		printf("DEBUG WARNING: TcpScanner::sendPacket called with pcurrent_host_element = null\n");
	}
#endif

	// If all host elements have been deleted, we're done.
	if (!pcurrent_host_element) return 0;

#ifdef DEBUG
	if (!pcurrent_host_element->pcurrent_port) {
		printf("DEBUG WARNING: TcpScanner::sendPacket called with pcurrent_host_element->pcurrent_port = null\n");
	}
#endif
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
	int send_socket;

	// Make a new packet based on the template packet
	struct send_tcp packet;
	memcpy(&packet, &template_packet, sizeof(packet));

	// Fill in dynamic fields in new packet
	memcpy(&packet.ip.saddr, &src_ip, sizeof(src_ip));
	packet.tcp.source = htons(getNextSourcePort());
	packet.ip.daddr = pcurrent_host_element->ip.s_addr;
	packet.tcp.dest = htons(pcurrent_host_element->pcurrent_port->port);
	packet.tcp.seq = htonl(syncookie(packet.ip.saddr, packet.ip.daddr, packet.tcp.source, packet.tcp.dest));
	packet.tcp.fin = fin_flag;
	packet.tcp.syn = syn_flag;
	packet.tcp.rst = rst_flag;
	packet.tcp.psh = psh_flag;
	packet.tcp.ack = ack_flag;
	packet.tcp.urg = urg_flag;
	packet.tcp.res2 = ece_flag;
	// packet.tcp.ece = ece_flag;
	// packet.tcp.cwr = cwr_flag;
	packet.ip.ttl = getTTL();

	// Now open the raw socket for sending
	sin.sin_family = AF_INET;
	sin.sin_port = packet.tcp.source;
	sin.sin_addr.s_addr = packet.ip.daddr;
	send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	int options;
	options = O_NONBLOCK | fcntl(send_socket, F_GETFL);
	if(fcntl(send_socket, F_SETFL, options) < 0) {
		perror("FCNTL");
		exit(1);
	}

	int one = 1;
	int *oneptr = &one;

	// TODO Note what these socket options actually do
	if (setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, oneptr, sizeof(one)) == -1) {
		printf("setsockopt: set IP_HDRINCL failed\n");
	}

	if (setsockopt(send_socket, SOL_SOCKET, SO_BROADCAST, oneptr, sizeof(one)) == -1) {
		printf("libnet_open_raw_sock: set SO_BROADCAST failed\n");
	}

	// From synhose.c by knight
	pseudo_hdr_tcp.source_address = packet.ip.saddr;
	pseudo_hdr_tcp.dest_address = packet.ip.daddr;
	pseudo_hdr_tcp.placeholder = 0;
	pseudo_hdr_tcp.protocol = IPPROTO_TCP;
	pseudo_hdr_tcp.tcp_length = htons(sizeof(packet.tcp));

	// recalc checksum
	packet.ip.check = 0;
	packet.tcp.check = 0;
	packet.ip.check = in_cksum((unsigned short *)&packet.ip, sizeof(packet.ip));
	memcpy((char *)&pseudo_hdr_tcp.tcp, (char *)&packet.tcp, sizeof(pseudo_hdr_tcp.tcp));
	packet.tcp.check = in_cksum((unsigned short *)&pseudo_hdr_tcp, sizeof(pseudo_hdr_tcp));

	// send packet
	if (verbose > 1) printf("Sending packet to %s:%d\n", inet_ntoa(pcurrent_host_element->ip), pcurrent_host_element->pcurrent_port->port);
	sendto(send_socket, &packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin));
	close(send_socket);

	// Increment number of times this port has been scanned
	pcurrent_host_element->pcurrent_port->send_count++;

	// Delete from list if unless we're going to scan it again
	// TODO This is elegant, but REALLY hurts performance.
	//if (pcurrent_host_element->pcurrent_port->send_count >= tries) {
	//	deletePort(pcurrent_host_element, pcurrent_host_element->pcurrent_port);
	//}

	// Return the length of the packet we sent
	return sizeof(packet);
}

void TcpScanner::sendAck(__u32 src_ip, __u32 dest_ip, int src_port, int dest_port, __u32 seq_no, __u32 ack_no) {
	if (debug > 3) printf("TcpScanner::sendSynAck: Called\n");

	/* vars for sending */
	struct sockaddr_in sin;
	struct send_tcp packet;
	int send_socket;

	// Make a new packet based on the template packet
	memcpy(&packet, &template_packet, sizeof(packet));

	// Fill in dynamic fields in new packet
	packet.ip.saddr = htonl(src_ip);
	packet.ip.daddr = htonl(dest_ip);
	packet.tcp.source = htons(src_port);
	packet.tcp.dest = htons(dest_port);
	packet.tcp.seq = htonl(seq_no);
	packet.tcp.ack_seq = htonl(ack_no);
	packet.tcp.syn = 0;
	packet.tcp.ack = 1;

	/* Now open the raw socket for sending */
	sin.sin_family = AF_INET;
	sin.sin_port = packet.tcp.source;
	sin.sin_addr.s_addr = packet.ip.daddr;
	send_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(send_socket < 0) {
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

	if (setsockopt(send_socket, SOL_SOCKET, SO_BROADCAST, oneptr, sizeof(one)) == -1) {
		printf("libnet_open_raw_sock: set SO_BROADCAST failed\n");
	}

	if(send_socket < 0)
	{
		perror("send socket cannot be open. Are you root?");
			exit(1);
	}

	/* From synhose.c by knight */
	pseudo_hdr_tcp.source_address = packet.ip.saddr;
	pseudo_hdr_tcp.dest_address = packet.ip.daddr;
	pseudo_hdr_tcp.placeholder = 0;
	pseudo_hdr_tcp.protocol = IPPROTO_TCP;
	pseudo_hdr_tcp.tcp_length = htons(20);
	/* end of sending setup */

	/* recalc checksum */
	packet.ip.check = 0;
	packet.tcp.check = 0;
	packet.ip.check = in_cksum((unsigned short *)&packet.ip, 20);
	// memcpy((char *)&packet.tcp, (char *)&pseudo_hdr_tcp.tcp, 20);
	memcpy((char *)&pseudo_hdr_tcp.tcp, (char *)&packet.tcp, 20);
	packet.tcp.check = in_cksum((unsigned short *)&pseudo_hdr_tcp, 32);

	/* send packet */
	// if (verbose) printf("Sending packet to %s:%d\n", inet_ntoa(pcurrent_host_element->ip), pcurrent_port_element->port);
	src_ip = ntohl(src_ip); // dirty hack so ips are printed properly
	dest_ip = ntohl(dest_ip);
	printf("\tReplying with ACK from %s:%d to %s:%d SEQ=%x, ACK=%x\n", inet_ntoa(*(in_addr *)&src_ip), src_port, inet_ntoa(*(in_addr *)&dest_ip), dest_port, seq_no, ack_no);
	sendto(send_socket, &packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin));
	close(send_socket);
}

void TcpScanner::noMoreRetries(in_addr ip, unsigned short int port) {
	if (debug > 2) printf("noMoreRetries: Searching for %s:%d.  Just sent to ", inet_ntoa(ip), port);
	if (debug > 2) printf("%s:%d. \n", inet_ntoa(pcurrent_host_element->ip), pcurrent_host_element->pcurrent_port->port);
	// dumpPortList();

	struct host_element *h;
	int more_hosts = 1;
	int found_port = 0;
	int ports_tried = 0;

	// if pcurrent_host_element is null, we're nearing the end of
	// our scan and there are no port elements left in the list to
	// remove.  Our work is done.  Just return.
	if (!pcurrent_host_element) {
		return;
	}

	h = pcurrent_host_element;

	// search for ip in hostlist
	while (more_hosts and !found_port) {
//		if (debug > 3) printf("comparing candidate %s with target ip %s\n", inet_ntoa(*(in_addr *)(&h->ip.s_addr)), inet_ntoa(ip));
//		// TODO why are the IPs always the same on the XX line??!?!?!
#ifdef DEBUG
		if (debug > 3) printf("host cmp: %x vs %x\n", h->ip.s_addr, ip.s_addr);
		if (debug > 3) printf("XX comparing candidate %s with target ip %s\n", inet_ntoa(h->ip), inet_ntoa(ip));
#endif

		// if this is the right host
		if (h->ip.s_addr == ip.s_addr) {
			if (debug > 3) printf("Found host\n");
			struct port_element *p;
			int more_ports = 1;
			
			p = h->pcurrent_port;

			// search for port in hostlist of this port
			while (more_ports and !found_port) {
				ports_tried++;
				if (debug > 3) printf("\tcomparing candidate port %d with target port %d\n", p->port, port);

				// if this is the right port
				if (p->port == port) {
					if (debug > 3) printf("Found port\n");
					found_port = 1;

					// deletePort might free() it's first arg
					// so set h to a value that won't get clobbered
					// TODO what if we've only got 1 host and pprev = pnext?
					h = h->pprev;
					deletePort(h->pnext, p); // TODO does this work?
				} else {
					p = p->pprev;
					if (p == h->pcurrent_port) {
						if (debug > 3) printf("STRANGE: have searched all the ports on this host\n");
						more_ports = 0;
					}
				}
			}
		}
		
		// increment host pointer
		if (pcurrent_host_element and more_hosts) { // check incase we just deleted the last host
							    // only increment host if we haven't already
			// Is this the last host we need to check?
			if (h == pcurrent_host_element->pnext) {
				more_hosts = 0;
			} else {
				h = h->pprev;
			}
		}
	}
	if (debug > 2) printf("Search took %d steps\n", ports_tried);

	if (!found_port and verbose) {
		printf("STRANGE: Couldn't find %s:%d in my port list!\n", inet_ntoa(ip), port);
	}
}

void TcpScanner::pcapCallback(Scanner *s, const struct pcap_pkthdr *pkthdr, const u_char *pkt) {
	if (debug > 3) printf("TcpScanner::pcapCallback: Called\n");
	int len = pkthdr->len;

	// static int packet_count = 0;
	struct iphdr* ip_hdr;          /* to get IP protocol data.  */
	struct tcphdr* tcp_hdr;        /* to get TCP protocol data. */
	// struct icmphdr* icmp_hdr;        /* to get ICMP protocol data. */
	char src_ip[100], dst_ip[100];
	// int type, code;
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
	
	/* we're only interested in TCP packets. */
	ip_hdr = (struct iphdr*)ip_raw;  /* the captured data is an IP packet. */
	/* lets get the src and dst addresses - translate from */
	/* network-byte-order binary data. */
	inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip));
	switch (ip_hdr->protocol) {
		case IPPROTO_TCP:
			/* lets get the port numbers - the payload of the IP packet is TCP.  */
			/* NOTE: in IP, the ihl (IP Header Length) field contains the number */
			/* of 4-octet chunks composing the IP packet's header.               */
			tcp_hdr = (struct tcphdr*)(ip_raw + ip_hdr->ihl * 4);
			src_port = ntohs(tcp_hdr->source);  /* ports are in network byte order. */
			dst_port = ntohs(tcp_hdr->dest);
	
			// printf("PACKET: [%d] src %s:%d, dst %s:%d\n", len, src_ip, src_port, dst_ip, dst_port);
			if( (int)syncookie(ip_hdr->daddr, ip_hdr->saddr, tcp_hdr->dest, tcp_hdr->source) == (int)ntohl(tcp_hdr->ack_seq) - 1 or (int)syncookie(ip_hdr->daddr, ip_hdr->saddr, tcp_hdr->dest, tcp_hdr->source) == (int)ntohl(tcp_hdr->ack_seq)) {
				if(getShowClosedPorts() or !tcp_hdr->rst) {
					printf("%s:%d\t", src_ip, src_port);

					if(resolve_service_names) {
						struct servent *serv;
						serv = getservbyport(ntohs(src_port), "tcp");
						if (serv) {
							printf("%s\t", serv->s_name);
						} else {
							printf("unknown\t");
						}
					}

					/* Print out packet length */
					printf("Len=%d ", ntohs(ip_hdr->tot_len));

					/* Print out interesting IP options */
					printf("TTL=%d ", ip_hdr->ttl);
					// if (tcp_hdr->doff ^ 4) printf("DF "); //TODO this doesn't work
					printf("IPID=%d ", ntohs(ip_hdr->id));

					/* Print out interesting TCP options */
					printf("FLAGS=");
					tcp_hdr->syn ? printf("S") : printf("_");
					tcp_hdr->ack ? printf("A") : printf("_");
					tcp_hdr->rst ? printf("R") : printf("_");
					tcp_hdr->fin ? printf("F") : printf("_");
					tcp_hdr->psh ? printf("P") : printf("_");
					tcp_hdr->urg ? printf("U") : printf("_");
					tcp_hdr->res2 ? printf("E") : printf("_");
					tcp_hdr->res2 ? printf("C") : printf("_");
					printf(" ");
					printf("SEQ=0x%08x ", ntohl(tcp_hdr->seq));
					printf("ACK=0x%08x ", ntohl(tcp_hdr->ack_seq));
					printf("WIN=%d", ntohs(tcp_hdr->window));
					// MSS TODO
					// Other TCP options TODO
	/*					printf("Incomming ACK was %08x\n", ntohl(tcp_hdr->ack_seq));
					printf("Outgoing syn was therefore %08x\n", ntohl(tcp_hdr->ack_seq) - 1);
					printf("Syncookie would be %08x\n", syncookie(ip_hdr->daddr, ip_hdr->saddr, tcp_hdr->dest, tcp_hdr->source));*/
					/* print out any data on the packet */
//							printf("headers=%d, header_len=%d, total_len=%d, tcp_hdr->doff=%d\n", ip_hdr->ihl * 4 + tcp_hdr->doff * 4, ip_hdr->ihl * 4, ntohs(ip_hdr->tot_len), tcp_hdr->doff * 4);
					if (ip_hdr->ihl * 4 + tcp_hdr->doff * 4 < ntohs(ip_hdr->tot_len)) {
						printf(" DATA=\"");
						// for(int p = (int)ip_hdr + ip_hdr->ihl * 4 + tcp_hdr->doff * 4; p <= (int)ip_hdr + ntohs(ip_hdr->tot_len); p++) {
						for(char *p = (char *)ip_hdr + ip_hdr->ihl * 4 + tcp_hdr->doff * 4; p <= (char *)ip_hdr + ntohs(ip_hdr->tot_len); p++) {
							printf("%c", *p);
						}
						printf("\"");
					}
					printf("\n");
					positive_response_count++;
				}

				struct in_addr ip;
				ip.s_addr = ip_hdr->saddr;
				noMoreRetries(ip, src_port);
			} else {
				if (debug > 3) printf("TcpScanner::pcapCallback: Packet didn't have a valid syncookie\n");
			}

			break;
		default:
			printf("TcpScanner::pcapCallback: protocol in IP packet (0x%x) is not TCP\n", ip_hdr->protocol);
			return;
	}
}

TcpScanner::~TcpScanner() {
	if (debug > 2) printf("TcpScanner: Destructing\n");
}

