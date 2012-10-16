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

#include "scanner-icmp.h"

// TODO
//
// Retries aren't implemented for ICMP scanning!!

// char *icmp_type[] = {
const char *icmp_type[] = {
 "ECHO_REPLY",
 "UNKNOWN-TYPE1",
 "UNKNOWN-TYPE2",
 "DEST_UNREACH",
 "SOURCE_QUENCH",
 "REDIRECT",
 "UNKNOWN-TYPE6",
 "UNKNOWN-TYPE7",
 "ECHO_REQUEST",
 "UNKNOWN-TYPE9",
 "ROUTER_SOLICITATION",
 "TIME_EXCEEDED",
 "PARAMETERPROB",
 "TIMESTAMP_REQUEST",
 "TIMESTAMP_REPLY",
 "INFO_REQUEST",
 "INFO_REPLY",
 "ADDRESS_REQUEST",
 "ADDRESS_REPLY"
};

/*
 * Constructor args:
 *
 * char *device - Device to listen of for returned packets
 * 
 */
IcmpScanner::IcmpScanner(char *device) {
	if (debug > 2) printf("IcmpScanner: Constructing\n");
	setDevice(device);
	scan_complete = 0;
	resetCounters();
}

IcmpScanner::IcmpScanner() {
	if (debug > 2) printf("IcmpScanner: Constructing\n");
	scan_complete = 0;
	resetCounters();
}

void IcmpScanner::resetCounters() {
	icmp_test_count = 0;
	host_test_count = 0;
}

void IcmpScanner::setPcapFilter() {
	snprintf(pfilter, PCAP_FILTER_LEN, "icmp and dst host %s", src_ip_str);
}

int IcmpScanner::getPercentComplete() {
	return int(100 * packets_sent / (icmp_test_count * getHostCount() * tries));
}

int IcmpScanner::getRemainingScanTime() {
	int bytes_per_packet = int(total_bytes_sent / packets_sent);
	return int(1 + getRTT().tv_sec + getRTT().tv_usec / 1000000 + (icmp_test_count * getHostCount() * tries - packets_sent) * bytes_per_packet * 8 / getBandwidthMax());
}

int IcmpScanner::sendPacket() {
	if (debug > 2) printf("IcmpScanner::sendPacket: Called\n");

	if (scan_complete) {
		return 0;
	}

	// First check if there's anything left to scan.  Return 0 if not.
	//
	// This involves moving onto the next host/port and checking if we've found
	// something that can be scanned.  It's a bit untidy, but it's important that
	// this func can be called even if nothing needs scanning.

	// Note the current port element
	// We need to note this so we can tell we've been completely round the port list
	
	// If all host elements have been deleted, we're done.
	if (!pcurrent_host_element) return 0;
	
#ifdef DEBUG
        if (!pcurrent_host_element) {
                printf("DEBUG WARNING: TcpScanner::sendPacket called with pcurrent_host_element = null\n");
        }

        if (!pcurrent_host_element->pcurrent) {
                printf("DEBUG WARNING: TcpScanner::sendPacket called with pcurrent_host_element->pcurrent = null\n");
        }
#endif

	struct icmp_element *pstart_icmp_element = pcurrent_host_element->pcurrent;
	
	// Increment the port pointer on this host
	pcurrent_host_element->pcurrent = pcurrent_host_element->pcurrent->pnext;
	int more_tests = 0;

	// Move onto next host
	pcurrent_host_element = pcurrent_host_element->pnext;

	// optimisation to avoid too much pointer defrerencing.  Hardly worth it.
	struct icmp_element *pcurhost_curicmp = pcurrent_host_element->pcurrent;

	while (!more_tests and pcurhost_curicmp != pstart_icmp_element) {
		// can we send to the current port in this portlist?
		if (pcurhost_curicmp->send_count < tries) {
			// we can send to this
			more_tests = 1;
		} else {
			// we can't send.  increment the port pointer on this host
			pcurrent_host_element->pcurrent = pcurhost_curicmp->pnext;

			// change to next host 
			pcurrent_host_element = pcurrent_host_element->pnext;
			pcurhost_curicmp = pcurrent_host_element->pcurrent;
		}
	}

	// Return 0 if there is nothing left to scan
	if (!(more_tests or pcurhost_curicmp->send_count < tries)) {
		return 0;
	}
	
	/* vars for sending */
	struct send_icmp send_icmp;
	struct sockaddr_in sin;
	int send_socket;

	/* setup for sending */
	int packet_size = sizeof(send_icmp);

	send_icmp.ip.ihl = 5;
	send_icmp.ip.version = 4;
	send_icmp.ip.tos = 0;
	send_icmp.ip.tot_len = htons(packet_size);
	send_icmp.ip.frag_off = 0;
	send_icmp.ip.ttl = getTTL();
	send_icmp.ip.protocol = IPPROTO_ICMP;
	send_icmp.ip.check = 0;
	memcpy(&send_icmp.ip.saddr, &src_ip, sizeof(src_ip));

	/* end of sending setup */
	
	sin.sin_family = AF_INET;
	send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(!send_socket) {
		perror("socket");
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

	// what does this do.  is it important?
	if (setsockopt(send_socket, SOL_SOCKET, SO_BROADCAST, oneptr, sizeof(one)) == -1)
	{
		printf("libnet_open_raw_sock: set SO_BROADCAST failed\n");
	}

	if(send_socket < 0)
	{
		perror("send socket cannot be open. Are you root?");
			exit(1);
	}
	
	send_icmp.ip.daddr = pcurrent_host_element->ip.s_addr;
	sin.sin_addr.s_addr = send_icmp.ip.daddr;
	
	// send_icmp.icmp.type = icmp_probe_type;
	send_icmp.icmp.type = pcurrent_host_element->pcurrent->type;
	// send_icmp.icmp.code = 0;
	send_icmp.icmp.code = pcurrent_host_element->pcurrent->code;
	int current_syncookie = syncookie(send_icmp.ip.saddr, send_icmp.ip.daddr, getpid(), getpid());

	/* Store the 16 high order bytes from the syncookie in id */
	send_icmp.icmp.un.echo.id = htons((unsigned short int)(current_syncookie % 65536));

	/* Store the 16 low order bytes from the syncookie in sequence */
	send_icmp.icmp.un.echo.sequence = htons((unsigned short int)(current_syncookie >> 16));

	/* recalc checksum */
	send_icmp.ip.check = 0;
	send_icmp.icmp.checksum = 0;
	send_icmp.ip.check = in_cksum((unsigned short *)&send_icmp.ip, sizeof(send_icmp.ip));

	// Now hack packets depending on their type
	char binary_packet[40];
	bcopy(&send_icmp, &binary_packet, packet_size); // length probably 28
	
	/* special case [read "hack"] for router solicitation */
	if (pcurrent_host_element->pcurrent->type == 10) {
		/* change ip header length */
		int new_packet_size = 28;
		send_icmp.ip.tot_len = htons(new_packet_size);
		send_icmp.ip.check = 0;
		send_icmp.ip.check = in_cksum((unsigned short *)&binary_packet, sizeof(send_icmp.ip));
			
		/* copy again now ip header is correct */
		bcopy(&send_icmp, &binary_packet, packet_size); // length probably 28
	
		/* fill in timestamp specific fields */
		binary_packet[24] = 0; // Reserved - must be 0
		binary_packet[25] = 0;
		binary_packet[26] = 0;
		binary_packet[27] = 0;
	
		/* update length so we copy right no of bytes to wire */
		packet_size = new_packet_size;
	}

	/* special case [read "hack"] for timestamp */
	if (pcurrent_host_element->pcurrent->type == 13) {
		/* change ip header length */
		int new_packet_size = 40;
		send_icmp.ip.tot_len = htons(new_packet_size);
		send_icmp.ip.check = 0;
		send_icmp.ip.check = in_cksum((unsigned short *)&binary_packet, sizeof(send_icmp.ip));
			
		/* copy again now ip header is correct */
		bcopy(&send_icmp, &binary_packet, packet_size); // length probably 28
	
		/* fill in timestamp specific fields */
		binary_packet[39] = 0; // Transmit timestamp
		binary_packet[38] = 0;
		binary_packet[37] = 0;
		binary_packet[36] = 0;
	
		binary_packet[35] = 0; // Receive timestamp
		binary_packet[34] = 0;
		binary_packet[33] = 0;
		binary_packet[32] = 0;
	
		struct timeval tv;     // Originate timestamp (msecs sinces midnight)
		gettimeofday(&tv, NULL);
		int msecs = htonl(1000 * (tv.tv_sec % (24*60*60)) + int(tv.tv_usec / 1000));
		memcpy(binary_packet + 28, &msecs, 4);

		/* update length so we copy right no of bytes to wire */
		packet_size = new_packet_size;
	}
	
	/* special case [read "hack"] for address mask */
	if (pcurrent_host_element->pcurrent->type == 17) {
		/* change ip header length */
		int new_packet_size = 32;
		send_icmp.ip.tot_len = htons(new_packet_size);
		send_icmp.ip.check = 0;
		send_icmp.ip.check = in_cksum((unsigned short *)&binary_packet, sizeof(send_icmp.ip));
			
		/* copy again now ip header is correct */
		bcopy(&send_icmp, &binary_packet, packet_size); // length probably 28
	
		/* fill in the source address mask */
		binary_packet[31] = 0; // Source ip = 0.0.0.0
		binary_packet[30] = 0;
		binary_packet[29] = 0;
		binary_packet[28] = 0;
	
		/* update length so we copy right no of bytes to wire */
		packet_size = new_packet_size;
	}

	// Calculate ICMP checksum
	binary_packet[23] = 0;
	binary_packet[22] = 0;
	*((unsigned short *)&binary_packet[22]) = in_cksum((unsigned short *)(&binary_packet[20]), packet_size - 20);

	/* send packet */
	if (verbose > 2) printf("Sending packet to %s:%s\n", inet_ntoa(pcurrent_host_element->ip), icmp_type[pcurrent_host_element->pcurrent->type]);
	sendto(send_socket, &binary_packet, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin));
	close(send_socket);

	// if (debug > 2) printf("pcurrent: %x, pcurrentnext, %x, first: %x, firstnext: %x, last: %x\n", (unsigned int)pcurrent_host_element, (unsigned int)pcurrent_host_element->pnext, (unsigned int)pfirst_host_element, (unsigned int)pfirst_host_element->pnext, (unsigned int)plast_host_element);

	// Increment number of times this icmp test has been done
	pcurrent_host_element->pcurrent->send_count++;
	
	// Delete from list if unless we're going to scan it again
	if (pcurrent_host_element->pcurrent->send_count >= tries) {
		deleteIcmpTest(pcurrent_host_element, pcurrent_host_element->pcurrent);
	}

	// If we just sent the last packet, record this fact
	//if(pcurrent_host_element == plast_host_element) {
	//	scan_complete = 1;
	//}

	// Move onto the next host
	//pcurrent_host_element = pcurrent_host_element->pnext;
	
	//After sending a packet ALWAYS return its size - even if it's the last packet
	return packet_size;

	/* 
	 * From RFC 792:
	 *
	 * Echo
	 * ----
	 * 
	 *     0                   1                   2                   3
	 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |     Type      |     Code      |          Checksum             |
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |           Identifier          |        Sequence Number        |
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |     Data ...
	 *     +-+-+-+-+-
	 *
	 * Timestamp or Timestamp Reply Message
	 * ------------------------------------
	 *
	 *     0                   1                   2                   3
	 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |     Type      |      Code     |          Checksum             |
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |           Identifier          |        Sequence Number        |
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |     Originate Timestamp                                       |
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |     Receive Timestamp                                         |
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |     Transmit Timestamp                                        |
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * Information Request or Information Reply Message
	 * ------------------------------------------------
	 *
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |     Type      |      Code     |          Checksum             |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |           Identifier          |        Sequence Number        |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * Address Mask Request (RFC 950)
	 * ------------------------------
	 *    
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |     Type      |      Code     |          Checksum             |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |           Identifier          |        Sequence Number        |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |                         Address Mask                          |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * Router Solicitation (RFC 1256)
	 * ------------------------------
	 *    
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |     Type      |      Code     |          Checksum             |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |                      Reserved (must be 0)                     |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */
}

void IcmpScanner::noMoreRetries(in_addr ip, unsigned char type, unsigned char code) {
	if (debug > 2) printf("noMoreRetries: Searching for %s:%hhu/%hhu.  Just sent to ", inet_ntoa(ip), type, code);
	if (debug > 2) printf("%s:%hhu/%hhu. \n", inet_ntoa(pcurrent_host_element->ip), pcurrent_host_element->pcurrent->type, pcurrent_host_element->pcurrent->code);

	struct host_element *h;
	int more_hosts = 1;
	int found_icmp_test = 0;
	int icmp_tests_tried = 0;
	int searching_for_host = 1;

        // if pcurrent_host_element is null, we're nearing the end of
        // our scan and there are no port elements left in the list to
        // remove.  Our work is done.  Just return.
        if (!pcurrent_host_element) {
	        return;
        }

	h = pcurrent_host_element;

	// search for ip in hostlist
	while (more_hosts and !found_icmp_test and searching_for_host) {
		// TODO when i write the printf as 1 line i get the same IP twice!
		if (debug > 2) printf("Comparing candidate %s with target ip ", inet_ntoa(h->ip));
		if (debug > 2) printf("%s\n", inet_ntoa(ip));

		// if this is the right host
		if (h->ip.s_addr == ip.s_addr) {
			searching_for_host = 0;
			// search for port in portlist
			if (debug > 2) printf("Found host\n");
			struct icmp_element *p;
			int more_icmp_tests = 1;
			
			p = h->pcurrent;

			while (more_icmp_tests and !found_icmp_test) {
				icmp_tests_tried++;
				if (debug > 2) printf("\tcomparing candidate type/code %hhu/%hhu with target type/code %hhu/%hhu\n", p->type, p->code, type, code);
				// if this is the right port
				if (p->type == type and p->code == code) {
					if (debug > 2) printf("Found type and code\n");
					found_icmp_test = 1;
					p->send_count = tries; // make sure we don't send to this port again
				} else {
					p = p->pnext;
					if (p == h->pcurrent) {
						if (debug > 2) printf("STRANGE: have searched all the icmp types on this host\n");
						more_icmp_tests = 0;
					}
				}
			}
		}
		
		// increment host pointer
		if (h == pcurrent_host_element->pnext) {
			more_hosts = 0;
		} else {
			h = h->pprev;
		}
	}
	if (debug > 2) printf("Search took %d steps\n", icmp_tests_tried);

	if (verbose and !found_icmp_test) {
		printf("STRANGE: Couldn't find %s:%hhu/%hhu in my icmp-type list!\n", inet_ntoa(ip), type, code);
	}
}

// adds an icmp type to each host in the host list
int IcmpScanner::addIcmpTest(unsigned char type, unsigned char code) {
	icmp_test_count++;
	struct host_element *h = pcurrent_host_element;
	int first_time_round = 1;

	while ( first_time_round or h != pcurrent_host_element) {
		host_test_count++;
		first_time_round = 0;
		if (debug > 3) printf("IcmpScanner::addIcmpTest: Adding test type=%hhu, code=%hhu to ip %s (%u tests in total)\n", type, code, inet_ntoa(h->ip), icmp_test_count);
		struct icmp_element *i;
		i = (struct icmp_element *)malloc(sizeof(icmp_element));
		i->type = type;
		i->code = code;
		i->send_count = 0;
	
		// if there are no icmp tests already
		if(!(h->pcurrent)) {
			// the hosts current icmp test is this new one
			h->pcurrent = i;
			
			// the next icmp test after this one is this one
			i->pprev = i;
	
			// the previous icmp test after this one is this one
			i->pnext = i;
	
		// otherwise add our element after the current one
		} else {
			// the next test after this new one is the one which follows the current one
			// (because we're sqeezing in netween current and current->next
			i->pnext = h->pcurrent->pnext;
//			printf("Setting pnext to %lx\n", (unsigned long int)h->pcurrent->pnext);
	
			// the test before this new one is the current one.
			i->pprev = h->pcurrent;
//			printf("Setting pprev to %lx\n", (unsigned long int)h->pcurrent);
			//dumpElement(i);
	
			// the pointers in the new element are now correct, but the
			// pointer if the current element and the one which follows it aren't
	
			h->pcurrent->pnext->pprev = i;
			h->pcurrent->pnext = i;
		}

		h = h->pnext;
	}
	//dumpIcmpList();

	return 1;
}

void IcmpScanner::dumpElement(icmp_element *i) {
	printf("i ......... %lx\n", (unsigned long int)i);
	printf("i->pnext .. %lx\n", (unsigned long int)i->pnext);
	printf("i->pprev .. %lx\n", (unsigned long int)i->pprev);
	printf("i->type ... %d\n", i->type);
	printf("i->code ... %d\n", i->code);
}

void IcmpScanner::pcapCallback(Scanner *s, const struct pcap_pkthdr *pkthdr, const u_char *pkt) {
	int len = pkthdr->len;

	//printf("Packet received\n");
	// static int packet_count = 0;
	struct iphdr* ip_hdr;          /* to get IP protocol data.  */
	struct icmphdr* icmp_hdr;        /* to get ICMP protocol data. */
	char src_ip[100], dst_ip[100];
	int type, code;
	// int src_port, dst_port;

	/* strip off MAC header */
	char ip_raw[1500];
	memcpy(ip_raw, pkt + hw_head_len, len - hw_head_len);
	
	/* we're only interested in TCP packets. */
	ip_hdr = (struct iphdr*)ip_raw;  /* the captured data is an IP packet. */
	/* lets get the src and dst addresses - translate from */
	/* network-byte-order binary data. */
	inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip));
	switch (ip_hdr->protocol) {
		case IPPROTO_ICMP:
			/* lets get the port numbers - the payload of the IP packet is TCP.  */
			/* NOTE: in IP, the ihl (IP Header Length) field contains the number */
			/* of 4-octet chunks composing the IP packet's header.               */
			icmp_hdr = (struct icmphdr*)(ip_raw + ip_hdr->ihl * 4);
			type = icmp_hdr->type;  /* ports are in network byte order. */
			code = icmp_hdr->code;
	
			/* if it's a reply that's not ours, then do nothing */
			if (type == 0 || type == 14 || type == 16 || type == 18) {
				/* Recalc syncookie to determine if it's a response to one of our probes */
				int current_syncookie = syncookie(ip_hdr->daddr, ip_hdr->saddr, getpid(), getpid());
				if(ntohs(icmp_hdr->un.echo.id) != (unsigned short int)(current_syncookie % 65536) and ntohs(icmp_hdr->un.echo.sequence) != (unsigned short int)(current_syncookie >> 16)) {
					break;
				} 
			} else {
				// Only report replies - not error messages.
				// This avoids seeing dest unreachable errors when ping scanning.
				break;
			}

			/* TODO Ignore this packet if we've seen a similar one before */
			
			/* Add to the count of open ports / ping responses / ... */
			positive_response_count++;
			
       	        	printf("%s:%d/%d [%s] ", src_ip, type, code, icmp_type[type]);
			/* dest unreach */
			if ((code == 3) && (type == 3)) {
				printf("\t[PORT_UNREACH]\t");
				struct iphdr* ip_hdr_embedded;
				ip_hdr_embedded = (struct iphdr*)(ip_raw + ip_hdr->ihl * 4 + 8);
				char src_ip_embedded[100], dst_ip_embedded[100];
				inet_ntop(AF_INET, &ip_hdr_embedded->saddr, src_ip_embedded, sizeof(src_ip_embedded));
				inet_ntop(AF_INET, &ip_hdr_embedded->daddr, dst_ip_embedded, sizeof(dst_ip_embedded));
				struct udphdr* udp_hdr_embedded = (struct udphdr*)(ip_raw + ip_hdr->ihl * 4 + 8 + ip_hdr_embedded->ihl * 4);
				printf("(port %d)", ntohs(udp_hdr_embedded->dest));
			}

			/* Print out packet length */
			printf("Len=%d ", ntohs(ip_hdr->tot_len));

			/* Print out interesting IP options */
			printf("TTL=%d ", ip_hdr->ttl);
			printf("IPID=%d ", ntohs(ip_hdr->id));

			/* reply */
			if (type == 0 || type == 14 || type == 16 || type == 18) {
				printf("ID=%d SEQ=%d ", ntohs(icmp_hdr->un.echo.id), ntohs(icmp_hdr->un.echo.sequence));
			}

			// needed for noMoreRetries call
			struct in_addr ip;
			ip.s_addr = ip_hdr->saddr;

			if (type == 0) {
				noMoreRetries(ip, 8, 0);
			}	

			if (type == 16) {
				noMoreRetries(ip, 15, 0);
			}

			/* timestamp reply */
			if (type == 14) {
				int endianness = 1; // endianness is correct
				
				time_t orig = ntohl(*(unsigned int *)(ip_raw + ip_hdr->ihl * 4 + 8));
				time_t recv = ntohl(*(unsigned int *)(ip_raw + ip_hdr->ihl * 4 + 12));
				time_t xmit = ntohl(*(unsigned int *)(ip_raw + ip_hdr->ihl * 4 + 16));

				// RFC 792 states that if the system cannot fill the Timestamp fields with
				// the seconds since midnight UTC, any value may be used, but the high bit
				// should be set to indicate that this has been done.
				//
				// std there means "standard" on the next line:
				unsigned int std = 1 ^ ((unsigned int)xmit >> 31); // 1 xor (high bit of xmit)

				printf("orig=0x%08x recv=0x%08x xmit=0x%08x", (unsigned int)orig, (unsigned int)recv, (unsigned int)xmit);

				// All timestamps should be standard and be less than 86400000 (24*60*60*1000)
				// If not server implementation might be broken, but still trying to tell us
				// the time
				if (!(std && (unsigned int)xmit < 86400000)) {
					
					// If a standard value is illegal, assume the endianness is messed up
					if (((unsigned int) xmit > 86400000) && std) {
						endianness = 0;
						xmit = ntohl(xmit);
						std = 1 ^ ((unsigned int)xmit >> 31);
					}

					// if a nonstandard value is legal when endianness is reversed assume
					// endianness was wrong initially
					if ((htonl(xmit) & 2147483647) < 86400000) {
						endianness = 0;
						xmit = ntohl(xmit);
						std = 1 ^ ((unsigned int)xmit >> 31);
					}

					// Check if we've fixed the problem
					if (std && (unsigned int)xmit < 86400000) {
					}
				}

				printf(" std=%u end=%d", std, endianness);

				if (std) {
					unsigned int msecs = xmit & 2147483647; // AND with 01111...111 to mask off top bit
					unsigned int hours = msecs / 3600000;
					msecs = msecs % 3600000;
					unsigned int mins = msecs / 60000;
					msecs = msecs % 60000;
					unsigned int secs = msecs / 1000;
					msecs = msecs % 1000;
					printf(" xmit-time=%02d:%02d:%02d.%03d delta=%0.3f", hours, mins, secs, msecs, ((float)xmit - orig) / 1000);
				}
				noMoreRetries(ip, 13, 0);
			}

			/* address mask reply */
			if (type == 18) {
				printf("MASK=%s", inet_ntoa(*(in_addr *)(ip_raw + ip_hdr->ihl * 4 + 8)));
				noMoreRetries(ip, 17, 0);
			}

			printf("\n");
//			noMoreRetries(ip, (unsigned char)type, (unsigned char)code);
			
			break;
		default:
			printf("protocol in IP packet (0x%x) is not ICMP\n", ip_hdr->protocol);
			return;
	}
}

int IcmpScanner::getIcmpProbeType() {
	return(icmp_probe_type);
}

void IcmpScanner::setIcmpProbeType(int new_probe_type) {
	icmp_probe_type = new_probe_type;
}

IcmpScanner::~IcmpScanner() {
	if (debug > 2) printf("IcmpScanner::~IcmpScanner: Called\n");
	host_element *h;
	int done = 0;
	while (!done) {
		h = pcurrent_host_element;
		if (h) {
			// deleteIcmpTest will return 1 when all ports have been deleted.
			// it updates h->pcurrent_port after each deletion
			while (! deleteIcmpTest(h, h->pcurrent)) {}
		} else {
			done = 1;
		}

		// deleteHost will return 1 when all hosts have been deleted.
		// it updates pcurrent_host_element after each deletion
		//if (deleteHost(h)) {
		//	done = 1;
		//}
	}
}

void IcmpScanner::deleteAllHosts() {
	host_element *h;
	int done = 0;
	while (!done) {
		h = pcurrent_host_element;
		if (h) {
			// deleteIcmpTest will return 1 when all ports have been deleted.
			// it updates h->pcurrent_port after each deletion
			while (! deleteIcmpTest(h, h->pcurrent)) {}
		} else {
			done = 1;
		}

		// deleteHost will return 1 when all hosts have been deleted.
		// it updates pcurrent_host_element after each deletion
		//if (deleteHost(h)) {
		//	done = 1;
		//}
	}
}

// Remove a port from a host's portlist (linked list)
// return 0 if port was deleted and there are more ports left
// return 1 if port was deleted and there are no ports left (i.e. it's now safe to delete host element)
int IcmpScanner::deleteIcmpTest(host_element *h, icmp_element *i) {
	if (debug > 2) printf("IcmpScanner::deleteIcmpTest: Deleting element %s:%d/%d\n", inet_ntoa(h->ip), i->type, i->code);
	// dumpIcmpList();
	// do nothing if we were passed a null pointer
	if(!i) {
#ifdef DEBUG
		printf("DEBUG WARNING: IcmpScanner::deleteIcmpTest was passed a null icmp_element\n");
#endif
		return 1;
	}

	// if this is the last element, set all global pointers to 0
	if (i->pnext == i and i->pprev == i) {
		if (debug > 2) printf("IcmpScanner::deleteIcmpTest: There are no more ICMP elements after this\n");
		h->pcurrent = 0;
#ifdef DEBUG
		memset(i, 'I', sizeof(i));
#endif
		free(i);
		deleteHost(h);

		// TODO update counter
		return 1;
	
	// not the last element.  make sure global pointers will still be valid.
	} else {
		// if host is current_host, move current_host on
		if (i == h->pcurrent) {
			if (debug > 2) printf("IcmpScanner::deleteIcmpTest called on current element\n");
			h->pcurrent = i->pnext;
		}
		
		// if host is first_host, move current_host on
		//if (i == h->pfirst) {
		//	if (debug > 2) printf("IcmpScanner::deleteIcmpTest called on first element\n");
		//	h->pfirst = i->pnext;
		//}
		
		// if host is last_host, move current_host on
		//if (i == h->plast) {
		//	if (debug > 2) printf("IcmpScanner::deleteIcmpTest called on last element\n");
		//	h->plast = i->pprev;
		//}
	}
	
	// join previous host to next host
	i->pprev->pnext = i->pnext;
	
	// join next host to previous host
	i->pnext->pprev = i->pprev;
	
	// free (TODO need to free port elements to really!)
	//printf("free1\n");
#ifdef DEBUG
	memset(i, 'I', sizeof(i));
#endif
	free(i);
	
	host_test_count--;
	
	// dumpIcmpList();
	// return success status
	return 0;
}

void IcmpScanner::dumpIcmpList() {
        int done = 0;
        struct host_element *h = pfirst_host_element->pnext;
        dumpHostList();
        while (!done) {
                printf("--- Start of icmplist dump for %s ---\n", inet_ntoa(h->ip));
                struct icmp_element *i;
                i = h->pcurrent->pnext;
                printf("Current icmp test addr: %lx\n", (unsigned long int)h->pcurrent);
                while(i != h->pcurrent) {
                        printf("\ttype=%d, code=%d, send_count=%d ptr addr=%lx prev=%lx next=%lx", i->type, i->code, i->send_count, (unsigned long int)i, (unsigned long int)i->pprev, (unsigned long int)i->pnext);
                        if (i == h->pcurrent) {
                                printf(" <- current");
                        }
                        printf("\n");
                        i = i->pnext;
                }
                printf("\ttype=%d, code=%d, send_count=%d ptr addr=%lx prev=%lx next=%lx", i->type, i->code, i->send_count, (unsigned long int)i, (unsigned long int)i->pprev, (unsigned long int)i->pnext);
                if (i == h->pcurrent) {
                        printf(" <- current");
                }
                printf("\n");
                printf("--- End of icmplist dump ---\n");

                // h++
                if (h == pfirst_host_element) {
                        done = 1;
                } else {
                        h = h->pnext;
                }
        }
}
