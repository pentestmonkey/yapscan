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

#include "scanner.h"
#include <errno.h>

Scanner::Scanner() {
	// default settings
	port_count = 0;
	debug = 0;
	verbose = 0;
	host_count = 0;
	positive_response_count = 0;
	device[0] = '\0';
	pfirst_host_element = 0;
	plast_host_element = 0;
	pcurrent_host_element = 0;
	packets_sent = 0;
	tries = 1;
	ttl = 64;
	src_ip_str[0] = '\0';
	name_resolution = 1;
	scanning_chunk = 0;

	// Make STDIN non-blocking.  Need to do this for the "read" in updateCompletionTime().
	int options = O_NONBLOCK | fcntl(1, F_GETFL);
	if(fcntl(1, F_SETFL, options) < 0) {
		perror("FCNTL");
		exit(1);
	}

}

void Scanner::scanningChunk(int yesorno) {
	if (yesorno) {
		scanning_chunk = 1;
	} else {
		scanning_chunk = 0;
	}
}

// get rid of one of the warning messages from -Weffc++
Scanner::Scanner(const Scanner&) {
	printf("ERROR: Scanner::Scanner(const Scanner&) not implemented yet\n");
	exit(1);
}

Scanner::~Scanner() {
	if (debug > 2) printf("Scanner: Destructing\n");
	while (pcurrent_host_element != 0) {
		deleteHost(pcurrent_host_element);
	}
}

void Scanner::setNameResolution(int flag) {
	name_resolution = flag;
}

int Scanner::getTTL() {
	return ttl;
}

void Scanner::setTTL(int newttl) {
	ttl = newttl;
}

// This is rubbish.  Think harder.
char* Scanner::getPcapFilter() {
	return(pfilter);
}

// How does this work?  Need it to get -Weffc++ working
//Scanner* operator=(const Scanner&) {
//	printf("ERROR: Scanner* operator=(const Scanner&) not implmented yet\n");
//	exit(1);
//}

void Scanner::setDebugLevel(int level) {
	debug = level;
}

int Scanner::getDebugLevel() {
	return debug;
}
	
void Scanner::setVerboseLevel(int level) {
	verbose = level;
}

int Scanner::getVerboseLevel() {
	return verbose;
}
	
// read value of positive_response
int Scanner::getPositiveResponseCount() {
	return positive_response_count;
}

// set value of hw_head_len (Hardware Header Length - e.g. 14 for ethernet)
void Scanner::setHwHeadLen(int len) {
	hw_head_len = len;
}

// read value of hw_head_len
int Scanner::getHwHeadLen() {
	return hw_head_len;
}

//
// detect the correct offset for start of IP packet
// in captured packets.  e.g. 14 for ethernet.
//
// Taken from SynScan Daemon 3.0-pre7 by MadMax & psychoid/tCl
//
int Scanner::setHwHeadLenAuto(void) {
	int datalink;
	datalink = pcap_datalink(sniffer);
  	switch (datalink)
	      {
	        case DLT_EN10MB:
		        setHwHeadLen(14);
			break;
		case DLT_NULL:
		case DLT_PPP:
			setHwHeadLen(4);
			break;
		case DLT_SLIP:
			setHwHeadLen(16); //apparently this works for ppp0 interface set up by pptp-linux/network-manager-pptp (debian).  auto-detect fails.  -H 16
			break;
		case DLT_RAW:
			setHwHeadLen(0);
			break;
		case DLT_SLIP_BSDOS:
		case DLT_PPP_BSDOS:
			setHwHeadLen(24);
			break;
		case DLT_ATM_RFC1483:
			setHwHeadLen(8);
			break;
		case DLT_IEEE802:
			setHwHeadLen(22);
			break;
		default:
			fprintf (stderr, "unknown datalink type (%d)", datalink);
			return (0);
		}
	return(1);
}

//
// Process any packets we've received since the last recv call
//
void Scanner::recvPackets() {
	if (debug > 3) printf("Scanner::recvPackets: Called\n");
	while(pcap_dispatch(sniffer, 0, recv_packets, (u_char *)this)) {
		pcap_dispatch(sniffer, 0, recv_packets, (u_char*)this);
	}
	while(pcap_dispatch(sniffer, 0, recv_packets, (u_char *)this)) {
		pcap_dispatch(sniffer, 0, recv_packets, (u_char *)this);
	}
}

//
// startScan scans the entire hostlist and returns when the scan
// is complete.  Basically it does:
//
// while (there are packets to send) {
// 	send a packet
// 	update estimated completion time (if user pressed enter)
// 	wait a bit, so we don't execeed bandwidth_max
// 	recv packets
// }
//
void Scanner::startScan() {
	if (debug > 2) printf("Scanner::startScan called\n");
	struct timeval starttime_tv;
	gettimeofday(&starttime_tv, NULL);

	int bytes_sent = 1;
	total_bytes_sent = 0;
	packets_sent = 0;

	while(bytes_sent) {
		// Send packet 
		bytes_sent = sendPacket();

		// Recalculate bandwidth
		total_bytes_sent += bytes_sent;
		if (bytes_sent) packets_sent++;
		struct timeval runtime_tv;
		struct timeval timenow_tv;
		gettimeofday(&timenow_tv, NULL);
		timeval_subtract(&runtime_tv, &timenow_tv, &starttime_tv);
		float runtime_sec = runtime_tv.tv_sec + (float)runtime_tv.tv_usec / 1000000;
		unsigned int total_bytes_sent_max = (unsigned int)floorf((bandwidth_max * runtime_sec) / 8);

		// Update user with estimated completion time
		updateCompletionTime();
		
		// If we've sent too many packets, wait for a bit
		if (total_bytes_sent_max < total_bytes_sent) {
			int total_bytes_sent_diff = total_bytes_sent - total_bytes_sent_max;
			float wait_time_sec = (float)total_bytes_sent_diff / (float)bandwidth_max;

			struct timeval interpacket_tv;
			interpacket_tv.tv_sec = (int)floorf(wait_time_sec);
			interpacket_tv.tv_usec = (int)(1000000 * (wait_time_sec - floorf(wait_time_sec)));
			select(0, NULL, NULL, NULL, &interpacket_tv);
		}

		recvPackets();
	}

	struct timeval runtime_tv;
	struct timeval timenow_tv;
	gettimeofday(&timenow_tv, NULL);
	timeval_subtract(&runtime_tv, &timenow_tv, &starttime_tv);
	float runtime_sec = runtime_tv.tv_sec + (float)runtime_tv.tv_usec / 1000000;
	float bandwidth = 8 * (float)total_bytes_sent / runtime_sec;

	/* wait for round trip time so we get all replies */
	select(0, NULL, NULL, NULL, &rtt_tv);
	
	recvPackets();

	timeval now;
	struct tm *tm;
	char ascii_time[256];
	gettimeofday(&now, NULL);
	tm = gmtime(&now.tv_sec);
	strftime(ascii_time, sizeof(ascii_time), "%F %T %z", tm);
	printf("####### Scan completed at %s #########\n", ascii_time);

	printf("%d positive results.\n\n%d packets (%d bytes) sent in %.2f secs.\nScan rate was: %.0f bits/sec | %.0f bytes/sec | %.0f packets/sec.\n", getPositiveResponseCount(), packets_sent, total_bytes_sent, runtime_sec, bandwidth, bandwidth / 8, packets_sent / runtime_sec);
	if (verbose) printf("%u packets received by pcap filter.  %u packets dropped by kernel.\n", getPcapPacketsProcessed(), getPcapPacketsDropped());
	if (unsigned int dropped_packets = getPcapPacketsDropped()) {
		printf("WARNING: Kernel dropped %u packets.  Results may have been missed.  Try reducing scan speed.\n", dropped_packets);
	}
}

// Prints an updated completion time if the user has pressed Enter.
void Scanner::updateCompletionTime(void) {
	char buf[100];
	int c = read(1, buf, 99);
	if (c >= 1) {
		printf("[%d%% complete] Scanning of this chunk will complete in less than %dm %ds.\n", getPercentComplete(), getRemainingScanTime() / 60, getRemainingScanTime() % 60);
	}
}

//
// RTT is only used to determine how long to wait for
// outstanding replies after the last probe has been sent.
//
// Might as well set it high (e.g. 1 sec) as we only wait
// for RTT once during execution.
//
void Scanner::setRTT(struct timeval *newrtt) {
	rtt_tv = *newrtt;
}

timeval Scanner::getRTT() {
	return rtt_tv;
}

// returns number of hosts in hostlist
unsigned int Scanner::getHostCount() {
	return(host_count);
}

// set no of tries scanner will make 
void Scanner::setTries(unsigned int newtries) {
	tries = newtries;
}

// return no of tries scanner will make 
int Scanner::getTries() {
	return tries;
}

// populates hostlist by reading in a file of ips
//   filename   is the file to read from 
//   start_pos  is the line number to start reading from (numbered from 1)
//   host_hosts is the maximum number of hosts to read before returning
//
// returns 0 is all hosts were added;
// returns a count of the the number of hosts added if they weren't all added
int Scanner::addHostsFromFile(char *filename, unsigned int start_pos, unsigned int max_hosts) {
	FILE *inputfd;
	char line[MAXLINE + 1];
	char *cp;
	unsigned int pos = 0;
	unsigned int hosts_added = 0;

	/* nmap */
	if (!strcmp(filename, "-")) {
		inputfd = stdin;
	} else {
		inputfd = fopen(filename, "r");
		if (!inputfd) {
			printf("ERROR: Failed to open host input file %s for reading\n", filename);
			exit(1);
		}
	}

	while (fgets(line, MAXLINE, inputfd)) {
		pos++;
		if (inputfd == stdin or pos >= start_pos) {
			for (cp = line; !isspace((unsigned char)*cp) && *cp != '\0'; cp++)
				;
			*cp = '\0';
			addHost(line);
			hosts_added++;
		}
		if (pos >= start_pos + max_hosts) {
			return hosts_added;
		}
	}

	if (inputfd != stdin)
	fclose(inputfd);

	return 0;
}

// delete an element from the linked list of all hosts
// return 0 if host was deleted
// return 1 if host was deleted and there are no more hosts
int Scanner::deleteHost(struct host_element *h) {
	if (!h) {
#ifdef DEBUG
		printf("DEBUG WARNING: Scanner::deleteHost was called with a null host_element\n");
#endif
		return(1);
	}

	if (debug > 2) printf("Scanner::deleteHost: Deleting host element %s\n", inet_ntoa(pcurrent_host_element->ip));

	// if this is the last element, set all global pointers to 0
	if (h->pnext == h and h->pprev == h) {
		if (debug > 2) printf("Scanner::deleteHost: There are no more host elements after this\n");
		pcurrent_host_element = 0;
		pfirst_host_element = 0;
		plast_host_element = 0;
		host_count--;
		return(1);
	
	// not the last element.  make sure global pointers will still be valid.
	} else {
		// if host is current_host, move current_host on
		if (h == pcurrent_host_element) {
			if (debug > 2) printf("Scanner::deleteHost called on current element\n");
			pcurrent_host_element = pcurrent_host_element->pnext;
		}
		
		// if host is first_host, move current_host on
		if (h == pfirst_host_element) {
			if (debug > 2) printf("Scanner::deleteHost called on first element\n");
			pfirst_host_element = pfirst_host_element->pnext;
		}
		
		// if host is last_host, move current_host on
		if (h == plast_host_element) {
			if (debug > 2) printf("Scanner::deleteHost called on last element\n");
			plast_host_element = plast_host_element->pprev;
		}
	}
	
	// join previous host to next host
	h->pprev->pnext = h->pnext;
	
	// join next host to previous host
	h->pnext->pprev = h->pprev;
#ifdef DEBUG	
	memset(h, 'H', sizeof(h));
#endif
	free(h);
	
	host_count--;
	// return success status
	return 0;
}

int Scanner::addHost(char *newhost) {
	return addHost(newhost, 0, 0);
}

//
// Adds an IP address to the hostlist.
//
// newhost is a string containing an IP, host or IP range.  If it's and IP range:
//    start_pos is the number of hosts to skip in the range
//    host_count is the number of hosts to add
//
// returns number of hosts added if not all could be added
// returns 0 if all hosts were added
// returns -1 if host could not be added
//
int Scanner::addHost(char *newhost, unsigned int start_pos, unsigned int max_hosts) {
	// printf("Addhost called with: %s, %u, %u\n", newhost, start_pos, max_hosts);
	struct in_addr ip;
	int resolved = 0;

	// If we were passed an IP then parse it as such
	if(!resolved and inet_aton(newhost, &ip)) {
		resolved = 1;
	}

	// otherwise check if we were passed a name we can resolve
	struct hostent *phostent;
	if(!resolved and name_resolution and (phostent = gethostbyname(newhost)) != 0) {
		ip = *(struct in_addr *)phostent->h_addr;
		resolved = 1;
	}

	if (resolved) {
		struct host_element *h;
		h = (struct host_element *)malloc(sizeof(host_element));
		h->pfirst_port    = 0;
		h->plast_port     = 0;
		h->pcurrent       = 0;
		h->pcurrent_port  = 0;
		h->rtt_tv.tv_sec  = 0;    // rtt is unset to  
		h->rtt_tv.tv_usec = 0;    //  start with
		h->inter_packet_interval_us = inter_packet_interval_us; // first approximation
		h->next_probe_time_tv.tv_sec  = 0;  // next probe is
		h->next_probe_time_tv.tv_usec = 0;  //   overdue
	
		host_count++;
		if (debug > 1) printf("Scanner::addHost: Adding host %s.  There are now %d hosts\n", newhost, host_count);
		h->ip = ip;
		if(!pfirst_host_element) {
			pfirst_host_element = h;
		}
	
		if(!plast_host_element) {
			plast_host_element = h;
		}
	
		h->pnext = pfirst_host_element;
		plast_host_element->pnext = h;
	
		h->pprev = plast_host_element;
		pfirst_host_element->pprev = h;
	
		plast_host_element = h;
	
		if(!pcurrent_host_element) {
			pcurrent_host_element = pfirst_host_element;
		}

		if (debug > 1) printf("Scanner::addHost: Added host %s\n", inet_ntoa(h->ip));
		
		return 0;
	}

	// We only reach this part of the code if we haven't been passed a 
	// single resolvable host (i.e. a hostname or IP address).
	//
	// We have been passed a IP range.  It could be in one of the following
	// formats
	//   1.2.3.0-63
	//   1.2.3.4-2.3.4.5
	//   1.2.3.64/26

	int processed_range = 0;
	unsigned int pos = 0;
	unsigned int hosts_added = 0;
	
	//////////////////////////////////////////////////////////////////
	//////// Were we passed an ip range like 1.2.3.64-127? ///////////
	//////////////////////////////////////////////////////////////////
	
	// ip ranges will have exactly one '-' in last octet, e.g. the
	// following are ok:
	// - 1.2.3.4-6
	// - 1.2.3.0-255
	// - 1.2.3.1-1
	// 
	// but the following aren't:
	// - 1.2.3-4.5
	// - 1.2.3-4.5-6

	char ip_range[32];
	char *cp;
	char *cp2;
	char *cp3;
	int start_range;
	int end_range;

	strncpy(ip_range, newhost, sizeof(ip_range));
	// check that we have numbers and dots followed by a -
	for (cp = ip_range; (*cp >= '0' && *cp <= '9') || *cp == '.'; cp++);

	if (*cp == '-') {

		*cp = '\0';
		cp++;
	
		// check the second part of the range is a number 
		// for (cp2 = cp; *cp2 >= '0' && *cp2 <= '9' && *cp2 != '\0'; cp2++);
		for (cp2 = cp; *cp2 >= '0' && *cp2 <= '9'; cp2++);
	
		if (*cp2 == '\0') {
			end_range = atoi(cp);
			
			// check if first part of range is a valid ip (e.g. "1.2.3.4" in "1.2.3.4-6";
			if (inet_aton(ip_range, &ip)) {
				cp--; cp--;
				for (cp3 = cp; *cp3 >= '0' && *cp3 <= '9' && cp3 > ip_range; cp3--);
				if (*cp3 == '.') {
					cp3++;
					start_range = atoi(cp3);
			
					// change string to end in a ".0"
					*cp3 = '0';
					cp3++;
					*cp3 = '\0';
			
					if(inet_aton(ip_range, &ip)) {
						for (int i = start_range; i <= end_range; i++) {
							//printf("adding: %x + %d = %x\n", ip, i, ntohl(ntohl(*(int *)&ip) + i));
							int ip_dec = ntohl(ntohl(*(int *)&ip) + i);
							char *ip_string = inet_ntoa(*(struct in_addr *)&ip_dec);
							//printf("ip: %s\n", ip_string);
							pos++;
							if (pos >= start_pos + max_hosts) {
								return hosts_added;
							}
							if (pos >= start_pos) {
								hosts_added++;
								addHost(ip_string);
							}
						}
						processed_range = 1;
					} else {
						printf("STRANGE: %s should be an IP but isn't.  This code should never be reached.\n", ip_range);
						//goto badrange;
					}
				}
			}
		}
	}

	if (processed_range) return 0;
	
	//////////////////////////////////////////////////////////////////
	//////// Were we passed an ip range like 1.2.3.64-127? ///////////
	//////////////////////////////////////////////////////////////////
	
	// TODO doesn't work for /32 ranges yet
	// maybe we were passed a range in a different format
	// following are ok:
	// - 1.2.3.4-1.2.3.6
	// - 1.2.3.0-1.2.4.255
	// 
	// but the following aren't:
	// - 1.2.3.0-4.255
	// - 1.2.3.0-255.255.255

	char *pend_ip = cp;

	strncpy(ip_range, newhost, sizeof(ip_range));
	// check that we have numbers and dots followed by a -
	for (cp = ip_range; (*cp >= '0' && *cp <= '9') || *cp == '.'; cp++);

	if (*cp == '-') {
	
		*cp = '\0';
		cp++;
	
		// check the second part of the range is an IP
		for (cp2 = cp; (*cp2 >= '0' && *cp2 <= '9') || *cp2 == '.'; cp2++);
	
		if (*cp2 == '\0') {
			pend_ip = cp;
			
			// check if first part of range is a valid ip (e.g. "1.2.3.4" in "1.2.3.4-6";
			struct in_addr ip_start;
			struct in_addr ip_end;
			//printf("start string: %s\n", ip_range);
			//printf("end string  : %s\n", pend_ip);
			if (inet_aton(ip_range, &ip_start) and inet_aton(pend_ip, &ip_end)) {
				unsigned int ip_start_dec = ntohl(*(int *)&ip_start);
				unsigned int ip_end_dec = ntohl(*(int *)&ip_end);
		
				//printf("start: %u, %08x\n", ip_start_dec, ip_start_dec);
				//printf("end:   %u, %08x\n", ip_end_dec, ip_end_dec);
		
				// check for backwards range;
				if (ip_end_dec < ip_start_dec) {
					printf("WARNING: Backwards IP range given.  Reversing.\n");
					int temp;
					temp = ip_end_dec;
					ip_end_dec = ip_start_dec;
					ip_start_dec = temp;
				}
		
				for (unsigned int ip_dec = ip_start_dec; ip_dec <= ip_end_dec; ip_dec++) {
					//printf("ip_dec: %d\n", ip_dec);
					int ip_dec_byteswap = ntohl(ip_dec);
					char *ip_string = inet_ntoa(*(struct in_addr *)&ip_dec_byteswap);
					//printf("ip: %s\n", ip_string);
					pos++;
					if (pos >= start_pos + max_hosts) {
						return hosts_added;
					}
					if (pos >= start_pos) {
						hosts_added++;
						addHost(ip_string);
					}
				}
		
				processed_range = 1;
			}
		}
	}

	if (processed_range) return 0;

	/////////////////////////////////////////////////////////
	// Check if we were passed a range is slash notation ////
	/////////////////////////////////////////////////////////

	strncpy(ip_range, newhost, sizeof(ip_range));
	char *netmask_ptr;
	if ((netmask_ptr = index(ip_range,'/'))) {
		*netmask_ptr = '\0';
		netmask_ptr++;
		int netmask_bits = atol(netmask_ptr);
		if (netmask_bits > 0 and netmask_bits <=32) {
			struct in_addr ip;
			struct hostent *phostent;
			if(!inet_aton(ip_range, &ip)) {
				if(name_resolution and (phostent = gethostbyname(ip_range)) != 0) {
					ip = *(struct in_addr *)phostent->h_addr;
					resolved = 1;
				}
			} else {
				resolved = 1;
			}
		
			if (resolved) {
				unsigned int ip_dec = ntohl(*(int *)&ip);
				int hostmask = 0xffffffff >> netmask_bits;
				int netmask = 0xffffffff ^ hostmask;
				if (!scanning_chunk and ip_dec & hostmask) {
					printf("WARNING: Network address wasn't used to specify range to be scanned\n");
				}
				ip_dec = ip_dec & netmask;
				hostmask++;
				for (int next_ip_dec = ip_dec; hostmask; next_ip_dec++) {
					int next_ip_dec_byteswap = ntohl(next_ip_dec);
					char *ip_string = inet_ntoa(*(struct in_addr *)&next_ip_dec_byteswap);
					pos++;
					if (pos >= start_pos + max_hosts) {
						return hosts_added;
					}
					if (pos >= start_pos) {
						hosts_added++;
						addHost(ip_string);
					}
					hostmask--;
				}

				processed_range = 1;
			}
		}
	} else {
		goto badrange;
	}

	if (processed_range) return 0;

	badrange:
		printf("WARNING: Failed to resolve %s\n", newhost);
		return -1;
}

// prints out the entire hostlist.  For debugging use. 
void Scanner::dumpHostList() {
	if (debug > 2) printf("Scanner::dumpHostList: Called\n");
	printf("Current Host Pointer: %lx\n", (unsigned long int)pcurrent_host_element);
	printf("--- Start of hostlist dump ---\n");
	struct host_element *ph;
	ph = pfirst_host_element;
	while(ph != plast_host_element) {
		printf("\t%s (pointer addr: %lx)", inet_ntoa(ph->ip), (unsigned long int)ph);
		if (ph == pcurrent_host_element) {
			printf(" <- current_host");
		}
		printf("\n");
		ph = ph->pnext;
	}

	// print out last host element - careful incase we're dumping an empty list
	if (ph) {
		printf("\t%s (pointer addr: %lx)", inet_ntoa(ph->ip), (unsigned long int)ph);
		if (ph == pcurrent_host_element) {
			printf(" <- current_host");
		}
		printf("\n");
	}
	printf("--- End of hostlist dump ---\n");
	if (debug > 2) printf("Scanner::dumpHostList: End of hostlist dump\n");
}

// alias for setDevice - see below 
void Scanner::setInterface(char *newdevice) {
	setDevice(newdevice);
}

// 
// Set interface on which pcap will listen for replies.
//
// This could be counter-intuitive if you are expecting packets
// to be SENT from this interface.  All sending is handled by
// the routing table, not by code in the scanner.
//
// From the interface we can automatically determine the
// source address.  Once this is done, we're in a position
// to set up the pcap filter.
//
void Scanner::setDevice(char *newdevice) {
	strncpy(device, newdevice, sizeof(device));
	if (verbose) printf("Scanner::SetDevice: Device set to %s\n", device);

	struct ifreq ifr;
	strncpy(ifr.ifr_name,device, sizeof(ifr.ifr_name));

	/* from arptool.c */
	// Setting up the sockets, interface, and getting data.
	int ret;
	int fd;
	//struct sockaddr_in sin;
	char hwaddr[ETH_ALEN];
	fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
	if (fd==-1) {
		perror("Socket: "); exit (1);
	}
	
	// Determine HW Addr.
	ret = ioctl(fd,SIOCGIFHWADDR,&ifr);
	if (ret==-1) {
		printf("ERROR: Can't find HW address for interface %s: %s\n", device, strerror(errno));
		exit(1);
	}
	memcpy(hwaddr,ifr.ifr_hwaddr.sa_data,ETH_ALEN);
	setSrcMAC(hwaddr_to_str((unsigned char *)hwaddr));
	
	initSrcIP();
	setPcapFilter();
                        
	//
	// Set up sniffer 
	// 
	
	int snaplen = 1500;
	int promisc = 0x100; // what is 0x100?
	int to_ms = 1000;    // timeout in milliseconds
	char errbuf[1000];   // store returned error - what length is best?
	struct bpf_program fcode;
	int optimize = 0;
	bpf_u_int32 netmask, localnet;

	// Set netmask.  we need this for pcap_compile
	pcap_lookupnet(device, &localnet, &netmask, errbuf);

	// Create a sniffer 
	sniffer = pcap_open_live(device, snaplen, promisc, to_ms, errbuf); // TODO why *?

	if (!sniffer) {
		printf("ERROR: Failed to start sniffer on %s: %s\n", device, errbuf);
		exit(1);
	}

	// Make sniffer behave like a non-blocking recv
	// Don't do this when using pcap_loop or it will busy-wait
	pcap_setnonblock(sniffer, 1, errbuf);

	// compile the filter.  set fcode.  we need this for pcap_setfilter
	pcap_compile(sniffer, &fcode, getPcapFilter(), optimize, netmask);

	// set the filter on the sniffer
	pcap_setfilter(sniffer, &fcode);
}

// initialises src_ip_str if need be
void Scanner::initSrcIP(void) {
	if (!strlen(src_ip_str)) {
		if (!strlen(getDevice())) {
			printf("ERROR: getSrcIPBin called, but device hasn't been set yet\n");
			exit(1);
		}

		struct ifreq ifr;
		strncpy(ifr.ifr_name,getDevice(), sizeof(ifr.ifr_name));
	
		/* from arptool.c */
		// Setting up the sockets, interface, and getting data.
		int ret;
		int fd;
		fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
		if (fd==-1) {
			perror("Socket: "); exit (1);
		}
		struct sockaddr_in sin;
		// Determine IP Addr.
		ret = ioctl(fd,SIOCGIFADDR,&ifr);
		if (ret==-1) {
			printf("ERROR: Can't get IP address for interface %s: %s\n", device, strerror(errno));
			exit (1);
		}
		memcpy(&sin,&ifr.ifr_addr,sizeof(struct sockaddr_in));
		setSrcIP(ipaddr_to_str((unsigned char *)&sin.sin_addr.s_addr));
	}
}

//
// return name of device (interface) that pcap is configured to
// listen on for replies.
//
char* Scanner::getDevice() {
	return(device);
}
	
// 
// set source ip for probes
//
void Scanner::setSrcIP(char *new_src_ip_str) {
	// if we weren't passed an IP, try resolving
	if(!inet_aton(new_src_ip_str, &src_ip)) {
		struct hostent *phostent;
		if(name_resolution and (phostent = gethostbyname(new_src_ip_str)) != 0) {
		// printf("Successfully resolved %s to %s\n", newhost, inet_ntoa(*(struct in_addr *)phostent->h_addr_list[0]));
		src_ip = *(struct in_addr *)phostent->h_addr;
		} else {
			printf("ERROR: Unable to resolve source ip %s\n", new_src_ip_str);
			exit(1);
		}
	}
	strncpy(src_ip_str, inet_ntoa(src_ip), sizeof(src_ip_str));
	if (verbose) printf("Scanner::SetSrcIP: Source IP set to %s\n", src_ip_str);
	setPcapFilter();
}

//
// set source MAC.  There is no point to doing this
// no code uses it (yet).
//
void Scanner::setSrcMAC(char *new_src_mac_str) {
	strncpy(src_mac_str, new_src_mac_str, sizeof(src_mac_str));
	if (verbose) printf("Scanner::SetSrcMAC: Source MAC set to %s\n", src_mac_str);
}

//
// return source ip used no the probes we're sending.
//
char* Scanner::getSourceAddress() {
	return(src_ip_str);
}

//
// set the maximum bandwidth we can use in bits per second
//
void Scanner::setBandwidthMax(unsigned int new_bandwidth_max) {
	bandwidth_max = new_bandwidth_max;
	// printf("about to do division: %d / %d\n", packet_size, bandwidth_max);
	inter_packet_interval_us = int(packet_size / bandwidth_max) * 1000000;
}

//
// returns max bandwidth we can use in bits per second
//
unsigned int Scanner::getBandwidthMax() {
	return(bandwidth_max);
}

// Return number of packets processed by pcap filter
unsigned int Scanner::getPcapPacketsProcessed() {
	struct pcap_stat ps_stats;
	pcap_stats(sniffer, &ps_stats);
	if ((pcap_stats(sniffer, &ps_stats)) < 0) {
		printf("WARNING: Couldn't get pcap stats: %s", pcap_geterr(sniffer));
	}
	return(ps_stats.ps_recv);
}

// Return number of packets processed by kernel during sniffing
unsigned int Scanner::getPcapPacketsDropped() {
	struct pcap_stat ps_stats;
	pcap_stats(sniffer, &ps_stats);
	if ((pcap_stats(sniffer, &ps_stats)) < 0) {
		printf("WARNING: Couldn't get pcap stats: %s", pcap_geterr(sniffer));
	}
	return(ps_stats.ps_drop);
}

