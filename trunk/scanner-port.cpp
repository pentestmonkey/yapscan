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
#include "scanner-port.h"

/*
 * Constructor args:
 *
 * char *device - Device to listen of for returned packets
 * 
 */
PortScanner::PortScanner(char *device) {
	if (debug > 2) printf("PortScanner: Constructing\n");
	src_port = getFirstPID();
	show_closed_ports = 0;
	resolve_service_names = 1;
	custom_source_port_flag = 0;
	resetCounters();
	setDevice(device);
}

PortScanner::PortScanner() {
	if (debug > 2) printf("PortScanner: Constructing\n");
	src_port = getFirstPID();;
	show_closed_ports = 0;
	resolve_service_names = 1;
	custom_source_port_flag = 0;
	resetCounters();
}

void PortScanner::resetCounters() {
	host_port_count = 0;
	port_count = 0;
}

PortScanner::~PortScanner() {
	if (debug > 2) printf("PortScanner::~PortScanner: Called\n");
	host_element *h;
	int done = 0;
	while (!done) {
		h = pcurrent_host_element;
		if (h) {
			// deletePort will return 1 when all ports have been deleted.
			// it updates h->pcurrent_port after each deletion
			// it deletes h when all ports have been removed
			while (! deletePort(h, h->pcurrent_port)) {}
		} else {
			done = 1;
		}

		// deleteHost will return 1 when all hosts have been deleted.
		// it updates pcurrent_host_element after each deletion
//		if (deleteHost(h)) {
//			done = 1;
//		}
	}
}

void PortScanner::deleteAllHosts() {
	host_element *h;
	int done = 0;
	while (!done) {
		h = pcurrent_host_element;
		if (h) {
			// deletePort will return 1 when all ports have been deleted.
			// it updates h->pcurrent_port after each deletion
			// it deletes h when all ports have been removed
			while (! deletePort(h, h->pcurrent_port)) {}
		} else { 
			done = 1;
		}
	}
}

// Remove a port from a host's portlist (linked list)
// return 0 if port was deleted and there are more ports left
// return 1 if last port was deleted and the host along with it
int PortScanner::deletePort(host_element *h, port_element *p) {
	if (debug > 2) printf("Scanner::deletePort: Deleting port element %s:%d\n", inet_ntoa(h->ip), p->port);
	//printf("Scanner::deletePort: Deleting port element %s:%d\n", inet_ntoa(h->ip), p->port);
	//printf("Scanner::deletePort: Deleting port element %s:%d\n", inet_ntoa(h->ip), p->port);

	// dumpPortList();
	// do nothing if we were passed a null pointer
	if(!p or !h) {
#ifdef DEBUG
		if (!p) printf("DEBUG: PortScanner::deletePort: Called with null port pointer\n");
		if (!h) printf("DEBUG: PortScanner::deletePort: Called with null host pointer\n");
#endif
		return 1;
	}

	// if this is the last element, set all global pointers to 0
	if (p->pnext == p and p->pprev == p) {
		if (debug > 2) printf("Scanner::deletePort: There are no more port elements after this\n");
		h->pfirst_port = 0;
		h->plast_port = 0;
		h->pcurrent_port = 0;
		free(p);
		deleteHost(h);
		
		// update port count
		host_port_count--;

		return 1;
	
	// not the last element.  make sure global pointers will still be valid.
	} else {
		// NB: The following conditions are all independent (e.g. current could = last)
		
		// if host is current_host, move current_host on
#ifdef DEBUG
		if (debug > 3) printf("Checking p (%lx) against h->current_port (%lx), h->pfirst_port (%lx) and h->plast_port (%lx)\n", (unsigned long int)p, (unsigned long int)h->pcurrent_port, (unsigned long int)h->pfirst_port, (unsigned long int)h->plast_port);
#endif
		if (p == h->pcurrent_port) {
			if (debug > 2) printf("Scanner::deletePort called on current element\n");
			h->pcurrent_port = p->pnext;
		}
		
		// if host is first_host, move current_host on
		if (p == h->pfirst_port) {
			if (debug > 2) printf("Scanner::deletePort called on first element\n");
			h->pfirst_port = p->pnext;
		}

		// if host is last_host, move current_host on
		if (p == h->plast_port) {
			if (debug > 2) printf("Scanner::deletePort called on last element\n");
			h->plast_port = p->pprev;
		}
	}
	
	// join previous host to next host
	p->pprev->pnext = p->pnext;
	
	// join next host to previous host
	p->pnext->pprev = p->pprev;
	
#ifdef DEBUG
	memset(p, 'P', sizeof(p));
#endif
	free(p);
	
	// update port count
	host_port_count--;

	// return success status
	return 0;
}

void PortScanner::setResolveServiceNames(int onoff) {
	if (onoff) {
		resolve_service_names = 1;
	} else {
		resolve_service_names = 0;
	}
}


void PortScanner::setShowClosedPorts(int newval) {
	show_closed_ports = newval;
}

// Read port names from a file - not used yet TODO
void PortScanner::loadPortNamesFromFile(char *filename) {
	FILE *inputfd;
	char line[MAXLINE + 1];
	char servicename[MAXPORTNAMELENGTH + 1];
	unsigned short int port;
	char proto[4];

	/* nmap */
	if (!strcmp(filename, "-")) {
		inputfd = stdin;
	} else {
		inputfd = fopen(filename, "r");
		if (!inputfd) {
			printf("ERROR: Failed to open port name input file %s for reading\n", filename);
			exit(1);
		}
	}

	while (fgets(line, MAXLINE, inputfd)) {
		printf("Read line: %s\n", line);
		int matched = sscanf(line, "%30s %hu/%3s", servicename, &port, proto);
		if(matched == 3) {
			printf("desc=%s, port=%d, proto=%s\n", servicename, port, proto);
		}
		//for (cp = line; !isspace((unsigned char)*cp) && *cp != '\0'; cp++)
		//	;
		//*cp = '\0';
		//addPort(atoi(line));
	}
	if (inputfd != stdin)
	fclose(inputfd);
}

int PortScanner::getShowClosedPorts() {
	return show_closed_ports;
}
/* 
 * adds a port to be scanned
 *
 * returns:
 * 1: if port was added
 * 0: if not
 *
 */
int PortScanner::addPort(int port) {
	if (port <= 0 || port >65535) {
		return 0;
	}

	port_count++;
	int done = 0;
	if (!pfirst_host_element) {
		printf("ERROR001: PortScanner::addPort called while hostlist was empty.  It's a bug, sorry!\n");
		exit(1);
	}
	struct host_element *h = pfirst_host_element->pnext;

	// add this port the portlist of every host
	while (!done) {
		//printf("PortScanner::addPort: Adding port %d to ip %x\n", port, h->ip);
		host_port_count++;
		struct port_element *p;
		p = (struct port_element *)malloc(sizeof(port_element));
		p->port = port;
		p->send_count = 0;
		p->status = 1; // assume all ports are open until we find they're closed.
	
		if (debug > 4) printf("Scanner::addPort: Adding port %d.  There are now %d ports\n", port, getHostPortCount());
	
		if(!(h->pfirst_port)) {
			h->pfirst_port = p;
		}

		if(!(h->plast_port)) {
			h->plast_port = p;
		}
		
		p->pprev = h->plast_port;
		h->plast_port->pnext = p;

		p->pnext = h->pfirst_port;
		h->pfirst_port->pprev = p;
		
		h->plast_port = p;

		if(!h->pcurrent_port) {
			h->pcurrent_port = h->pfirst_port;
		}

		if (h == pfirst_host_element) {
			done = 1;
		} else {
			h = h->pnext;
		}
	}
	
	return 1;
}

// populates portlist by reading in a file of ports 
void PortScanner::addPortsFromFile(char *filename) {
	FILE *inputfd;
	char line[MAXLINE + 1];
	char *cp;

	/* nmap */
	if (!strcmp(filename, "-")) {
		inputfd = stdin;
	} else {
		inputfd = fopen(filename, "r");
		if (!inputfd) {
			printf("ERROR: Failed to open port input file %s for reading\n", filename);
			exit(1);
		}
	}

	while (fgets(line, MAXLINE, inputfd)) {
		for (cp = line; !isspace((unsigned char)*cp) && *cp != '\0'; cp++)
			;
		*cp = '\0';
		addPort(atoi(line));
	}

	if (inputfd != stdin) fclose(inputfd);
}

void PortScanner::dumpPortList() {
	int done = 0;
	if (!pfirst_host_element) {
		printf("ERROR002: PortScanner::dumpPortList called while hostlist was empty.  It's a bug, sorry!\n");
		exit(1);
	}
	struct host_element *h = pfirst_host_element->pnext;
	dumpHostList();
	printf("--- Start of portlist dump ---\n");
	while (!done) {
		printf("\tPortlist dump for %s:\n", inet_ntoa(h->ip));
		struct port_element *pp;
		pp = h->pfirst_port;
		// printf("Current port addr: %lx\n", (unsigned long int)h->pcurrent_port);
		while(pp != h->plast_port) {
			printf("\t\tport=%d, send_count=%d ptr addr=%lx", pp->port, pp->send_count, (unsigned long int)pp);
			if (pp == h->pcurrent_port) {
				printf(" <- current_port");
			}
			if (pp == h->pfirst_port) {
				printf(" <- first_port");
			}
			if (pp == h->plast_port) {
				printf(" <- last_port");
			}
			printf("\n");
			pp = pp->pnext;
		}
		printf("\t\tport=%d, send_count=%d ptr addr=%lx", pp->port, pp->send_count, (unsigned long int)pp);
		if (pp == h->pcurrent_port) {
			printf(" <- current_port");
		}
		if (pp == h->pfirst_port) {
			printf(" <- first_port");
		}
		if (pp == h->plast_port) {
			printf(" <- last_port");
		}
		printf("\n");
		//printf("--- End of portlist dump ---\n");

		// h++
		if (h == pfirst_host_element) {
			done = 1;
		} else {
			h = h->pnext;
		}
	}
	printf("--- End of portlist dump ---\n");
}

// Calculate most conservative esitmate of scan progress
int PortScanner::getPercentComplete() {
	if (debug > 2) printf("PortScanner::getPercentComplete: Called\n");
	return int(100 * packets_sent / (getPortCount() * getHostCount() * tries));
}

// Calculate the max time the rest of the scan could take
int PortScanner::getRemainingScanTime() {
	if (debug > 2) printf("PortScanner::getRemainingScanTime: Called\n");
	int bytes_per_packet = int(total_bytes_sent / packets_sent);
	return int(1 + getRTT().tv_sec + getRTT().tv_usec / 1000000 + (getPortCount() * getHostCount() * tries - packets_sent) * bytes_per_packet * 8 / getBandwidthMax());
}

int PortScanner::getHostPortCount() {
	return host_port_count;
}

int PortScanner::getPortCount() {
	return port_count;
}

void PortScanner::setSourcePort(int newport) {
	src_port = newport;
}

int PortScanner::getNextSourcePort() {
	if (custom_source_port_flag) {
		return custom_source_port;
	} else {
		src_port = src_port % 65535 + 1;
		return src_port;
	}
}

void PortScanner::setCustomSourcePort(int port) {
	custom_source_port_flag = 1;
	custom_source_port = port;
}
