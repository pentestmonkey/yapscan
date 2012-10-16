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

// Description
// -----------
// Framework for performing custom scan types.  Basically the framework
// should take care of basic scanning (scanning at a given rate, with retries,
// reading hosts and ports in, displaying benchmarking stats, etc).
//
// This should hopefully make implementing new types of scan more straightforward
//

//TODO how to set EFENCE define from make file?
#include "yapscan.h"
#include "scanner.h"
#include "scanner-icmp.h"
#include "scanner-udp.h"
#include "scanner-tcp.h"

// From synhose.c by knight
int probes[4] = {
	ICMP_ECHO,
	ICMP_TIMESTAMP,
	ICMP_INFO_REQUEST,
	ICMP_ADDRESS
};

// These global vars are needed by main() and the usage() function
int debug = 0;
int verbose = 0;
unsigned int bandwidth_max = 1000000;
char device[MAXDEVICENAMELENGTH + 1];
const char *saddr = "127.0.0.1";
const char *scan_type = "\0";
int hw_head_len = 14; // ethernet
unsigned int tries = 1;
struct timeval rtt_tv;
int ttl = 64;
int show_closed_ports = 0;
int icmp_default_retries = 3;
unsigned int available_memory_kbytes = 150000;

// Function prototypes
void usage ();

// This string is automatically updated by RCS/CVS.  Do not edit.
char pversion_short[] = "0.7.7-beta";
char phomepage_url[] = "http://pentestmonkey.net/tools/yapscan";

// Main
int 
main ( int argc, char **argv) {

	// Create scanner instances
	IcmpScanner sI;
	TcpScanner sT;
	UdpScanner sU;
	Scanner *pScanner;

	int go;
	char port_range[2000]; memset(port_range, 0, 2000);
	float wait_time_sec;

	// These track which options have been used
	int hw_head_len_specified = 0;
	int portlist_specified = 0;
	int portfile_specified = 0;
	int tries_specified = 0;
	int type_specified = 0;
	
	int icmp_probe_test_echo = 0;
	int icmp_probe_test_timestamp = 0;
	int icmp_probe_test_info = 0;
	int icmp_probe_test_addrmask = 0;
	int icmp_probe_test_routersol = 0;
	int icmp_probe_type_specified = 0;
	show_closed_ports = 0;
	int resolve_service_names = 1;	
	int name_resultion = 1;

	// Set default RTT
	rtt_tv.tv_sec = 0;
	rtt_tv.tv_usec = 950000;

	char *prange_start = optarg;
	char prange_full[] = "1-65535";
	int more_ranges = 1;
	strncpy(device, "eth0", MAXDEVICENAMELENGTH);
	char hostfilename[MAXFILENAMELENGTH + 1];
	hostfilename[0] = '\0';
	char portfilename[MAXFILENAMELENGTH + 1];
	portfilename[0] = '\0';
	char source_ip[MAXHOSTNAMELENGTH + 1];
	source_ip[0] = '\0';
	int source_port_flag = 0;
	int source_port = 0;
	int more_types = 1;
	char types[101];
	char *ptype = types;
	unsigned int port_count = 0;
	unsigned int port_element_size = 62;
	unsigned int icmp_element_size = 120; // TODO this is a guess
	unsigned int memory_max;

	int portlist[MAXPORT + 1];
	for (int i = 0; i <= MAXPORT; i++) {
		portlist[i] = 0;
	}

	while ((go = getopt (argc, argv, "AFH:cdf:P:hs:vi:S:b:P:p:r:vt:R:T:VnNl:m:")) != EOF) {
		switch (go) {
			// No name resultion
			case 'n':
				name_resultion = 0;
				break;

			// Source port
			case 'l':
				source_port = atoi(optarg);
				source_port_flag = 1;
				break;

			// Show closed TCP ports
			case 'c':
				show_closed_ports = 1;
				break;

			// Debug level
			case 'd':
				debug++;
				break;

			// File of hosts to scan
			case 'f':
				strncpy(hostfilename, optarg, MAXFILENAMELENGTH);
				break;

			// File of ports to scan
			case 'P':
				strncpy(portfilename, optarg, MAXFILENAMELENGTH);
				portfile_specified = 1;
				break;

			// Help
			case 'h': 
				usage();
				break;

			// Version
			case 'V':
				printf("yapscan v%s ( %s )\n", pversion_short, phomepage_url);
				exit(0);
				break;

			// Hardware header length
			case 'H': 
				hw_head_len = atoi(optarg);	
				hw_head_len_specified = 1;	
				break;

			// Don't resolve service names
			case 'N': 
				resolve_service_names = 0;	
				break;

			// Scan type (-sI, -sS, etc.)
			case 's': 
				scan_type = optarg;
				break;

			// Source IP
			case 'S': 
				strncpy(source_ip, optarg, MAXHOSTNAMELENGTH);
				break;

			// Verbose
			case 'v':
				verbose = 1;
				break;

			// Bandwidth
			case 'b':
				char bandwidth_string[30];
				if (strlen(optarg) > 20) {
					printf("ERROR: Bandwidth string passed via -b is too long\n");
					exit(1);
				}
				strncpy(bandwidth_string, optarg, 20);
				switch (bandwidth_string[strlen(bandwidth_string) - 1]) {
					case 'k':
						bandwidth_string[strlen(bandwidth_string) - 1] = '\0';
						strncat(bandwidth_string, "000", 3);
						break;
					case 'K':
						bandwidth_string[strlen(bandwidth_string) - 1] = '\0';
						strncat(bandwidth_string, "000", 3);
						break;
					case 'm':
						bandwidth_string[strlen(bandwidth_string) - 1] = '\0';
						strncat(bandwidth_string, "000000", 6);
						break;
					case 'M':
						bandwidth_string[strlen(bandwidth_string) - 1] = '\0';
						strncat(bandwidth_string, "000000", 6);
						break;
					case 'g':
						bandwidth_string[strlen(bandwidth_string) - 1] = '\0';
						strncat(bandwidth_string, "000000000", 9);
						break;
					case 'G':
						bandwidth_string[strlen(bandwidth_string) - 1] = '\0';
						strncat(bandwidth_string, "000000000", 9);
						break;
					default:
						break;
				}

				if (index(bandwidth_string, '-')) {
					printf("ERROR: No minus signs allowed in bandwidth (-b) option\n");
					exit(1);
				}

				bandwidth_max = (unsigned int)atoll(bandwidth_string);

				// TODO: 4294967295 gives a horrible warning;
				//       warning: this decimal constant is unsigned only in ISO C90
				if (bandwidth_max > 2147483647) {
					printf("ERROR: Maximum allowed bandwidth is 2147483647\n");
					exit(1);
				}

				if (bandwidth_max <= 0) {
					printf("ERROR: Bandwidth must be greater than zero\n");
					exit(1);
				}

				break;

			// Memory
			case 'm':
				char memory_string[30];
				if (strlen(optarg) > 20) {
					printf("ERROR: Memory string passed via -m is too long\n");
					exit(1);
				}
				strncpy(memory_string, optarg, 20);
				switch (memory_string[strlen(memory_string) - 1]) {
					case 'k':
						memory_string[strlen(memory_string) - 1] = '\0';
						strncat(memory_string, "000", 3);
						break;
					case 'K':
						memory_string[strlen(memory_string) - 1] = '\0';
						strncat(memory_string, "000", 3);
						break;
					case 'm':
						memory_string[strlen(memory_string) - 1] = '\0';
						strncat(memory_string, "000000", 6);
						break;
					case 'M':
						memory_string[strlen(memory_string) - 1] = '\0';
						strncat(memory_string, "000000", 6);
						break;
					case 'g':
						memory_string[strlen(memory_string) - 1] = '\0';
						strncat(memory_string, "000000000", 9);
						break;
					case 'G':
						memory_string[strlen(memory_string) - 1] = '\0';
						strncat(memory_string, "000000000", 9);
						break;
					default:
						break;
				}

				if (index(memory_string, '-')) {
					printf("ERROR: No minus signs allowed in memory (-m) option\n");
					exit(1);
				}

				memory_max = (unsigned int)atoll(memory_string);

				// TODO: 4294967295 gives a horrible warning;
				//       warning: this decimal constant is unsigned only in ISO C90
				if (memory_max > 2147483647) {
					printf("ERROR: Maximum allowed memory is 2147483647\n");
					exit(1);
				}

				if (memory_max <= 0) {
					printf("ERROR: Bandwidth must be greater than zero\n");
					exit(1);
				}

				available_memory_kbytes = (unsigned int)(memory_max / 1000);

				if (memory_max <= 1000) {
					available_memory_kbytes = 1;
				}

				break;

			// Network Interface
			case 'i': 
				strncpy(device, optarg, MAXDEVICENAMELENGTH);
				break;

			// ICMP scan type
			case 't':
				#define MAXTYPELENGTH 100
				strncpy(types, optarg, MAXTYPELENGTH);
				ptype = types;
				more_types = 1;
				while (more_types) {
					// types will contain something like:
					// echo
					// time,addr
					// e,t,a
					//
					switch (*ptype) {
						case 'e':
							icmp_probe_test_echo  = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'E':
							icmp_probe_test_echo  = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'p':
							icmp_probe_test_echo  = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'P':
							icmp_probe_test_echo  = 1;
							icmp_probe_type_specified = 1;
							break;
						case 't':
							icmp_probe_test_timestamp = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'T':
							icmp_probe_test_timestamp = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'a':
							icmp_probe_test_addrmask = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'A':
							icmp_probe_test_addrmask = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'm':
							icmp_probe_test_addrmask = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'M':
							icmp_probe_test_addrmask = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'i':
							icmp_probe_test_info = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'I':
							icmp_probe_test_info = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'r':
							icmp_probe_test_routersol = 1;
							icmp_probe_type_specified = 1;
							break;
						case 'R':
							icmp_probe_test_routersol = 1;
							icmp_probe_type_specified = 1;
							break;
						case '-':
							icmp_probe_type_specified = 1;
							icmp_probe_test_echo  = 1;
							icmp_probe_test_timestamp = 1;
							icmp_probe_test_addrmask = 1;
							icmp_probe_test_info = 1;
							icmp_probe_test_routersol = 1;
							break;
						default:
							break;
					}

					// find the next ',' or end of line
					for (ptype = ptype; *ptype != ',' && *ptype != '\0'; ptype++);
					if(*ptype == '\0') {
						more_types = 0;
					} else {
						*ptype = '\0';
						ptype++;
					}
				}
				type_specified = 1;
				break;

			// Retries
			case 'r':
				tries = atoi(optarg) + 1;
				tries_specified = 1;
				break;

			// RTT
			case 'R': 
				wait_time_sec = atof(optarg);
				rtt_tv.tv_sec = (int)floorf(wait_time_sec);
				rtt_tv.tv_usec = (int)(1000000 * (wait_time_sec - floorf(wait_time_sec)));
				break;

			// Port range
			case 'p':
				// arg will be something like: 1-1024,6000-6064,8080,18264
				portlist_specified = 1;
				prange_start = optarg;

				// Check port list limit hasn't been exceeded
				if (strlen(prange_start) >= sizeof(port_range)) {
					printf("ERROR: Port range is tool long.  %zd character limit\n", sizeof(port_range));
					printf("       Use -P filename to read ports from a file instead\n");
					exit(1);
				}

				// Synonyms for 1-65535 are "-" and "all"
				if (!strcmp(prange_start, "all") or !strcmp(prange_start, "-")) {
					prange_start = prange_full;
				}
				
				// Save a copy
				strncpy(port_range, prange_start, sizeof(port_range));

				more_ranges = 1;
				char *pstring1_start;
				while (more_ranges) {
					// Replace first , with a null
					// pstring1_start will then point to the start of the first comma-separated item
					// (pstring2_start will later point to the sencond hypen-delimited item)
					// e.g. if we start with "1-1024,8080" we initially get
					//                    *pstring1_start = "1-1024"
					//                    *pstring2_start = "1024"
					for (pstring1_start = prange_start; *pstring1_start != ',' && *pstring1_start != '\0'; pstring1_start++);
					if(*pstring1_start == '\0') {
						more_ranges = 0;
					}
					*pstring1_start = '\0';

					// Check if we've been passed a service name like "http"
					servent *sp;
					sp = getservbyname(prange_start, NULL);
					if (sp != 0) {
						int port = htons(sp->s_port);
						// printf("DEBUG: Service %s has port %d\n", prange_start, port);
						portlist[port] = 1;

					// Otherwise we must have been passed a range like "80" or "1-1024".
					} else {
					
						// Should have commented this, really.  Errgghh...  TODO
						char *pstring2_start;
						int start_range;
						int end_range;

						// Find the first none digit in current string (string like "123" or "90-100")
						for (pstring2_start = prange_start; *pstring2_start >= '0' && *pstring2_start <= '9' && *pstring2_start != '\0'; pstring2_start++);
						
						// Range is illegal unless non-digit is null or "-"
						if(*pstring2_start != '-' && *pstring2_start != '\0') {
							printf("ERROR: Illegal port range specified: %s\n", prange_start);
							exit(1);
						}

						// Overwrite "-" with null
						*pstring2_start = '\0';
						
						// If a range wasn't specified (e.g. "80")
						// then pretend we got the range "80-80", so the for-loop still works.
						start_range = atoi(prange_start);
						if(pstring2_start < pstring1_start) {
							end_range = atoi(pstring2_start + 1);
						} else {
							end_range = atoi(prange_start);
						}

						// Sanity-check range
						if(start_range > end_range) {
							printf("ERROR: Illegal (backwards) port range specified\n");
							exit(1);
						}

						// Add whole range of ports to our list
						for(int port = start_range; port <= end_range; port++) {
							portlist[port] = 1;
						}
					}

					// Next comma-separated item
					prange_start = pstring1_start + 1;
				}
				break;

			// TTL
			case 'T':
				ttl = atoi(optarg);
				break;

			// Invalid option
			case '?':
				if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;
				break;

			default: 
				break;
		}
	}

	// Check a scan type was specified
	if (strlen(scan_type) == 0) {
		printf("WARNING: No scan type specified with -s flag.  Assuming TCP SYN scan: -sS.  -h for help\n");
		scan_type = "S";
	}

	if ((strlen(scan_type) != 1) || !( scan_type[0] == 'I' || scan_type[0] == 'S' || scan_type[0] == 'u' 
		|| scan_type[0] == 'A' || scan_type[0] == 'N' || scan_type[0] == 'F' || scan_type[0] == 'X')) {
		printf("ERROR: Scan type must be specified: -sS, -sI, -su, -sN, -sF, -sX or -sA.  See -h for help.\n");
		exit(1);
	}

	// A lot of the scan-setting-up is independent of scan type
	// we therefore define pScanner to point to the particular
	// type of scan we're doing.
	// 
	// I guess we can only call generic Scanner methods, but this
	// still saves us a lot of ugly code.
	int tcp_scan = 0;
	int udp_scan = 0;
	int icmp_scan = 0;
	switch(scan_type[0]) {
		case 'N':
			pScanner = &sT;
			sT.setTcpFlag('N', 1);
			tcp_scan = 1;
			break;
		case 'F':
			pScanner = &sT;
			sT.setTcpFlag('F', 1);
			tcp_scan = 1;
			break;
		case 'X':
			pScanner = &sT;
			sT.setTcpFlag('X', 1);
			tcp_scan = 1;
			break;
		case 'A':
			pScanner = &sT;
			sT.setTcpFlag('A', 1);
			tcp_scan = 1;
			break;
		case 'S':
			pScanner = &sT;
			sT.setTcpFlag('S', 1);
			tcp_scan = 1;
			break;
		case 'u':
			pScanner = &sU;
			udp_scan = 1;
			break;
		case 'I':
			pScanner = &sI;
			icmp_scan = 1;
			break;
		default:
			printf("ERROR: Unknown scan type \"%s\"\n", scan_type);
			exit(1);
			break;
	}

	// TCP port scan defaults to using "known" ports (like nmap)
	if(!(portlist_specified or portfile_specified) and (udp_scan or tcp_scan)) {
		printf("WARNING: Both -p and -P options missed.  Defaulting to \"-P known\"\n");
		strncpy(portfilename, "known", MAXFILENAMELENGTH);
		portfile_specified = 1;
	}

	// Default for ICMP scanning is 3 tries (2 retries)
	// (users can override this with -r, though)
	if(icmp_scan and !tries_specified) {
		tries = icmp_default_retries;
	}

	// Default icmp scan type is ping
	if (icmp_scan and !icmp_probe_type_specified) {
		printf("WARNING: -t option missed for ICMP scan.  Defaulting to ping scan: \"-t p\".\n");
		icmp_probe_test_echo  = 1;
		icmp_probe_type_specified = 1;
	}
	
	// 
	// Check for illegal/unwise option combinations
	// 
	if(show_closed_ports and !tcp_scan) {
		printf("ERROR: Illegal option combination.  -c can only be used with TCP scans.  -h for help.\n");
		exit(1);
	}

	if((portlist_specified or portfile_specified) and icmp_scan) {
		printf("ERROR: Illegal option combination.  -p and -P can't be used for ICMP scans.  Use -t.  -h for help.\n");
		exit(1);
	}
	
	if(portlist_specified and portfile_specified) {
		printf("WARNING: Port list specified on command line AND from a file.\n");
	}
	
	if(type_specified and !icmp_scan) {
		printf("ERROR: Illegal option combination.  -t can't be used for TCP scans.  Use -p.  -h for help.\n");
		exit(1);
	}

	if(tries <= 2 and icmp_scan) {
		printf("WARNING: At least 2 retries are recommended for ICMP scanning.  Set this with -r 2.\n");
	}

	if(bandwidth_max > 2000000) {
		printf("WARNING: High bandwidth testing can hammer the CPU and miss results.  Keeping\n");
		printf("         rates below 2000000 bits/sec should be safe on modern (1.5Ghz) systems\n");
	}
	
	// Check we have the necessary privs to run 
	// - need to be root to sniff and send raw packets
	if (geteuid() != 0) {
		printf("ERROR: Your EUID isn't 0.  You need to be root to run this.\n");
		exit(1);
	}

	// Set debug/verbose level
	pScanner->setDebugLevel(debug);
	pScanner->setVerboseLevel(verbose);

	// Turn off service name resolution if reqd
	if(tcp_scan) {
		sT.setResolveServiceNames(resolve_service_names);
	}

	if(udp_scan) {
		sU.setResolveServiceNames(resolve_service_names);
	}

	// Set number of probes (aka retires + 1) */
	pScanner->setTries(tries);

	// Set TTL
	pScanner->setTTL(ttl);

	// Set bandwidth 
	// (must to this before generating host list because
	// of the way the interpacket interval is recorded in
	// the host list.)
	pScanner->setBandwidthMax(bandwidth_max);

	// Set Name resultion option
	if (!name_resultion) {
		pScanner->setNameResolution(0);
	}
	
	// Set RTT
	pScanner->setRTT(&rtt_tv);

	// Set source IP (MUST be done before setDevice)
	if (strlen(source_ip) > 0) {
		pScanner->setSrcIP(source_ip);
	}

	// Set device
	pScanner->setDevice(device);

	// Set hardware header length (must come after setDevice)
	if (hw_head_len_specified) {
		pScanner->setHwHeadLen(hw_head_len);
	} else {
		pScanner->setHwHeadLenAuto();
	}

	//
	// Process scan-type specific options (i.e. ICMP, TCP or UDP)
	//

	// Read in ports from a file if one was specified.  Populate portlist array.
	// TODO drop privs before opening files?
	if ((tcp_scan or udp_scan) and portfile_specified) {
		FILE *inputfd;
		inputfd = fopen(portfilename, "r");
		// if the file is readable, open it
		if ((inputfd == NULL)) {
			if (!strcmp(portfilename, "-")) {
				inputfd = stdin;
			} else {
				// otherwise, open a file from /usr/local/share/yapscan if it's similar
				// TODO path should be a #DEFINE
				char newfilename[300];
				if (tcp_scan) {
					snprintf(newfilename, 300, "/usr/local/share/yapscan/ports-tcp-%s.txt", portfilename);
				} else {
					snprintf(newfilename, 300, "/usr/local/share/yapscan/ports-udp-%s.txt", portfilename);
				}
				inputfd = fopen(newfilename, "r");
				if ((inputfd == NULL)) {
					printf("ERROR: Can't open ports file for reading (tried %s and %s)\n", portfilename, newfilename);
					exit(1);
				}
			}
		}

		// We now have an open file
		char line[MAXLINE];
		char *cp;

		while (fgets(line, MAXLINE, inputfd)) {
			for (cp = line; !isspace((unsigned char)*cp) && *cp != '\0'; cp++)
				;
			*cp = '\0';
			int port = atoi(line);
			if (port >=0 and port <= 65535) {
				portlist[port] = 1;
			} else {
				printf("WARNING: Portlist contains invalid entry: %s.  Ignoring.\n", line);
			}
		}
	
		if (inputfd != stdin) fclose(inputfd);
	}

	// Count the number of ports we need to scan
	for (int port = 0; port <=65535; port++) {
		if (portlist[port]) {
			port_count++;
		}
	}

	// Count the number of ICMP types we're scanning
	int icmp_count = 0;
	if(icmp_scan) {
		if (icmp_probe_test_echo) {
			icmp_count++;
		}
		
		if (icmp_probe_test_timestamp) {
			icmp_count++;
		}
		
		if (icmp_probe_test_addrmask) {
			icmp_count++;
		}
		
		if (icmp_probe_test_info) {
			icmp_count++;
		}

		if (icmp_probe_test_routersol) {
			icmp_count++;
		}
	}

	// Set TCP specific options
	if(tcp_scan) {
		// Are we showing closed ports?
		sT.setShowClosedPorts(show_closed_ports);
	}
	
	// Calculate the number of hosts we can scan in parallel
	// This depends on the amount of memory we are allowed to use
	unsigned int max_hosts = 0;
	if (tcp_scan or udp_scan) {
		max_hosts = available_memory_kbytes * 1000 / (port_count * port_element_size);
	}
	if (icmp_scan) {
		// TODO this won't work for ICMP
		max_hosts = available_memory_kbytes * 1000 / (icmp_count * icmp_element_size);
	}

	// Set a sensisble lower limit for parallel hosts
	if (max_hosts <= 1) {
		max_hosts = 2;
	}

	//
	// Print out scan parameters
	// 
	printf("Starting Yapscan v%s ( %s )\n\n", pversion_short, phomepage_url);
	printf(" ---------------------------------------------------------- \n");
	printf("|                   Scan Information                       |\n");
	printf(" ---------------------------------------------------------- \n");

	// Print informaiton which applies to all types of tests
	//TODO netmask and default gw would also be helpful
	if (tcp_scan) {
		printf("Scan type: ......... TCP\n");
	} else if (udp_scan) {
		printf("Scan type: ......... UDP\n");
	} else if (icmp_scan) {
		printf("Scan type: ......... ICMP\n");
	}
	if (strlen(hostfilename)) printf("IPs File: .......... %s\n", hostfilename);
	printf("Interface: ......... %s\n", pScanner->getDevice());
	printf("Bandwidth limit: ... %u bits/sec\n", pScanner->getBandwidthMax());
	printf("Source address: .... %s\n", pScanner->getSourceAddress());
	if (debug) printf("HW Head Len: ....... %d\n", pScanner->getHwHeadLen());
	if (debug) printf("Pcap Filter: ....... %s\n", pScanner->getPcapFilter());
	printf("RTT: ............... %d.%d secs\n", (int)rtt_tv.tv_sec, (int)rtt_tv.tv_usec);
	printf("Retries: ........... %d\n", pScanner->getTries() - 1);
	printf("Max Memory: ........ %d KBytes (Scanning up to %d hosts at once)\n", available_memory_kbytes, max_hosts);
	
	// Print generic "Port Scanning" information
	if(tcp_scan or udp_scan) {
		if (strlen(port_range)) {
			printf("Port range: ........ %s\n", port_range);
		}
		if (strlen(portfilename)) {
			printf("Port file: ......... %s\n", portfilename);
		}
	}

	// Print UDP scanning information
	if(udp_scan) {
		printf("Port count: ........ %d\n", port_count);
	}

	// Print TCP scanning information
	if(tcp_scan) {
		printf("Port count: ........ %d\n", port_count);
		printf("Show closed ports .. %s\n", sT.getShowClosedPorts() ? "on" : "off");
	}

	// Print out the various types of ICMP scanning we're doing.
	if(icmp_scan) {
		printf("ICMP Probe Types: ..");
		int comma_needed = 0;
		if (icmp_probe_test_echo) {
			if (comma_needed) printf(",");
			printf(" %d (%s)", 8, icmp_type[8]);
			comma_needed = 1;
		}
		if (icmp_probe_test_timestamp) {
			if (comma_needed) printf(",");
			printf(" %d (%s)", 13, icmp_type[13]);
			comma_needed = 1;
		}
		if (icmp_probe_test_info) {
			if (comma_needed) printf(",");
			printf(" %d (%s)", 15, icmp_type[15]);
			comma_needed = 1;
		}
		if (icmp_probe_test_addrmask) {
			if (comma_needed) printf(",");
			printf(" %d (%s)", 17, icmp_type[17]);
			comma_needed = 1;
		}
		if (icmp_probe_test_routersol) {
			if (comma_needed) printf(",");
			printf(" %d (%s)", 10, icmp_type[10]);
			comma_needed = 1;
		}
		printf("\n");
	}

	unsigned int start_pos = 1;
	int current_line_number = 1;
	argv = &argv[optind];
	int more_hosts = 1;
	int first_chunk = 1;
	unsigned int host_total = 0;

	while (more_hosts) {
		more_hosts = 0;

	 	// Remove all hosts before populating pScanner
		if (tcp_scan) {
			sT.deleteAllHosts();
			sT.resetCounters();;
		}
		if (icmp_scan) {
			sI.deleteAllHosts();
		}
		if (udp_scan) {
			sU.deleteAllHosts();
			sT.resetCounters();;
		}

		// Read hosts in from command line
		while (*argv) {

			// Increment argv only once addHost returns 0.  This indicates that all
			// hosts in the range have been added.
			int status = pScanner->addHost(*argv, start_pos, max_hosts);
			if (status == 0) {
				// All hosts from range were successfully added
				start_pos = 0;
				argv++;
			} else if (status == -1) {
				printf("WARNING: Invalid host: %s.  Ignored.\n", *argv);
			} else {
				start_pos += status;
			}

			// Check if memory is full
 			if (pScanner->getHostCount() >= max_hosts) {
	 			more_hosts = 1;
	 			break;
	 		}
		}
	
		// Read a chunk of ips from a file if one was specified
		if (strlen(hostfilename)) {
			if (pScanner->getHostCount()) {
				printf("WARNING: Host list specified on command line AND from a file.  Hosts count from command line: %d\n", pScanner->getHostCount());
			}
			int status = pScanner->addHostsFromFile(hostfilename, current_line_number, max_hosts - pScanner->getHostCount());
			if (status != 0) {
				// not all hosts were added
				current_line_number += status;
			}
		}

		// Check if there are any more hosts left in the file
		if (pScanner->getHostCount() >= max_hosts) {
			more_hosts = 1;
		}

		// Check we have some hosts to scan 
		if (!pScanner->getHostCount()) {
			printf("ERROR: No hosts to scan!  Specify hosts on command line or use -f ips.txt.  -h for help.\n");
			exit(1);
		}

		// Add ports to hostlist for TCP/UDP scans
		if (tcp_scan) {
			for (int port = 0; port <= 65535; port++) {
				if (portlist[port]) {
					sT.addPort(port);
				}
			}
		}

		if (udp_scan) {
			for (int port = 0; port <= 65535; port++) {
				if (portlist[port]) {
					sU.addPort(port);
				}
			}
		}
	
		// Add icmp tests to hostlist
		if(icmp_scan) {
			if (icmp_probe_test_echo) {
				sI.addIcmpTest(8, 0);
			}
			
			if (icmp_probe_test_timestamp) {
				sI.addIcmpTest(13, 0);
			}
			
			if (icmp_probe_test_addrmask) {
				sI.addIcmpTest(17, 0);
			}
			
			if (icmp_probe_test_info) {
				sI.addIcmpTest(15, 0);
			}

			if (icmp_probe_test_routersol) {
				sI.addIcmpTest(10, 0);
			}
		}

		// Dump out the host list if required
		if (debug) pScanner->dumpHostList();

		// Set TCP specific options
		if(tcp_scan) {
			if (debug) sT.dumpPortList();
	
			if (source_port_flag) {
				sT.setCustomSourcePort(source_port);
			}
		}
	
		// Set UDP Scanner specific options
		/* TODO: Integrate this better with above TCP code */
		if(udp_scan) {
			if (debug) sU.dumpPortList();
	
			// Are we showing closed ports?
			sU.setShowClosedPorts(show_closed_ports);
	
			if (source_port_flag) {
				sU.setCustomSourcePort(source_port);
			}
		}

		// Print out scan start time
	        timeval now;
		struct tm *tm;
		char ascii_time[256];
		gettimeofday(&now, NULL);
		tm = gmtime(&now.tv_sec);
		strftime(ascii_time, sizeof(ascii_time), "%F %T %z", tm);
		pScanner->scanningChunk(1);
		if (first_chunk) printf("\n####### Scan of first %d hosts started at %s #########\n", pScanner->getHostCount(), ascii_time);
		if (!first_chunk) {
			printf("\n####### Scan of hosts %u to %u started at %s #########\n", host_total + 1, host_total + pScanner->getHostCount(), ascii_time);
		}
		host_total += pScanner->getHostCount();
		first_chunk = 0;
	
		// Turn off tty echo
		// We do this because when users press enter to see a progress 
		// update, they don't want to see an extra CR onscreen.
		struct termios initialrsettings, newrsettings;
		tcgetattr(fileno(stdin), &initialrsettings);
		newrsettings = initialrsettings;
		newrsettings.c_lflag &= ~ECHO;
		if(tcsetattr(fileno(stdin), TCSAFLUSH, &newrsettings) != 0) {
			printf("ERROR: Couldn't turn terminal echo off\n");
			exit(1);
		}

		// Start the scan
	 	pScanner->startScan();

		// Turn tty echo back on
		tcsetattr(fileno(stdin), TCSANOW, &initialrsettings);
	}
}

void 
usage () {
	printf("Yapscan v%s ( %s )\n\n", pversion_short, phomepage_url);
	printf("Usage: yapscan -s(I|S|u|N|F|X|A) [options] (-f ips.txt | host [host] ...)\n");
	printf("                                                            \n");
	printf("Hosts can be specified in the following ways:               \n");
	printf("         Lists:          10.0.0.1 10.0.0.2 10.0.0.3         \n");
	printf("         Ranges:         10.0.0.1-3 or 10.0.0.1-10.0.0.3    \n");
	printf("         Slash notation: 10.0.0.0/22                        \n");
	printf("         Files:          -f ips.txt                         \n");
	printf("                                                            \n");
	printf("options are:                                                \n");
	printf("         -s type   Set scan type to type                    \n");
	printf("                   Possible values are I, S, u, N, F, X, A  \n");
	printf("                   (like nmap) for ICMP, TCP SYN, UDP, Null,\n");
	printf("                   FIN, XMAS, ACK respectively              \n");
	printf("         -b n      Scan at n bits/sec (default: %d)         \n", bandwidth_max);
	printf("                   e.g. -b 32000, -b 32K, -b 1M             \n");
	printf("         -i int    Listen for replies on int (default: %s)  \n", device);
	// TODO printf("                   also set using env var YAPSCAN_IF        \n");
	printf("         -f file   Read ips to scan from file               \n");
	printf("         -S addr   Spoof source IP address                  \n");
	printf("         -R rtt    Set RTT as rtt (default: %d.%06ds)       \n", (int)rtt_tv.tv_sec, (int)rtt_tv.tv_usec);
	printf("                   Time to wait for replies at end of scan  \n");
	printf("         -r n      Set number of retries (default: %d)      \n", tries - 1);
	printf("         -H n      Set hw header len (default: autodetect)  \n");
	printf("         -T n      Set IP TTL to n (default: %d)            \n", ttl);
	printf("         -m n      Bytes of memory to use (default: %d)     \n", available_memory_kbytes * 1000);
	printf("         -d        Debugging information                    \n");
	printf("         -v        Verbose (not useful as present)          \n");
	printf("         -n        Don't try hostname resultion             \n");
	printf("         -N        Don't try service name resultion         \n");
	printf("         -h        Display this help message                \n");
	printf("                                                            \n");
	printf("ICMP Specific options (-sI):                                \n");
	printf("         -t n      Set ICMP probe type (default: none)      \n");
	printf("                   n=8, e, E, p or P for Echo Requests      \n");
	printf("                   n=10, r, R for Router Solicitation*      \n");
	printf("                   n=13, t or T for Timestamp Reqeusts      \n");
	printf("                   n=15, i or I for Information Reuqests    \n");
	printf("                   n=17, a, A, m or M for Addr Mask Requests\n");
	printf("                   n=- for all supported ICMP requests      \n");
	printf("         NB: Retries is set to %d for ICMP for reliability  \n", icmp_default_retries);
	printf("         * BUG: yapscan can send type 10 request but wont   \n");
	printf("           report replies yet.                              \n");
	printf("                                                            \n");
	printf("TCP Specific options  (-sS):                                \n");
	printf("         -p ports  Ports to scan (e.g. 80,443,6000-6063)    \n");
	printf("         -P file   File of ports (one per line)             \n");
	printf("         -c        Show closed ports (default: don't)       \n");
	printf("         -l port   Local (source) port to use               \n");
	printf("         WARNING: SYN scanning works well, but the other TCP\n");
	printf("                  scan types are mostly untested            \n");
	printf("                                                            \n");
	printf("UDP Specific options  (-su):                                \n");
	printf("         -p ports  Ports to scan (e.g. 80,443,6000-6063)    \n");
	printf("         -l port   Local (source) port to use               \n");
	printf("                                                            \n");
	printf("WARNING: UDP Scanning doesn't back off intelligently yet    \n");
	printf("         so can't reliably report open ports.  Only use it  \n");
	printf("         to confirm that hosts are firewalled.  Hence       \n");
	printf("         the lowercase u to be different from nmap.         \n");
	printf("                                                            \n");
	printf("Press Enter during the scan for an progress update          \n");
	printf("                                                            \n");
	printf("Also see yapscan-user-docs.pdf from distribution tar ball.  \n");
	exit(0);
}

