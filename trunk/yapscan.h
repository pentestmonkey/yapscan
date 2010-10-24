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

#include <net/if.h> // ifreq
#include <stdio.h> // printf
#include <string.h> // strncpy
#include <arpa/inet.h> // sockaddr_in
#include <linux/if_ether.h> // ETH_ALEN
#include <stdlib.h> //exit
#include <linux/sockios.h> // SOIGC
#include <sys/ioctl.h> // ioctl
#include <pcap.h>
#include <linux/ip.h>  // iphdr
#include <linux/icmp.h> // icmphdr
// #include <linux/tcp.h> // tcphdr
// #include <linux/udp.h> // udphdr
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <fcntl.h> //O_NONBLK
#include <ctype.h> //isspace
#include <math.h> //floor
#include <netdb.h> //gethostbyname
#include <netdb.h> //getservbyport
#include <termios.h> // tcgetattr, tcsetattr (for turn off tty echo)
#include <time.h> // gmtime on debian

#ifdef HAVE_LIBCRYPTO
#  include <openssl/md5.h>
# else
#  include "md5.h"
#endif

/* prototypes */
char * hwaddr_to_str (unsigned char * str);
char * ipaddr_to_str (unsigned char * str);
pcap_t *mypcap_init(char *filter, char *device);
void recv_packets(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
int timeval_subtract ( struct timeval *result, struct timeval *x, struct timeval *y);
int syncookie (int src_ip, int dest_ip, int src_port, int dest_port);
unsigned short int getFirstPID(void);

#define MAXLINE 100
#define PCAP_FILTER_LEN 1000
#define MAXDEVICENAMELENGTH 20
#define MAXFILENAMELENGTH 300
#define MAXHOSTNAMELENGTH 50
#define MAXPORT 65535
#define MAXPORTNAMELENGTH 30

