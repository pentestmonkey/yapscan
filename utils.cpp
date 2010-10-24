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
#include "scanner.h"

// Subtract the `struct timeval' values X and Y,
// storing the result in RESULT.
// Return 1 if the difference is negative, otherwise 0. 
// http://www.delorie.com/gnu/docs/glibc/libc_428.html
int
timeval_subtract ( struct timeval *result, struct timeval *x, struct timeval *y )
{
	// Perform the carry for the later subtraction by updating y.
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	// Compute the time remaining to wait.
	// tv_usec is certainly positive.
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	// Return 1 if result is negative.
	return x->tv_sec < y->tv_sec;
}

// Return md5(pid . src_ip . dest_ip . src_port . dest_port) 
// All are represented as 4 byte quantities in NETWORK byte order
#ifndef HAVE_LIBCRYPTO
int 
syncookie (int src_ip, int dest_ip, int src_port, int dest_port) {
        char pstring[20];
	md5_state_t mymd5;
	md5_byte_t pmd5sum[16];
	unsigned char *p;
	p = (unsigned char *)pstring;
	int pid = getpid();

	memcpy(p, &src_ip, 4);
	p += 4;
	memcpy(p, &dest_ip, 4);
	p += 4;
	memcpy(p, &src_port, 4);
	p += 4;
	memcpy(p, &dest_port, 4);
	p += 4;
	memcpy(p, &pid, 4);

	md5_init(&mymd5);
	md5_append(&mymd5, (md5_byte_t *)pstring, sizeof(pstring));
	md5_finish(&mymd5, pmd5sum);

	return *(long int *)pmd5sum;
}
#endif // HAVE_LIBCRYPTO

#ifdef HAVE_LIBCRYPTO
int 
syncookie (int src_ip, int dest_ip, int src_port, int dest_port) {
        char pstring[20];
	MD5state_st mymd5;
	unsigned char pmd5sum[16];
	unsigned char *p;
	p = (unsigned char *)pstring;
	int pid = getpid();

	memcpy(p, &src_ip, 4);
	p += 4;
	memcpy(p, &dest_ip, 4);
	p += 4;
	memcpy(p, &src_port, 4);
	p += 4;
	memcpy(p, &dest_port, 4);
	p += 4;
	memcpy(p, &pid, 4);

	MD5_Init(&mymd5);
	MD5_Update(&mymd5, (void *)pstring, sizeof(pstring));
	MD5_Final(pmd5sum, &mymd5);

	return *(long int *)pmd5sum;
}
#endif // HAVE_LIBCRYPTO

// Useful functions from arptool.c v0.1 by Cristiano Lincoln Mattos
char* 
hwaddr_to_str (unsigned char * str) {
	static char tmp[20];
	sprintf(tmp,"%02X:%02X:%02X:%02X:%02X:%02X",str[0],str[1],str[2],str[3],str[4],str[5]);
	return tmp;
}

char* 
ipaddr_to_str (unsigned char * str) {
	static char tmp[20];
	sprintf(tmp,"%d.%d.%d.%d",str[0],str[1],str[2],str[3]);
	return tmp;
}

unsigned short 
in_cksum(unsigned short *ptr, int nbytes)
{
        register long           sum;            /* assumes long == 32 bits */
        u_short                 oddbyte;
        register u_short        answer;         /* assumes u_short == 16 bits */

        /*
         * Our algorithm is simple, using a 32-bit accumulator (sum),
         * we add sequential 16-bit words to it, and at the end, fold back
         * all the carry bits from the top 16 bits into the lower 16 bits.
         */

        sum = 0;
        while (nbytes > 1)  {
                sum += *ptr++;
                nbytes -= 2;
        }

                                /* mop up an odd byte, if necessary */
        if (nbytes == 1) {
                oddbyte = 0;            /* make sure top half is zero */
                *((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
                sum += oddbyte;
        }

        /*
         * Add back carry outs from top 16 bits to low 16 bits.
         */

        sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;          /* ones-complement, then truncate to 16 bits */

        return(answer);

} /* end in_cksm() */

/* 
 * I wanted to be able to use class functions as pcap callback functions.
 *
 * pcap insists that the callback is void (*), so I couldn't.  This little helper
 * function keeps pcap happy by being of the correct type, then simply passes
 * the arguments onto the corresponding class function.
 *
 * To achieve this the u_char * argument to pcap dispatch MUST be the scanner object.
 */
void 
recv_packets(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt) {
	Scanner *s;
	s = (Scanner *)u;

	s->pcapCallback(s, pkthdr, pkt);
	return;
}

unsigned short int
getFirstPID(void) {
	return ((getpid() * time(NULL)) + 1024) % 65535;
}
