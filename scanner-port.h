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

#ifndef __SCANNERPORT__
#define __SCANNERPORT__

#include "yapscan.h"
#include "scanner.h"

struct port_element {
	 struct port_element *pnext;
	 struct port_element *pprev;
	 unsigned short int port;
	 unsigned int send_count; // count retries
	 unsigned char status;     // open, closed, filtered
	 struct timeval last_probe_time_tv;    // udp only
};

class PortScanner : public Scanner {
	public:
		PortScanner(char *device);
		PortScanner();
		~PortScanner();
		void setResolveServiceNames(int onoff);
		char* getPcapFilter();
		void setShowClosedPorts(int newval);
		void loadPortNamesFromFile(char *filename);
		int getShowClosedPorts();
		int addPort(int port);
		void addPortsFromFile(char *filename);
		void dumpPortList();
		int getHostPortCount();
		void setSourcePort(int newport);
		int getNextSourcePort();
		int deletePort(host_element *h, port_element *p);
		int getPercentComplete();
		int getRemainingScanTime();
		int getPortCount();
		void setCustomSourcePort(int port);
		void deleteAllHosts();
		void resetCounters();

	protected:
		int icmp_probe_type;
		int src_port;
		int port_count;
		int host_port_count;
		int resolve_service_names;
		int show_closed_ports;
		int custom_source_port_flag;
		int custom_source_port;
		//struct port_element *pfirst_port_element;
		//struct port_element *plast_port_element;
		//struct port_element *pcurrent_port_element;
};

#endif // __SCANNERPORT__
