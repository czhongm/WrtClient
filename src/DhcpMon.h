/*
 * DhcpMon.h
 *
 *  Created on: 2014年10月11日
 *      Author: czm
 *
 *      用于监控DHCP服务器分配ip地址的信息，并上报云AC管理平台
 */

#ifndef DHCPMON_H_
#define DHCPMON_H_

namespace wrtclient {

#define DEFAULT_DHCPMON_SOCK	"/tmp/dhcpmon.sock"

class DhcpMon {
public:
	DhcpMon();
	virtual ~DhcpMon();

	void start();
	void stop(){m_bTerminated=false;};

	static void*	thread_handler(void *arg);
protected:
	bool m_bTerminated;
	int m_socket;
};

} /* namespace wrtclient */

#endif /* DHCPMON_H_ */
