/*
 * SyncClient.h
 *
 *  Created on: 2014年10月30日
 *      Author: czm
 */

#ifndef SYNCCLIENT_H_
#define SYNCCLIENT_H_

#include <string>
#include <queue>
#include <pthread.h>
using namespace std;

#include "SyncPackDef.h"

#define REC_BUF_MAX			4096

namespace wrtclient {

struct _queue_item{
	unsigned char*	data;
	int	length;
};

class SyncClient {
public:
	SyncClient(const char* remoteip, int port,const char* interface);
	virtual ~SyncClient();

	void start();
	void stop();

	void authClient(int gw_index,const  char* szMac,const char* szIp);
	void syncDhcp(unsigned char action,const char* szMac,const char* szIp,const char* szHost);
	void postApp(int gw_index,const char* appid,unsigned char* mac);
	void postCounter(int gw_index,unsigned char* ip,unsigned char* mac,unsigned long long sendbytes,unsigned long long recvbytes);
protected:
	bool connect();
	bool get_iface_mac(const char *ifname, unsigned char* result);
	void procRecv();
	void procSend();
	void constructHeader( _sync_pack_header* header,unsigned char type,unsigned short length);
	void addPackage(unsigned char* data,int len);

	void procAuthResp(unsigned char* data,int len);

	void closeSocket();

protected:
	int m_socket;
	string m_remoteip;
	int m_remoteport;
	unsigned char m_mac[6];

	bool m_bConnected;
	bool m_bTerminated;

	queue<struct _queue_item*>	m_lstPackage;
	pthread_mutex_t	m_mutex;

};

extern SyncClient* g_syncclient;

} /* namespace wrtclient */

#endif /* SYNCCLIENT_H_ */
