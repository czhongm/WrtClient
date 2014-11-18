/*
 * SyncClient.cpp
 *
 *  Created on: 2014年10月30日
 *      Author: czm
 */

#include "SyncClient.h"

#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>

#include "EventLog.h"
#include "Wifidog.h"

namespace wrtclient {

SyncClient* g_syncclient = NULL;

SyncClient::SyncClient(const char* remoteip, int port, const char* interface) :
		m_remoteip(remoteip), m_remoteport(port) {
	UDT::startup();
	m_bConnected = false;
	m_bTerminated = false;
	m_mutex = PTHREAD_MUTEX_INITIALIZER;
	m_client = UDT::INVALID_SOCK;
	get_iface_mac(interface, m_mac);
}

SyncClient::~SyncClient() {
	pthread_mutex_lock(&m_mutex);
	while (!m_lstPackage.empty()) {
		struct _queue_item* pItem = m_lstPackage.front();
		free(pItem->data);
		delete (pItem);
		m_lstPackage.pop();
	}
	pthread_mutex_unlock(&m_mutex);

	UDT::close(m_client);
	UDT::cleanup();
}

/**
 * 取MAC地址
 */
bool SyncClient::get_iface_mac(const char *ifname, unsigned char* result) {
	int r, s;
	struct ifreq ifr;
	char *hwaddr;

	strcpy(ifr.ifr_name, ifname);

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		EventLog::trace(TRACE_ERROR, "get_iface_mac socket: %s", strerror(errno));
		return false;
	}

	r = ioctl(s, SIOCGIFHWADDR, &ifr);
	if (r == -1) {
		EventLog::trace(TRACE_ERROR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
		close(s);
		return false;
	}

	hwaddr = ifr.ifr_hwaddr.sa_data;
	close(s);
	result[0] = hwaddr[0] & 0xFF;
	result[1] = hwaddr[1] & 0xFF;
	result[2] = hwaddr[2] & 0xFF;
	result[3] = hwaddr[3] & 0xFF;
	result[4] = hwaddr[4] & 0xFF;
	result[5] = hwaddr[5] & 0xFF;

	EventLog::trace(TRACE_INFO, "MAC=%02x:%02x:%02x:%02x:%02x:%02x", result[0], result[1], result[2], result[3], result[4], result[5]);
	return true;
}

bool SyncClient::connect() {
	UDT::close(m_client);

	struct addrinfo hints, *local;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_socktype = SOCK_DGRAM;

	if (0 != getaddrinfo(NULL, "9431", &hints, &local)) {
		EventLog::trace(TRACE_ERROR, "incorrect network address.\n");
		return false;
	}

	m_client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);
	freeaddrinfo(local);

	//修改UDT参数

	int recvtimeout = 200;
	int sendtimeout = 200;
	int sendbuf = 1024000;
	int recvbuf = 1024000;
	int udpsendbuf = 102400;
	int udprecvbuf = 102400;

	UDT::setsockopt(m_client, 0, UDT_SNDTIMEO, &sendtimeout, sizeof(sendtimeout));
	UDT::setsockopt(m_client, 0, UDT_RCVTIMEO, &recvtimeout, sizeof(recvtimeout));
	UDT::setsockopt(m_client, 0, UDT_SNDBUF, &sendbuf, sizeof(sendbuf));
	UDT::setsockopt(m_client, 0, UDT_RCVBUF, &recvbuf, sizeof(recvbuf));
	UDT::setsockopt(m_client, 0, UDP_SNDBUF, &udpsendbuf, sizeof(udpsendbuf));
	UDT::setsockopt(m_client, 0, UDP_RCVBUF, &udprecvbuf, sizeof(udprecvbuf));

	char strPort[32];
	struct addrinfo *peer;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_socktype = SOCK_DGRAM;

	sprintf(strPort, "%d", m_remoteport);
	if (0 != getaddrinfo(m_remoteip.c_str(), strPort, &hints, &peer)) {
		EventLog::trace(TRACE_ERROR, "%s incorrect server/peer address. ", m_remoteip.c_str());
		return false;
	}
	// connect to the server, implict bind
	if (UDT::ERROR == UDT::connect(m_client, peer->ai_addr, peer->ai_addrlen)) {
		EventLog::trace(TRACE_ERROR, "can't connect %s: %s", m_remoteip.c_str(), UDT::getlasterror().getErrorMessage());
		return false;
	}
	freeaddrinfo(peer);
	m_bConnected = true;
	return true;
}

void SyncClient::start() {
	do {
		if (connect()) {
			bool bNeedRecon = false;
			while (!(m_bTerminated || bNeedRecon)) {
				pthread_mutex_lock(&m_mutex);
				while (!m_lstPackage.empty()) {
					struct _queue_item* pItem = m_lstPackage.front();
					int ss;

					if (UDT::ERROR == (ss = UDT::send(m_client, (char*) pItem->data, pItem->length, 0))) {
						EventLog::trace(TRACE_ERROR, "send:%s", UDT::getlasterror().getErrorMessage());
						bNeedRecon = true;
						break;
					} else {
						EventLog::trace(TRACE_INFO, "Send type=%d pack success.", ((struct _sync_pack_header*) (pItem->data))->type);
						usleep(100 * 1000);
					}
					free(pItem->data);
					delete (pItem);
					m_lstPackage.pop();
				}
				pthread_mutex_unlock(&m_mutex);

				if (!bNeedRecon) {
					int rs;
					int rcv_size;
					int var_size = sizeof(int);
					unsigned char data[1024];

					UDT::getsockopt(m_client, 0, UDT_RCVDATA, &rcv_size, &var_size);
					if (rcv_size > 0) {
						if (UDT::ERROR == (rs = UDT::recv(m_client, (char*) data, sizeof(data), 0))) {
							EventLog::trace(TRACE_ERROR, "recv:%s", UDT::getlasterror().getErrorMessage());
							break;
						} else {
							AppendRecBuf(data, rs);
							procRecv();
						}
					}
					usleep(100 * 1000);
				}
			}
		} else {
			usleep(300 * 1000);
		}
	} while (!m_bTerminated);
}

void SyncClient::procRecv() {
	do {
		//找寻头
		for(unsigned int i=0;i<m_nBufLen;i++){
			if(m_RecBuf[i]!=SYNCPACK_HEADTAG){
				EventLog::trace(TRACE_DEBUG,"Drop %d bytes",i);
				DecRecBuf(i);
				break;
			}
		}
		if(m_nBufLen<sizeof(struct _sync_pack_header)){
			EventLog::trace(TRACE_DEBUG, "Not enougth bytes,wait next loop");
			return;
		}
		struct _sync_pack_header* header = (struct _sync_pack_header*) m_RecBuf;
		unsigned int packlen = header->length + sizeof(struct _sync_pack_header);
		if ( packlen > m_nBufLen) {
			EventLog::trace(TRACE_DEBUG, "Not enougth bytes,wait next loop packlen=%d,buflen=%d",packlen,m_nBufLen);
			return;
		}
		if (memcmp(m_mac, header->mac, sizeof(m_mac)) != 0) {
			EventLog::trace(TRACE_DEBUG, "DROP package because MAC");
		}else{
			switch (header->type) {
			case SYNCPACK_TYPE_AUTH_RESP:
				procAuthResp();
				break;
			case SYNCPACK_TYPE_DHCP_RESP:
				break;
			}
		}
		DecRecBuf(packlen);
	} while (true);
}

void SyncClient::stop() {
	m_bTerminated = true;
}

void SyncClient::constructHeader(_sync_pack_header* header, unsigned char type, unsigned short length) {
	header->tag = SYNCPACK_HEADTAG;
	header->ver = SYNCPACK_VERSION;
	memcpy(header->mac, m_mac, sizeof(m_mac));
	header->type = type;
	header->length = length;
}

void SyncClient::addPackage(unsigned char* data, int len) {
	pthread_mutex_lock(&m_mutex);
	if (m_lstPackage.size() < MAX_QUEUE_LEN) {
		struct _queue_item* pItem = new (struct _queue_item);
		pItem->data = data;
		pItem->length = len;
		m_lstPackage.push(pItem);
	}
	pthread_mutex_unlock(&m_mutex);
}

void SyncClient::authClient(int gw_index, const char* szMac) {
	EventLog::trace(TRACE_DEBUG, "authClient gw_index=%d, mac=%s", gw_index, szMac);
	unsigned int mac[6];
	int datalen = sizeof(struct _sync_pack_header) + sizeof(struct _sync_pack_data_auth);
	unsigned char* data = (unsigned char*) malloc(datalen);
	memset(data, 0, datalen);
	struct _sync_pack_header* header = (struct _sync_pack_header*) data;
	constructHeader(header, SYNCPACK_TYPE_AUTH, sizeof(struct _sync_pack_data_auth));
	struct _sync_pack_data_auth* authdata = (struct _sync_pack_data_auth*) (data + sizeof(struct _sync_pack_header));
	authdata->gw_index = gw_index;
	sscanf(szMac, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	for (int i = 0; i < 6; i++) {
		authdata->mac[i] = mac[i];
	}
	addPackage(data, datalen);
}

void SyncClient::syncDhcp(unsigned char action, const char* szMac, const char* szIp, const char* szHost) {
	unsigned int mac[6];
	unsigned int ip[4];
	int datalen = sizeof(struct _sync_pack_header) + sizeof(struct _sync_pack_data_dhcp);
	unsigned char* data = (unsigned char*) malloc(datalen);
	memset(data, 0, datalen);
	struct _sync_pack_header* header = (struct _sync_pack_header*) data;
	constructHeader(header, SYNCPACK_TYPE_DHCP, sizeof(struct _sync_pack_data_dhcp));
	struct _sync_pack_data_dhcp* dhcpdata = (struct _sync_pack_data_dhcp*) (data + sizeof(struct _sync_pack_header));
	dhcpdata->action = action;
	sscanf(szMac, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	//memcpy(dhcpdata->mac, mac, sizeof(dhcpdata->mac));
	for (int i = 0; i < 6; i++) {
		dhcpdata->mac[i] = mac[i];
	}
	sscanf(szIp, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]);
	//memcpy(dhcpdata->ip, ip, sizeof(dhcpdata->ip));
	for (int i = 0; i < 4; i++) {
		dhcpdata->ip[i] = ip[i];
	}

	memcpy(dhcpdata->hostname, szHost, strlen(szHost));
	EventLog::trace(TRACE_DEBUG, "sync Dhcp ip=%s, mac=%s,hostname=%s", szIp, szMac, szHost);
	addPackage(data, datalen);
}

void SyncClient::postApp(int gw_index, const char* appid, const char* szMac) {
	unsigned int mac[6];
	int datalen = sizeof(struct _sync_pack_header) + sizeof(struct _sync_pack_data_app);
	unsigned char* data = (unsigned char*) malloc(datalen);
	memset(data, 0, datalen);
	struct _sync_pack_header* header = (struct _sync_pack_header*) data;
	constructHeader(header, SYNCPACK_TYPE_APP, sizeof(struct _sync_pack_data_app));
	struct _sync_pack_data_app* appdata = (struct _sync_pack_data_app*) (data + sizeof(struct _sync_pack_header));
	appdata->gw_index = gw_index;
	strncpy((char*) appdata->appid, appid, sizeof(appdata->appid));
	sscanf(szMac, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	for (int i = 0; i < 6; i++) {
		appdata->mac[i] = mac[i];
	}
	addPackage(data, datalen);
}

void SyncClient::procAuthResp() {
	struct _sync_pack_data_auth_resp* resp = (struct _sync_pack_data_auth_resp*) (m_RecBuf + sizeof(struct _sync_pack_header));
	EventLog::trace(TRACE_DEBUG, "procAuthResp");
	if (resp->gw_index < g_lstWifidog.size()) {
		Wifidog* pWifidog = g_lstWifidog[resp->gw_index];
		Client* pClient = pWifidog->findClientByMac(resp->mac);
		if (pClient) {
			EventLog::trace(TRACE_DEBUG, "procAuthResp Client Ip=%s, mac=%s", pClient->m_ip.c_str(), pClient->m_mac.c_str());
			pClient->setState(resp->result);
			pWifidog->allowClient(pClient);
		}
	}
}

/**
 * 添加数据到接收缓存
 * @param szBuf 要添加的数据
 * @param nLen 要添加的长度
 */
void SyncClient::AppendRecBuf(unsigned char *szBuf, int nLen) {
	if (nLen <= 0)
		return;
	if (nLen > REC_BUF_MAX) {
		memcpy(m_RecBuf, szBuf + nLen - REC_BUF_MAX, REC_BUF_MAX);
		m_nBufLen = REC_BUF_MAX;
		return;
	} else if (nLen + m_nBufLen > REC_BUF_MAX) {
		DecRecBuf(nLen + m_nBufLen - REC_BUF_MAX);
	}
	memcpy(m_RecBuf + m_nBufLen, szBuf, nLen);
	m_nBufLen += nLen;
}

/**
 * 删除接收缓冲区的数据
 * @param nLen 删除的长度
 */
void SyncClient::DecRecBuf(int nLen) {
	if (nLen <= 0)
		return;
	if (nLen >= REC_BUF_MAX || nLen >= m_nBufLen) {
		m_nBufLen = 0;
	} else {
		memcpy(m_RecBuf, m_RecBuf + nLen, m_nBufLen - nLen);
		m_nBufLen -= nLen;
	}
}

} /* namespace wrtclient */
