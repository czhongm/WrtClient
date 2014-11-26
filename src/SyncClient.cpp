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
	m_bConnected = false;
	m_bTerminated = false;
	m_mutex = PTHREAD_MUTEX_INITIALIZER;
	m_socket = -1;
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

	closeSocket();
}

void SyncClient::closeSocket() {
	if (m_socket >= 0) {
		close(m_socket);
		m_socket = -1;
	}
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
	struct sockaddr_in local_address;
	int sockopt = 1;
	if ((m_socket = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		EventLog::trace(TRACE_ERROR, "Unable to create socket [%s][%d]\n", strerror(errno), m_socket);
		return false;
	}

	setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &sockopt, sizeof(sockopt));

	memset(&local_address, 0, sizeof(local_address));
	local_address.sin_family = AF_INET;
	local_address.sin_port = htons(m_remoteport);
	local_address.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(m_socket, (struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
		EventLog::trace(TRACE_ERROR, "Bind error [%s]\n", strerror(errno));
		closeSocket();
		return false;
	}

	return true;
}

void SyncClient::start() {
	while (!m_bTerminated) {
		procSend();
		procRecv();
		usleep(300 * 1000);
	}
}

void SyncClient::procSend() {
	if (m_socket < 0) {
		if (connect() == false) {
			usleep(1000 * 1000);
			return;
		}
	}

	struct sockaddr_in remote_addr;
	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(m_remoteport);
	remote_addr.sin_addr.s_addr = inet_addr(m_remoteip.c_str());

	pthread_mutex_lock(&m_mutex);
	while (!m_lstPackage.empty()) {
		struct _queue_item* pItem = m_lstPackage.front();
		int ss;

		if (-1 == (ss = sendto(m_socket, pItem->data, pItem->length, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)))) {
			EventLog::trace(TRACE_ERROR, "sendto:%s", strerror(errno));
			closeSocket();
			break;
		} else {
			EventLog::trace(TRACE_INFO, "Send type=%d pack success.", ((struct _sync_pack_header*) (pItem->data))->type);
		}
		free(pItem->data);
		delete (pItem);
		m_lstPackage.pop();
	}
	pthread_mutex_unlock(&m_mutex);
}

void SyncClient::procRecv() {
	if (m_socket < 0) {
		if (connect() == false) {
			usleep(1000 * 1000);
			return;
		}
	}
	int n;
	struct sockaddr_in remote_addr;
	size_t nSize = sizeof(remote_addr);
	fd_set s;
	FD_ZERO(&s);
	FD_SET(m_socket, &s);
	struct timeval timeout;
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	int retval = select(m_socket + 1, &s, &s, &s, &timeout);
	if (retval == -1) {
		return;
	}
	unsigned char buf[1024];
	n = recvfrom(m_socket, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *) &remote_addr, &nSize);
	if (n == -1) {
		return;
	}
	if (n < sizeof(struct _sync_pack_header)) {
		EventLog::trace(TRACE_DEBUG, "Not enougth bytes!");
		return;
	}
	struct _sync_pack_header* header = (struct _sync_pack_header*) buf;
	unsigned int packlen = header->length + sizeof(struct _sync_pack_header);
	if (packlen > n) {
		EventLog::trace(TRACE_DEBUG, "Not enougth bytes,wait next loop packlen=%d,buflen=%d", packlen, n);
		return;
	}
	if (memcmp(m_mac, header->mac, sizeof(m_mac)) != 0) {
		EventLog::trace(TRACE_DEBUG, "DROP package because MAC");
	} else {
		switch (header->type) {
		case SYNCPACK_TYPE_AUTH_RESP:
			procAuthResp(buf, n);
			break;
		case SYNCPACK_TYPE_DHCP_RESP:
			break;
		}
	}
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

void SyncClient::authClient(int gw_index, const char* szMac, const char* szIp) {
	EventLog::trace(TRACE_DEBUG, "authClient gw_index=%d, mac=%s, ip=%s", gw_index, szMac, szIp);
	unsigned int mac[6];
	int ip[4];
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
	sscanf(szIp, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
	for (int i = 0; i < 4; i++) {
		authdata->ip[i] = ip[i] & 0xFF;
	}
	addPackage(data, datalen);
	EventLog::trace(TRACE_DEBUG, "authClient gw_index=%d, mac=%s ip=%s end", gw_index, szMac, szIp);
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

void SyncClient::postApp(int gw_index, const char* appid, unsigned char* mac) {
	int datalen = sizeof(struct _sync_pack_header) + sizeof(struct _sync_pack_data_app);
	unsigned char* data = (unsigned char*) malloc(datalen);
	memset(data, 0, datalen);
	struct _sync_pack_header* header = (struct _sync_pack_header*) data;
	constructHeader(header, SYNCPACK_TYPE_APP, sizeof(struct _sync_pack_data_app));
	struct _sync_pack_data_app* appdata = (struct _sync_pack_data_app*) (data + sizeof(struct _sync_pack_header));
	appdata->gw_index = gw_index;
	strncpy((char*) appdata->appid, appid, sizeof(appdata->appid));
	memcpy(appdata->mac,mac,sizeof(appdata->mac));
	addPackage(data, datalen);
}

void SyncClient::procAuthResp(unsigned char* data, int len) {
	struct _sync_pack_data_auth_resp* resp = (struct _sync_pack_data_auth_resp*) (data + sizeof(struct _sync_pack_header));
	EventLog::trace(TRACE_DEBUG, "procAuthResp Client Ip=%d.%d.%d.%d, mac=%02x:%02x:%02x:%02x:%02x:%02x,state=%d", resp->ip[0], resp->ip[1], resp->ip[2],
			resp->ip[3], resp->mac[0], resp->mac[1], resp->mac[2], resp->mac[3], resp->mac[4], resp->mac[5], resp->result);
	if (resp->gw_index < g_lstWifidog.size()) {
		Wifidog* pWifidog = g_lstWifidog[resp->gw_index];
		if(resp->result == STATE_DENY){
			pWifidog->denyClient(resp->mac);
		}else{
			Client* pClient = pWifidog->findClientByMac(resp->mac);
			if (pClient) {
				pClient->setState(resp->result);
				pWifidog->allowClient(pClient);
			} else {
				pClient = pWifidog->appendClient(resp->ip,resp->mac, resp->result);
				pWifidog->allowClient(pClient);
			}
		}
	}
}

void SyncClient::postCounter(int gw_index,unsigned char* ip,unsigned char* mac,unsigned long long sendbytes,unsigned long long recvbytes){
	int datalen = sizeof(struct _sync_pack_header) + sizeof(struct _sync_pack_data_counter);
	unsigned char* data = (unsigned char*) malloc(datalen);
	memset(data, 0, datalen);
	struct _sync_pack_header* header = (struct _sync_pack_header*) data;
	constructHeader(header, SYNCPACK_TYPE_COUNTER, sizeof(struct _sync_pack_data_counter));
	struct _sync_pack_data_counter* counterdata = (struct _sync_pack_data_counter*) (data + sizeof(struct _sync_pack_header));
	memcpy(counterdata->ip,ip,sizeof(counterdata->ip));
	memcpy(counterdata->mac,mac,sizeof(counterdata->mac));
	counterdata->recvbytes = recvbytes;
	counterdata->sendbytes = sendbytes;
	addPackage(data, datalen);
}

} /* namespace wrtclient */
