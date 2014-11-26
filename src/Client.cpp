/*
 * Client.cpp
 *
 *  Created on: 2014年10月14日
 *      Author: czm
 */


#include <string.h>
#include <stdio.h>

#include "Client.h"

namespace wrtclient {

Client::Client(const char* szIp, const char* szMac, int state) :
		m_state(state), m_oldstate(STATE_INVALIDATE) {
	unsigned int mac[6];
	int ip[4];
	sscanf(szMac, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	for (int i = 0; i < 6; i++) {
		m_mac[i] = mac[i];
	}
	sscanf(szIp, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
	for (int i = 0; i < 4; i++) {
		m_ip[i] = ip[i] & 0xFF;
	}
	m_lastupdate = 0;
	m_recv = 0;
	m_send = 0;
}

Client::Client(unsigned char* ip, unsigned char* mac, int state) :
		m_state(state), m_oldstate(STATE_INVALIDATE) {
	memcpy(m_ip, ip, sizeof(m_ip));
	memcpy(m_mac, mac, sizeof(m_mac));
	m_lastupdate = 0;
	m_recv = 0;
	m_send = 0;
}
Client::~Client() {

}

void Client::getIp(char* szIp) {
	sprintf(szIp, "%d.%d.%d.%d", m_ip[0], m_ip[1], m_ip[2], m_ip[3]);
}
void Client::getIp(unsigned char* ip) {
	memcpy(ip, m_ip, sizeof(m_ip));
}
void Client::getMac(char* szMac) {
	sprintf(szMac, "%02x:%02x:%02x:%02x:%02x:%02x", m_mac[0], m_mac[1], m_mac[2], m_mac[3], m_mac[4], m_mac[5]);
}
void Client::getMac(unsigned char* mac) {
	memcpy(mac, m_mac, sizeof(m_mac));
}

void Client::setState(int state) {
	m_oldstate = m_state;
	m_state = state;
}

time_t Client::getLastupdate() const {
	return m_lastupdate;
}

unsigned long long Client::getRecv() const {
	return m_recv;
}

void Client::setRecv(unsigned long long recv) {
	if (recv > m_recv) {
		m_recv = recv;
		m_lastupdate = time(NULL);
	}
}

unsigned long long Client::getSend() const {
	return m_send;
}

void Client::setSend(unsigned long long send) {
	if (send > m_send) {
		m_send = send;
		m_lastupdate = time(NULL);
	}
}

bool Client::equalMac(unsigned char* mac){
	return memcmp(m_mac,mac,sizeof(m_mac))==0;
}

bool Client::equalIp(unsigned char* ip){
	return memcmp(m_ip,ip,sizeof(m_ip))==0;
}

} /* namespace wrtclient */
