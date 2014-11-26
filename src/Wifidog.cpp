/*
 * Wifidog.cpp
 *
 *  Created on: 2014年10月11日
 *      Author: czm
 */

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

#include "Wifidog.h"
#include "EventLog.h"
#include "SyncClient.h"

namespace wrtclient {

int Wifidog::s_index = 0;
pthread_mutex_t Wifidog::s_mutex = PTHREAD_MUTEX_INITIALIZER;

vector<Wifidog*> g_lstWifidog;

Wifidog::Wifidog(config_setting_t *config) {
	m_index = s_index++;
	m_mutex_global = PTHREAD_MUTEX_INITIALIZER;
	m_mutex_valid = PTHREAD_MUTEX_INITIALIZER;
	m_mutex_trustmac = PTHREAD_MUTEX_INITIALIZER;
	m_mutex_clients = PTHREAD_MUTEX_INITIALIZER;
	m_bTerminated = false;
	m_pIptables = NULL;
	m_pWebServer = NULL;
	m_docroot = "/tmp";
	m_interval_updateip = DEFAULT_INTERVAL_UPDATEIP;
	m_interval_uploadcounter = DEFAULT_INTERVAL_UPLOADCOUTNER;

	loadConfig(config);
}

Wifidog::~Wifidog() {
	pthread_mutex_lock(&m_mutex_clients);
	for (vector<Client*>::iterator p = m_clients.begin(); p != m_clients.end(); ++p) {
		delete (*p);
	}
	pthread_mutex_unlock(&m_mutex_clients);
	if (m_pIptables) {
		delete m_pIptables;
		m_pIptables = NULL;
	}
	if (m_pWebServer) {
		delete m_pWebServer;
		m_pWebServer = NULL;
	}
}

/**
 * 初始化
 */
bool Wifidog::init() {
	return true;
}

Client* Wifidog::findClientByIp(const char* szIp) {
	unsigned char ip[4];
	int nIp[4];
	sscanf(szIp, "%d.%d.%d.%d", nIp[0], nIp[1], nIp[2], nIp[3]);
	for (int i = 0; i < 4; i++)
		ip[i] = nIp[i] & 0xFF;
	return findClientByIp(ip);
}
Client* Wifidog::findClientByIp(unsigned char* ip) {
	Client* pClient = NULL;
	pthread_mutex_lock(&m_mutex_clients);
	for (vector<Client*>::iterator p = m_clients.begin(); p != m_clients.end(); ++p) {
		if ((*p)->equalIp(ip)) {
			pClient = *p;
			break;
		}
	}
	pthread_mutex_unlock(&m_mutex_clients);
	return pClient;
}

void Wifidog::testClient(Client* pClient) {

}

void Wifidog::loadConfig(config_setting_t *config) {
	const char* strVal;
	int nval;
	if (config_setting_lookup_string(config, "GatewayInterface", &strVal)) {
		m_interface = strVal;
	}
	if (config_setting_lookup_string(config, "ExternalInterface", &strVal)) {
		m_ext_interface = strVal;
	}
	if (config_setting_lookup_string(config, "DocumentRoot", &strVal)) {
		m_docroot = strVal;
	}
	if (config_setting_lookup_int(config, "UpdateIp_Interval", &nval)) {
		m_interval_updateip = nval;
	}
	if (config_setting_lookup_int(config, "UploadCounter_Interval", &nval)) {
		m_interval_uploadcounter = nval;
	}
	config_setting_t* authserver = config_setting_get_member(config, "AuthServer");
	if (authserver != NULL) {
		if (config_setting_lookup_string(authserver, "Host", &strVal)) {
			m_authserver = strVal;
		}
		vector<string> lstIp;
		getHostIp(m_authserver.c_str(), lstIp);
		if (lstIp.size() > 0)
			m_authserver = lstIp[0];
	}
	m_ip = get_iface_ip(m_interface.c_str());

	config_setting_t* globalAllow = config_setting_get_member(config, "GlobalAllow");
	if (globalAllow != NULL) {
		unsigned int count = config_setting_length(globalAllow);
		const char* ip;
		for (unsigned int i = 0; i < count; i++) {
			ip = config_setting_get_string_elem(globalAllow, i);
			m_globalhostlist.push_back(ip);
		}
	}
	config_setting_t* validAllow = config_setting_get_member(config, "ValidAllow");
	if (validAllow != NULL) {
		unsigned int count = config_setting_length(validAllow);
		const char* ip;
		for (unsigned int i = 0; i < count; i++) {
			ip = config_setting_get_string_elem(validAllow, i);
			m_validhostlist.push_back(ip);
		}
	}
	config_setting_t* trustMac = config_setting_get_member(config, "TrustMac");
	if (trustMac != NULL) {
		unsigned int count = config_setting_length(trustMac);
		const char* ip;
		for (unsigned int i = 0; i < count; i++) {
			ip = config_setting_get_string_elem(trustMac, i);
			m_trustmaclist.push_back(ip);
		}
	}
}

void Wifidog::getHostIp(const char* hostname, vector<string>& lstResult) {
	struct hostent *he;
	struct in_addr **addr_list;
	char *ip;
	int i;
	pthread_mutex_lock(&s_mutex); //因为gethostbyname不能重入，下次用getnameinfo
	he = gethostbyname(hostname);
	pthread_mutex_unlock(&s_mutex);
	if (he == NULL)
		return;
	addr_list = (struct in_addr **) he->h_addr_list;
	for (i = 0; addr_list[i] != NULL; i++) {
		ip = inet_ntoa(*addr_list[i]);
		lstResult.push_back(ip);
	}
}

string Wifidog::get_iface_ip(const char *ifname) {
	struct ifreq if_data;
	struct in_addr in;
	char *ip_str;
	int sockd;
	u_int32_t ip;

	/* Create a socket */
	if ((sockd = socket(AF_INET, SOCK_PACKET, htons(0x8086))) < 0) {
		EventLog::trace(TRACE_ERROR, "socket(): %s", strerror(errno));
		return NULL;
	}

	/* Get IP of internal interface */
	strcpy(if_data.ifr_name, ifname);

	/* Get the IP address */
	if (ioctl(sockd, SIOCGIFADDR, &if_data) < 0) {
		EventLog::trace(TRACE_ERROR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
		return "";
	}
	memcpy((void *) &ip, (void *) &if_data.ifr_addr.sa_data + 2, 4);
	in.s_addr = ip;

	ip_str = inet_ntoa(in);
	close(sockd);
	return ip_str;
}

void* Wifidog::web_thread(void* param) {
	WebServer* pServer = (WebServer*) param;
	pServer->init();
	pServer->start();
	return (void*) 0;
}

void* Wifidog::updateip_thread(void* param) {
	Wifidog* pDog = (Wifidog*) param;
	pDog->updateIp();
	return (void*) 0;
}

void Wifidog::updateIp() {
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct timespec timeout;

	while (!m_bTerminated) {

		EventLog::trace(TRACE_DEBUG, "start checkip...");
		vector<string> globaliplist = checkIp(m_globalhostlist, m_globaliplist, m_mutex_global);
		m_pIptables->addto_globalip(globaliplist);
		vector<string> validiplist = checkIp(m_validhostlist, m_validiplist, m_mutex_valid);
		m_pIptables->addto_validip(validiplist);
		EventLog::trace(TRACE_DEBUG, " checkip end...");

		timeout.tv_sec = time(NULL) + m_interval_updateip;
		timeout.tv_nsec = 0;

		pthread_mutex_lock(&cond_mutex);
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		pthread_mutex_unlock(&cond_mutex);
	}
}

void* Wifidog::counter_thread(void* param) {
	Wifidog* pDog = (Wifidog*) param;
	pDog->updateCounter();
	return (void*) 0;
}

void Wifidog::updateCounter() {
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct timespec timeout;

	while (!m_bTerminated) {

		m_pIptables->couters_update();

		if (g_syncclient) {
			time_t current_time = time(NULL);
			pthread_mutex_lock(&m_mutex_clients);
			for (vector<Client*>::iterator p = m_clients.begin(); p != m_clients.end(); ++p) {
				if ((*p)->getLastupdate() + m_interval_uploadcounter >= current_time) {
					g_syncclient->postCounter(m_index,(*p)->getIp(),(*p)->getMac(),(*p)->getSend(),(*p)->getRecv());
				}
			}
			pthread_mutex_unlock(&m_mutex_clients);
		}
		timeout.tv_sec = time(NULL) + m_interval_uploadcounter;
		timeout.tv_nsec = 0;

		pthread_mutex_lock(&cond_mutex);
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		pthread_mutex_unlock(&cond_mutex);
	}
}

vector<string> Wifidog::checkIp(vector<string>& hostlist, vector<string>& iplist, pthread_mutex_t mutex) {
	vector<string> retlist;
	vector<string> newiplist;
	vector<string>::iterator p = hostlist.begin();
	for (; p != hostlist.end(); ++p) {
		getHostIp((*p).c_str(), newiplist);
	}
	pthread_mutex_lock(&mutex);
	for (p = newiplist.begin(); p != newiplist.end(); ++p) {
		bool bFound = false;
		vector<string>::iterator p1 = iplist.begin();
		for (; p1 != iplist.end(); ++p1) {
			if ((*p1) == (*p)) {
				bFound = true;
				break;
			}
		}
		if (!bFound) {
			iplist.push_back(*p);
			retlist.push_back(*p);
		}
	}
	pthread_mutex_unlock(&mutex);
	return retlist;
}

void Wifidog::start() {
	EventLog::trace(TRACE_DEBUG, "Wifidog Start..");
	if (m_pIptables == NULL)
		m_pIptables = new Iptables(this);
	if (m_pWebServer == NULL)
		m_pWebServer = new WebServer(this, GW_PORT + m_index, m_docroot.c_str());
	pthread_create(&m_webthread, NULL, Wifidog::web_thread, m_pWebServer);
	pthread_create(&m_updateipthread, NULL, Wifidog::updateip_thread, this);
	pthread_create(&m_counterthread, NULL, Wifidog::counter_thread, this);

	pthread_join(m_counterthread, NULL);
	pthread_join(m_updateipthread, NULL);
	pthread_join(m_webthread, NULL);
}

void Wifidog::stop() {
	EventLog::trace(TRACE_DEBUG, "Stop Wifidog...");
	m_bTerminated = true;
	if (m_pWebServer) {
		m_pWebServer->stop();
	}
}

Client* Wifidog::findClientByMac(unsigned char* mac) {
	Client* pClient = NULL;
	pthread_mutex_lock(&m_mutex_clients);
	for (vector<Client*>::iterator p = m_clients.begin(); p != m_clients.end(); ++p) {
		if ((*p)->equalMac(mac)) {
			pClient = (*p);
			break;
		}
	}
	pthread_mutex_unlock(&m_mutex_clients);
	return pClient;
}

void Wifidog::allowClient(Client* pClient) {
	if (m_pIptables) {
		m_pIptables->allowClient(pClient);
	}
}

void Wifidog::denyClient(unsigned char* mac){
	pthread_mutex_lock(&m_mutex_clients);
	for (vector<Client*>::iterator p = m_clients.begin(); p != m_clients.end(); ++p) {
		if ((*p)->equalMac(mac)) {
			m_pIptables->denyClient(*p);
			delete (*p);
			m_clients.erase(p);
			break;
		}
	}
	pthread_mutex_unlock(&m_mutex_clients);
}

Client* Wifidog::appendClient(unsigned char* ip, unsigned char* mac, int state) {
	Client* pClient = new Client(ip, mac, state);
	pthread_mutex_lock(&m_mutex_clients);
	m_clients.push_back(pClient);
	pthread_mutex_unlock(&m_mutex_clients);
	return pClient;
}

} /* namespace wrtclient */
