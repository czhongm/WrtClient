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
	loadConfig(config);
}

Wifidog::~Wifidog() {
	for (vector<Client*>::iterator p = m_clients.begin(); p != m_clients.end(); ++p) {
		delete (*p);
	}
	stop();
}

/**
 * 初始化
 */
bool Wifidog::init() {
	return true;
}

Client* Wifidog::findClientByIp(string ip) {
	Client* pClient = NULL;
	pthread_mutex_lock(&m_mutex_clients);
	for (vector<Client*>::iterator p = m_clients.begin(); p != m_clients.end(); ++p) {
		if ((*p)->m_ip == ip) {
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
	if (config_setting_lookup_string(config, "GatewayInterface", &strVal)) {
		m_interface = strVal;
	}
	if (config_setting_lookup_string(config, "ExternalInterface", &strVal)) {
		m_ext_interface = strVal;
	}
	if (config_setting_lookup_string(config, "DocumentRoot", &strVal)) {
		m_docroot = strVal;
	}
	config_setting_t* authserver = config_setting_get_member(config, "AuthServer");
	if (authserver != NULL) {
		if (config_setting_lookup_string(authserver, "Host", &strVal)) {
			m_authserver = strVal;
		}
		vector<string> lstIp;
		getHostIp(m_authserver.c_str(),lstIp);
		if(lstIp.size()>0) m_authserver = lstIp[0];
	}
	m_ip = get_iface_ip(m_interface.c_str());

	config_setting_t* globalAllow = config_setting_get_member(config,"GlobalAllow");
	if(globalAllow!=NULL){
		unsigned int count = config_setting_length(globalAllow);
		const char* ip;
		for(unsigned int i=0;i<count;i++){
			ip = config_setting_get_string_elem(globalAllow,i);
			m_globalhostlist.push_back(ip);
		}
	}
	config_setting_t* validAllow = config_setting_get_member(config,"ValidAllow");
	if(validAllow!=NULL){
		unsigned int count = config_setting_length(validAllow);
		const char* ip;
		for(unsigned int i=0;i<count;i++){
			ip = config_setting_get_string_elem(validAllow,i);
			m_validhostlist.push_back(ip);
		}
	}
	config_setting_t* trustMac = config_setting_get_member(config,"TrustMac");
	if(trustMac!=NULL){
		unsigned int count = config_setting_length(trustMac);
		const char* ip;
		for(unsigned int i=0;i<count;i++){
			ip = config_setting_get_string_elem(trustMac,i);
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
	if(he==NULL) return;
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

void* WebServerThread(void* param){
	WebServer* pServer = (WebServer*)param;
	EventLog::trace(TRACE_DEBUG, "Thread webserver start init!");
	pServer->init();
	EventLog::trace(TRACE_DEBUG, "Thread webserver start ");
	pServer->start();
	EventLog::trace(TRACE_DEBUG, "Thread webserver end here ");
	return (void*)0;
}

vector<string> Wifidog::checkIp(vector<string>& hostlist,vector<string>& iplist,pthread_mutex_t mutex){
	vector<string> retlist;
	vector<string> newiplist;
	vector<string>::iterator p = hostlist.begin();
	for(;p!=hostlist.end();++p){
		getHostIp((*p).c_str(),newiplist);
	}
	pthread_mutex_lock(&mutex);
	for(p=newiplist.begin();p!=newiplist.end();++p){
		bool bFound = false;
		vector<string>::iterator p1 = iplist.begin();
		for(;p1!=iplist.end();++p1){
			if((*p1)==(*p)) {
				bFound = true;
				break;
			}
		}
		if(!bFound){
			iplist.push_back(*p);
			retlist.push_back(*p);
		}
	}
	pthread_mutex_unlock(&mutex);
	return retlist;
}

void Wifidog::start(){
	EventLog::trace(TRACE_DEBUG,"start check ip");
	checkIp(m_globalhostlist,m_globaliplist,m_mutex_global);
	checkIp(m_validhostlist,m_validiplist,m_mutex_valid);
	EventLog::trace(TRACE_DEBUG,"start iptables...");
	if(m_pIptables == NULL) m_pIptables = new Iptables(this);
	EventLog::trace(TRACE_DEBUG,"start webserver...");
	if(m_pWebServer==NULL) m_pWebServer = new WebServer(this, GW_PORT + m_index, m_docroot.c_str());
	pthread_create(&m_webthread,NULL,WebServerThread,m_pWebServer);
	int i = 0;
	while(!m_bTerminated){
		usleep(300*1000);
		i++;
		if(i==300){ //30秒刷新一次
			EventLog::trace(TRACE_DEBUG,"start checkip...");
			vector<string> globaliplist = checkIp(m_globalhostlist,m_globaliplist,m_mutex_global);
			m_pIptables->addto_globalip(globaliplist);
			vector<string> validiplist =  checkIp(m_validhostlist,m_validiplist,m_mutex_valid);
			m_pIptables->addto_validip(validiplist);
			EventLog::trace(TRACE_DEBUG," checkip end...");
			i=0;
		}
	}
}

void Wifidog::stop(){
	EventLog::trace(TRACE_DEBUG,"Start to stop Wifidog in...");
	m_bTerminated = true;
	EventLog::trace(TRACE_DEBUG, "Start to stop Webserver in...");
	if (m_pWebServer){
		m_pWebServer->stop();
		pthread_join(m_webthread,NULL);
	}
	EventLog::trace(TRACE_DEBUG, "stop Webserver finished...");

	if (m_pIptables){
		delete m_pIptables;
		m_pIptables = NULL;
	}
	if (m_pWebServer){
		delete m_pWebServer;
		m_pWebServer = NULL;
	}
	EventLog::trace(TRACE_DEBUG,"stop Wifidog finished...");
}

Client* Wifidog::findClientByMac(string mac){
	EventLog::trace(TRACE_DEBUG,"findClientByMac mac=%s",mac.c_str());
	Client* pClient = NULL;
	pthread_mutex_lock(&m_mutex_clients);
	for (vector<Client*>::iterator p = m_clients.begin(); p != m_clients.end(); ++p) {
		if ((*p)->m_mac == mac) {
			pClient = (*p);
			break;
		}
	}
	pthread_mutex_unlock(&m_mutex_clients);
	return pClient;
}

void Wifidog::allowClient(Client* pClient){
	EventLog::trace(TRACE_DEBUG,"allowClient ip=%s mac=%s state=%d",pClient->m_ip.c_str(),pClient->m_mac.c_str(),pClient->getState());
	if(m_pIptables){
		m_pIptables->allowClient(pClient);
	}
}

Client* Wifidog::appendClient(const char* szIp,const char* szMac,int state){
	Client* pClient = new Client(szIp, szMac, state);
	pthread_mutex_lock(&m_mutex_clients);
	m_clients.push_back(pClient);
	pthread_mutex_unlock(&m_mutex_clients);
	return pClient;
}

} /* namespace wrtclient */
