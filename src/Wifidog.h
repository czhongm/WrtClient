/*
 * Wifidog.h
 *
 *  Created on: 2014年10月11日
 *      Author: czm
 *
 *      简化版wifidog，去除wifidog中多余的功能，增加实时控制功能
 */

#ifndef WIFIDOG_H_
#define WIFIDOG_H_

#include <vector>
#include <libconfig.h>
#include "Iptables.h"
#include "WebServer.h"
#include "Client.h"

using namespace std;

namespace wrtclient {

class Iptables;
class WebServer;

class Wifidog {
public:
	Wifidog(config_setting_t *config);
	virtual ~Wifidog();

	bool init();
	void start();
	void stop();

	void allowClient(Client* pClient);
	friend class Iptables;
	friend class WebServer;

	Client* findClientByIp(string ip);
	Client* findClientByMac(string mac);
	Client* appendClient(const char* szIp,const char* szMac,int state);

protected:
	void loadConfig(config_setting_t *config);
	void testClient(Client* pClient);
	string get_iface_ip(const char *ifname) ;
	void getHostIp(const char* hostname,vector<string>& lstResult);

	vector<string> checkIp(vector<string>& hostlist,vector<string>& iplist,pthread_mutex_t mutex);

protected:
	Iptables*			m_pIptables;
	WebServer* 	m_pWebServer;

	int m_index;
	string m_interface;
	string m_ip;
	string m_ext_interface;
	string m_authserver;
	string m_docroot;
	vector<string> m_trustmaclist;
	vector<string> m_validiplist;
	vector<string> m_globaliplist;
	vector<string> m_validhostlist;
	vector<string> m_globalhostlist;

	vector<Client*>	m_clients;
	pthread_mutex_t	m_mutex_global,m_mutex_valid,m_mutex_trustmac,m_mutex_clients;
	pthread_t m_webthread;

	bool	m_bTerminated;

	static int s_index;
	static pthread_mutex_t	s_mutex;
};

extern vector<Wifidog*> g_lstWifidog;

} /* namespace wrtclient */

#endif /* WIFIDOG_H_ */
