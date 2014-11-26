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

#define DEFAULT_INTERVAL_UPDATEIP 					20	//更新ip地址的间隔
#define DEFAULT_INTERVAL_UPLOADCOUTNER	60   //默认数据上报更新时间

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
	void denyClient(unsigned char* mac);
	friend class Iptables;
	friend class WebServer;

	Client* findClientByIp(const char* szIp);
	Client* findClientByIp(unsigned char* ip);
	Client* findClientByMac(unsigned char* mac);
	Client* appendClient(unsigned char* ip,unsigned char* mac,int state);

	static void* web_thread(void* param);
	static void* updateip_thread(void* param);
	static void* counter_thread(void* param);
protected:
	void updateIp();
	void updateCounter();

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
	int m_interval_updateip;
	int m_interval_uploadcounter;

	vector<string> m_trustmaclist;
	vector<string> m_validiplist;
	vector<string> m_globaliplist;
	vector<string> m_validhostlist;
	vector<string> m_globalhostlist;

	vector<Client*>	m_clients;
	pthread_mutex_t	m_mutex_global,m_mutex_valid,m_mutex_trustmac,m_mutex_clients;
	pthread_t m_webthread,m_updateipthread,m_counterthread;

	bool	m_bTerminated;

	static int s_index;
	static pthread_mutex_t	s_mutex;
};

extern vector<Wifidog*> g_lstWifidog;

} /* namespace wrtclient */

#endif /* WIFIDOG_H_ */
