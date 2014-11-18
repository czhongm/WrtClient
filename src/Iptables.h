/*
 * Iptables.h
 *
 *  Created on: 2014年10月13日
 *      Author: czm
 */

#ifndef IPTABLES_H_
#define IPTABLES_H_

#include <string>
#include <vector>
#include <pthread.h>

using namespace std;

#include "global.h"
#include "Client.h"
#include "Wifidog.h"


#define TABLE_WIFIDOG_OUTGOING  "WiFiDog_$ID$_Outgoing"
#define TABLE_WIFIDOG_WIFI_TO_INTERNET "WiFiDog_$ID$_WIFI2Internet"
#define TABLE_WIFIDOG_WIFI_TO_ROUTER "WiFiDog_$ID$_WIFI2Router"
#define TABLE_WIFIDOG_INCOMING  "WiFiDog_$ID$_Incoming"
#define TABLE_WIFIDOG_AUTHSERVERS "WiFiDog_$ID$_AuthServers"
#define TABLE_WIFIDOG_GLOBAL  "WiFiDog_$ID$_Global"
#define TABLE_WIFIDOG_VALIDATE  "WiFiDog_$ID$_Validate"
#define TABLE_WIFIDOG_KNOWN     "WiFiDog_$ID$_Known"
#define TABLE_WIFIDOG_UNKNOWN   "WiFiDog_$ID$_Unknown"
#define TABLE_WIFIDOG_LOCKED    "WiFiDog_$ID$_Locked"
#define TABLE_WIFIDOG_TRUSTED    "WiFiDog_$ID$_Trusted"


namespace wrtclient {

typedef enum _t_fw_marks {
	FW_MARK_PROBATION = 0x0100, /**< @brief The client is in probation period and must be authenticated
	 @todo: VERIFY THAT THIS IS ACCURATE*/
	FW_MARK_KNOWN = 0x0200, /**< @brief The client is known to the firewall */
	FW_MARK_LOCKED = 0x0300 /**< @brief The client has been locked out */
} t_fw_marks;

typedef enum fw_access_t_ {
    FW_ACCESS_ALLOW,
    FW_ACCESS_DENY
} fw_access_t;

class Wifidog;

class Iptables {
public:
	Iptables(Wifidog*	pParent);
	virtual ~Iptables();

protected:
	int do_command(const char *format, ...);
	void insert_gateway_id(char **input);

	int init();
	int destroy();
	int destroy_mention(const char * table, const char * chain, const char * mention);

	int access(fw_access_t type, const char *ip, const char *mac, int tag);

public:
	int couters_update();
	void update_globalip();
	void addto_globalip(vector<string>& iplist);
	void update_validip();
	void addto_validip(vector<string>& iplist);
	void update_trustmac();
	void addto_trustmac(vector<string>& maclist);

	void allowClient(Client* pClient);
	void denyClient(Client* pClient);


protected:
	Wifidog*	m_pParent;
	pthread_mutex_t	m_mutex;

};

} /* namespace wrtclient */

#endif /* IPTABLES_H_ */
