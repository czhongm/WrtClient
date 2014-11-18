/*
 * Iptables.cpp
 *
 *  Created on: 2014年10月13日
 *      Author: czm
 */

#include "Iptables.h"
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "EventLog.h"
#include "Utils.h"

namespace wrtclient {

Iptables::Iptables(Wifidog* pParent) :
		m_pParent(pParent) {
	m_mutex = PTHREAD_MUTEX_INITIALIZER;
	init();
}

Iptables::~Iptables() {
	destroy();
}

void Iptables::insert_gateway_id(char **input) {
	char *token;
	char *buffer;

	if (strstr(*input, "$ID$") == NULL)
		return;

	while ((token = strstr(*input, "$ID$")) != NULL)
		/* This string may look odd but it's standard POSIX and ISO C */
		memcpy(token, "%1$d", 4);

	Utils::safe_asprintf(&buffer, *input, m_pParent->m_index);

	free(*input);
	*input = buffer;
}

int Iptables::do_command(const char* format, ...) {
	va_list vlist;
	char *fmt_cmd;
	char *cmd;
	int rc;

	va_start(vlist, format);
	Utils::safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);

	Utils::safe_asprintf(&cmd, "iptables %s", fmt_cmd);
	free(fmt_cmd);

	insert_gateway_id(&cmd);

	EventLog::trace(TRACE_DEBUG, "Executing command: %s", cmd);

	rc = Utils::execute(cmd, true);

	if (rc != 0) {
		EventLog::trace(TRACE_ERROR, "iptables command failed(%d): %s", rc, cmd);
	}

	free(cmd);

	return rc;
}

int Iptables::init() {
	/*
	 *
	 * Everything in the MANGLE table
	 *
	 */

	/* Create new chains */
	do_command("-t mangle -N " TABLE_WIFIDOG_TRUSTED);
	do_command("-t mangle -N " TABLE_WIFIDOG_OUTGOING);
	do_command("-t mangle -N " TABLE_WIFIDOG_INCOMING);

	/* Assign links and rules to these new chains */
	do_command("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_OUTGOING, m_pParent->m_interface.c_str());
	do_command("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_TRUSTED, m_pParent->m_interface.c_str()); //this rule will be inserted before the prior one
	do_command("-t mangle -I POSTROUTING 1 -o %s -j " TABLE_WIFIDOG_INCOMING, m_pParent->m_interface.c_str());

	vector<string>::iterator p = m_pParent->m_trustmaclist.begin();
	for (; p != m_pParent->m_trustmaclist.end(); ++p) {
		do_command("-t mangle -A " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", p->c_str(), FW_MARK_KNOWN);
	}

	/*
	 *
	 * Everything in the NAT table
	 *
	 */

	/* Create new chains */
	do_command("-t nat -N " TABLE_WIFIDOG_OUTGOING);
	do_command("-t nat -N " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	do_command("-t nat -N " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	do_command("-t nat -N " TABLE_WIFIDOG_GLOBAL);
	do_command("-t nat -N " TABLE_WIFIDOG_UNKNOWN);
	do_command("-t nat -N " TABLE_WIFIDOG_AUTHSERVERS);
	//add by childman
	do_command("-t nat -N " TABLE_WIFIDOG_VALIDATE);

	/* Assign links and rules to these new chains */
	do_command("-t nat -A PREROUTING -i %s -j " TABLE_WIFIDOG_OUTGOING, m_pParent->m_interface.c_str());

	do_command("-t nat -A " TABLE_WIFIDOG_OUTGOING " -d %s -j " TABLE_WIFIDOG_WIFI_TO_ROUTER, m_pParent->m_ip.c_str());
	do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_ROUTER " -j ACCEPT");

	do_command("-t nat -A " TABLE_WIFIDOG_OUTGOING " -j " TABLE_WIFIDOG_WIFI_TO_INTERNET);

	do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark %u/0xff00 -j ACCEPT", FW_MARK_KNOWN);
	//edit by childman
	do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark %u/0xff00 -j " TABLE_WIFIDOG_VALIDATE, FW_MARK_PROBATION);
	for (p = m_pParent->m_validiplist.begin(); p != m_pParent->m_validiplist.end(); ++p) {
		do_command("-t nat -A "TABLE_WIFIDOG_VALIDATE" -d %s -j ACCEPT", p->c_str());
	}

	do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_UNKNOWN);

	do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_AUTHSERVERS);
	do_command("-t nat -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s  -j ACCEPT", m_pParent->m_authserver.c_str());

	do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_GLOBAL);
	//在此添加全局nat策略，目前为空
	for (p = m_pParent->m_globaliplist.begin(); p != m_pParent->m_globaliplist.end(); ++p) {
		do_command("-t nat -A "TABLE_WIFIDOG_GLOBAL" -d %s -j ACCEPT", p->c_str());
	}

	do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", GW_PORT + m_pParent->m_index);

	/*
	 *
	 * Everything in the FILTER table
	 *
	 */

	/* Create new chains */
	do_command("-t filter -N " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	do_command("-t filter -N " TABLE_WIFIDOG_AUTHSERVERS);
	do_command("-t filter -N " TABLE_WIFIDOG_LOCKED);
	do_command("-t filter -N " TABLE_WIFIDOG_GLOBAL);
	do_command("-t filter -N " TABLE_WIFIDOG_VALIDATE);
	do_command("-t filter -N " TABLE_WIFIDOG_KNOWN);
	do_command("-t filter -N " TABLE_WIFIDOG_UNKNOWN);

	/* Assign links and rules to these new chains */

	/* Insert at the beginning */
	do_command("-t filter -I FORWARD -i %s -j " TABLE_WIFIDOG_WIFI_TO_INTERNET, m_pParent->m_interface.c_str());

	do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m state --state INVALID -j DROP");

	/* XXX: Why this? it means that connections setup after authentication
	 stay open even after the connection is done...
	 do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m state --state RELATED,ESTABLISHED -j ACCEPT");*/

	//Won't this rule NEVER match anyway?!?!? benoitg, 2007-06-23
	//do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -i %s -m state --state NEW -j DROP", ext_interface);
	/* TCPMSS rule for PPPoE */
	do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
			m_pParent->m_ext_interface.c_str());

	do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_AUTHSERVERS);
	do_command("-t filter -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s  -j ACCEPT", m_pParent->m_authserver.c_str());

	do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark %u/0xff00 -j " TABLE_WIFIDOG_LOCKED, FW_MARK_LOCKED);
	do_command("-t filter -A " TABLE_WIFIDOG_LOCKED "  -j DROP");

	do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_GLOBAL);
	//在此添加全局过滤策略，目前为空
	for (p = m_pParent->m_globaliplist.begin(); p != m_pParent->m_globaliplist.end(); ++p) {
		do_command("-t filter -A "TABLE_WIFIDOG_GLOBAL" -d %s -j ACCEPT", p->c_str());
	}

	do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark %u/0xff00 -j " TABLE_WIFIDOG_VALIDATE, FW_MARK_PROBATION);
	do_command("-t filter -A "TABLE_WIFIDOG_VALIDATE"  -j ACCEPT"); //全部允许通过

	do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark %u/0xff00 -j " TABLE_WIFIDOG_KNOWN, FW_MARK_KNOWN);
	do_command("-t filter -A "TABLE_WIFIDOG_KNOWN"  -j ACCEPT"); //全部允许通过

	do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_UNKNOWN);
	do_command("-t filter -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 53 -j ACCEPT"); //开启dns端口
	do_command("-t filter -A " TABLE_WIFIDOG_UNKNOWN " -p udp --dport 53 -j ACCEPT");
	do_command("-t filter -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 67 -j ACCEPT"); //开启DHCP
	do_command("-t filter -A " TABLE_WIFIDOG_UNKNOWN " -p udp --dport 67 -j ACCEPT");

	do_command("-t filter -A " TABLE_WIFIDOG_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");
	return 1;
}

int Iptables::destroy() {
	EventLog::trace(TRACE_DEBUG, "Destroying our iptables entries");

	EventLog::trace(TRACE_DEBUG, "Destroying chains in the MANGLE table");
	destroy_mention("mangle", "PREROUTING", TABLE_WIFIDOG_TRUSTED);
	destroy_mention("mangle", "PREROUTING", TABLE_WIFIDOG_OUTGOING);
	destroy_mention("mangle", "POSTROUTING", TABLE_WIFIDOG_INCOMING);
	do_command("-t mangle -F " TABLE_WIFIDOG_TRUSTED);
	do_command("-t mangle -F " TABLE_WIFIDOG_OUTGOING);
	do_command("-t mangle -F " TABLE_WIFIDOG_INCOMING);
	do_command("-t mangle -X " TABLE_WIFIDOG_TRUSTED);
	do_command("-t mangle -X " TABLE_WIFIDOG_OUTGOING);
	do_command("-t mangle -X " TABLE_WIFIDOG_INCOMING);

	/*
	 *
	 * Everything in the NAT table
	 *
	 */
	EventLog::trace(TRACE_DEBUG, "Destroying chains in the NAT table");
	destroy_mention("nat", "PREROUTING", TABLE_WIFIDOG_OUTGOING);
	do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
	do_command("-t nat -F " TABLE_WIFIDOG_OUTGOING);
	do_command("-t nat -F " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	do_command("-t nat -F " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	do_command("-t nat -F " TABLE_WIFIDOG_GLOBAL);
	do_command("-t nat -F " TABLE_WIFIDOG_UNKNOWN);
	//add by childman
	do_command("-t nat -F " TABLE_WIFIDOG_VALIDATE);

	do_command("-t nat -X " TABLE_WIFIDOG_AUTHSERVERS);
	do_command("-t nat -X " TABLE_WIFIDOG_OUTGOING);
	do_command("-t nat -X " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	do_command("-t nat -X " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	do_command("-t nat -X " TABLE_WIFIDOG_GLOBAL);
	do_command("-t nat -X " TABLE_WIFIDOG_UNKNOWN);
	//add by childman
	do_command("-t nat -X " TABLE_WIFIDOG_VALIDATE);

	/*
	 *
	 * Everything in the FILTER table
	 *
	 */
	EventLog::trace(TRACE_DEBUG, "Destroying chains in the FILTER table");
	destroy_mention("filter", "FORWARD", TABLE_WIFIDOG_WIFI_TO_INTERNET);
	do_command("-t filter -F " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	do_command("-t filter -F " TABLE_WIFIDOG_AUTHSERVERS);
	do_command("-t filter -F " TABLE_WIFIDOG_LOCKED);
	do_command("-t filter -F " TABLE_WIFIDOG_GLOBAL);
	do_command("-t filter -F " TABLE_WIFIDOG_VALIDATE);
	do_command("-t filter -F " TABLE_WIFIDOG_KNOWN);
	do_command("-t filter -F " TABLE_WIFIDOG_UNKNOWN);
	do_command("-t filter -X " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	do_command("-t filter -X " TABLE_WIFIDOG_AUTHSERVERS);
	do_command("-t filter -X " TABLE_WIFIDOG_LOCKED);
	do_command("-t filter -X " TABLE_WIFIDOG_GLOBAL);
	do_command("-t filter -X " TABLE_WIFIDOG_VALIDATE);
	do_command("-t filter -X " TABLE_WIFIDOG_KNOWN);
	do_command("-t filter -X " TABLE_WIFIDOG_UNKNOWN);

	return 1;
}

int Iptables::destroy_mention(const char * table, const char * chain, const char * mention) {
	FILE *p = NULL;
	char *command = NULL;
	char *command2 = NULL;
	char line[MAX_BUF];
	char rulenum[10];
	char *victim = Utils::safe_strdup(mention);
	int deleted = 0;

	insert_gateway_id(&victim);

	EventLog::trace(TRACE_DEBUG, "Attempting to destroy all mention of %s from %s.%s", victim, table, chain);

	Utils::safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
	insert_gateway_id(&command);

	if ((p = popen(command, "r"))) {
		/* Skip first 2 lines */
		while (!feof(p) && fgetc(p) != '\n')
			;
		while (!feof(p) && fgetc(p) != '\n')
			;
		/* Loop over entries */
		while (fgets(line, sizeof(line), p)) {
			/* Look for victim */
			if (strstr(line, victim)) {
				/* Found victim - Get the rule number into rulenum*/
				if (sscanf(line, "%9[0-9]", rulenum) == 1) {
					/* Delete the rule: */
					EventLog::trace(TRACE_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain, victim);
					Utils::safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
					do_command(command2);
					free(command2);
					deleted = 1;
					/* Do not keep looping - the captured rulenums will no longer be accurate */
					break;
				}
			}
		}
		pclose(p);
	}

	free(command);
	free(victim);

	if (deleted) {
		/* Recurse just in case there are more in the same table+chain */
		destroy_mention(table, chain, mention);
	}

	return (deleted);
}

int Iptables::access(fw_access_t type, const char *ip, const char *mac, int tag) {
	int rc;
	switch (type) {
	case FW_ACCESS_ALLOW:
		do_command("-t mangle -A " TABLE_WIFIDOG_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d/0xff00", ip, mac, tag);
		rc = do_command("-t mangle -A " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
		break;
	case FW_ACCESS_DENY:
		do_command("-t mangle -D " TABLE_WIFIDOG_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d/0xff00", ip, mac, tag);
		rc = do_command("-t mangle -D " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
		break;
	default:
		rc = -1;
		break;
	}

	return rc;
}

void Iptables::allowClient(Client* pClient) {
	int state = pClient->getState();
	int oldstate = pClient->getOldState();
	if (state != oldstate) {
		if (STATE_VALIDATION == oldstate) {
			access(FW_ACCESS_DENY, pClient->m_ip.c_str(), pClient->m_mac.c_str(), FW_MARK_PROBATION);
		} else if(STATE_ALLOWED == oldstate){
			access(FW_ACCESS_DENY, pClient->m_ip.c_str(), pClient->m_mac.c_str(), FW_MARK_KNOWN);
		}
		if (STATE_VALIDATION == state) {
			access(FW_ACCESS_ALLOW, pClient->m_ip.c_str(), pClient->m_mac.c_str(), FW_MARK_PROBATION);
		} else if(STATE_ALLOWED == state){
			access(FW_ACCESS_ALLOW, pClient->m_ip.c_str(), pClient->m_mac.c_str(), FW_MARK_KNOWN);
		}
	}
}
void Iptables::denyClient(Client* pClient) {
	int state = pClient->getState();
	if (STATE_VALIDATION == state) {
		access(FW_ACCESS_DENY, pClient->m_ip.c_str(), pClient->m_mac.c_str(), FW_MARK_PROBATION);
	} else {
		access(FW_ACCESS_DENY, pClient->m_ip.c_str(), pClient->m_mac.c_str(), FW_MARK_KNOWN);
	}
}

int Iptables::couters_update() {
	FILE *output;
	char *script, ip[16], rc;
	unsigned long long int counter;
	Client *p1;
	struct in_addr tempaddr;

	/* Look for outgoing traffic */
	Utils::safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_OUTGOING);
	insert_gateway_id(&script);
	output = popen(script, "r");
	free(script);
	if (!output) {
		EventLog::trace(TRACE_ERROR, "popen(): %s", strerror(errno));
		return -1;
	}

	/* skip the first two lines */
	while (('\n' != fgetc(output)) && !feof(output))
		;
	while (('\n' != fgetc(output)) && !feof(output))
		;
	while (output && !(feof(output))) {
		rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s %*s", &counter, ip);
		//rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s 0x%*u", &counter, ip);
		if (2 == rc && EOF != rc) {
			/* Sanity*/
			if (!inet_aton(ip, &tempaddr)) {
				EventLog::trace(TRACE_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
				continue;
			}
			EventLog::trace(TRACE_DEBUG, "Read outgoing traffic for %s: Bytes=%llu", ip, counter);
			pthread_mutex_lock(&m_mutex);
			if ((p1 = m_pParent->findClientByIp(ip))) {
				if (p1->m_send < counter) {
					p1->m_send = counter;
					p1->m_lastupdate = time(NULL);
					EventLog::trace(TRACE_DEBUG, "%s - Updated counter.outgoing to %llu bytes.  Updated last_updated to %d", ip, counter, p1->m_lastupdate);
				}
			} else {
				EventLog::trace(TRACE_ERROR,
						"iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed", ip);
				EventLog::trace(TRACE_ERROR, "Preventively deleting firewall rules for %s in table %s", ip, TABLE_WIFIDOG_OUTGOING);
				destroy_mention("mangle", TABLE_WIFIDOG_OUTGOING, ip);
				EventLog::trace(TRACE_ERROR, "Preventively deleting firewall rules for %s in table %s", ip, TABLE_WIFIDOG_INCOMING);
				destroy_mention("mangle", TABLE_WIFIDOG_INCOMING, ip);
			}
			pthread_mutex_unlock(&m_mutex);
		}
	}
	pclose(output);

	/* Look for incoming traffic */
	Utils::safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_INCOMING);
	insert_gateway_id(&script);
	output = popen(script, "r");
	free(script);
	if (!output) {
		EventLog::trace(TRACE_ERROR, "popen(): %s", strerror(errno));
		return -1;
	}

	/* skip the first two lines */
	while (('\n' != fgetc(output)) && !feof(output))
		;
	while (('\n' != fgetc(output)) && !feof(output))
		;
	while (output && !(feof(output))) {
		rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %*s %15[0-9.]", &counter, ip);
		if (2 == rc && EOF != rc) {
			/* Sanity*/
			if (!inet_aton(ip, &tempaddr)) {
				EventLog::trace(TRACE_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
				continue;
			}
			EventLog::trace(TRACE_DEBUG, "Read incoming traffic for %s: Bytes=%llu", ip, counter);
			pthread_mutex_lock(&m_mutex);
			if ((p1 = m_pParent->findClientByIp(ip))) {
				if ((p1->m_recv) < counter) {
					p1->m_recv = counter;
					EventLog::trace(TRACE_DEBUG, "%s - Updated counter.incoming to %llu bytes", ip, counter);
				}
			} else {
				EventLog::trace(TRACE_ERROR,
						"iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed", ip);
				EventLog::trace(TRACE_ERROR, "Preventively deleting firewall rules for %s in table %s", ip, TABLE_WIFIDOG_OUTGOING);
				destroy_mention("mangle", TABLE_WIFIDOG_OUTGOING, ip);
				EventLog::trace(TRACE_ERROR, "Preventively deleting firewall rules for %s in table %s", ip, TABLE_WIFIDOG_INCOMING);
				destroy_mention("mangle", TABLE_WIFIDOG_INCOMING, ip);
			}
			pthread_mutex_unlock(&m_mutex);
		}
	}
	pclose(output);

	return 1;
}

void Iptables::update_globalip() {
	do_command("-t nat -F " TABLE_WIFIDOG_GLOBAL);
	do_command("-t filter -F " TABLE_WIFIDOG_GLOBAL);
	pthread_mutex_lock(&(m_pParent->m_mutex_global));
	vector<string>::iterator p = m_pParent->m_globaliplist.begin();
	for (; p != m_pParent->m_globaliplist.end(); ++p) {
		do_command("-t nat -A " TABLE_WIFIDOG_GLOBAL " -d %s -j ACCEPT", p->c_str());
		do_command("-t filter -A " TABLE_WIFIDOG_GLOBAL " -d %s -j ACCEPT", p->c_str());
	}
	pthread_mutex_unlock(&(m_pParent->m_mutex_global));
}
void Iptables::addto_globalip(vector<string>& iplist) {
	vector<string>::iterator p = iplist.begin();
	for (; p != iplist.end(); ++p) {
		do_command("-t nat -A " TABLE_WIFIDOG_GLOBAL " -d %s -j ACCEPT", p->c_str());
		do_command("-t filter -A " TABLE_WIFIDOG_GLOBAL " -d %s -j ACCEPT", p->c_str());
	}
}

void Iptables::update_validip() {
	do_command("-t nat -F " TABLE_WIFIDOG_VALIDATE);
	do_command("-t filter -F " TABLE_WIFIDOG_VALIDATE);
	pthread_mutex_lock(&(m_pParent->m_mutex_valid));
	vector<string>::iterator p = m_pParent->m_validiplist.begin();
	for (; p != m_pParent->m_validiplist.end(); ++p) {
		do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -d %s -j ACCEPT", p->c_str());
		do_command("-t filter -A " TABLE_WIFIDOG_VALIDATE " -d %s -j ACCEPT", p->c_str());
	}
	pthread_mutex_unlock(&(m_pParent->m_mutex_valid));
}
void Iptables::addto_validip(vector<string>& iplist) {
	vector<string>::iterator p = iplist.begin();
	for (; p != iplist.end(); ++p) {
		do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -d %s -j ACCEPT", p->c_str());
		do_command("-t filter -A " TABLE_WIFIDOG_VALIDATE " -d %s -j ACCEPT", p->c_str());
	}
}

void Iptables::update_trustmac() {
	do_command("-t mangle -F " TABLE_WIFIDOG_TRUSTED);
	pthread_mutex_lock(&(m_pParent->m_mutex_trustmac));
	vector<string>::iterator p = m_pParent->m_trustmaclist.begin();
	for (; p != m_pParent->m_trustmaclist.end(); ++p) {
		do_command("-t mangle -A " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", p->c_str(), FW_MARK_KNOWN);
	}
	pthread_mutex_unlock(&(m_pParent->m_mutex_trustmac));
}

void Iptables::addto_trustmac(vector<string>& maclist) {
	vector<string>::iterator p = maclist.begin();
	for (; p != maclist.end(); ++p) {
		do_command("-t mangle -A " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", p->c_str(), FW_MARK_KNOWN);
	}
}

} /* namespace wrtclient */
