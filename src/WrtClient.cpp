//============================================================================
// Name        : WrtClient.cpp
// Author      : czhongm
// Version     :
// Copyright   : tgrass
// Description : Main cpp
//============================================================================

#include <iostream>
using namespace std;

#include <stdlib.h>
#include<unistd.h>
#include <signal.h>

#include "global.h"

#include "EventLog.h"
#include "SyncClient.h"
#include "Wifidog.h"
#include "DhcpMon.h"
using namespace wrtclient;

#define CONFIG_PATH	"/etc/wrtclient.conf"
#define DEFAULT_CLOUDSERVER "218.244.131.138"
#define DEFAULT_CLOUDPORT	9432

bool g_bTerminated;

char config_path[32];

void parse_commandline(int argc, char** argv) {
	int c;
	while (-1 != (c = getopt(argc, argv, "d:c:"))) {
		switch (c) {
		case 'd':
			if (optarg) {
				EventLog::s_debug_level = atoi(optarg);
			}
			break;
		case 'c':
			if (optarg) {
				strcpy(config_path, optarg);
			}
			break;
		default:
			break;
		}
	}
}

/**
 * 处理系统信号
 * @param singno 信号
 */
void SignalTerminateHandler(int singno) {
	g_bTerminated = true;
}

void* SyncThread(void* param) {
	SyncClient* syncclient = (SyncClient*) param;
	syncclient->start();
	return (void*) 0;
}

void* WifidogThread(void* param) {
	Wifidog* pWifidog = (Wifidog*) param;
	pWifidog->init();
	pWifidog->start();
	return (void*) 0;
}

void * DhcpmonThread(void* param){
	DhcpMon* pDhcpmon = (DhcpMon*)param;
	pDhcpmon->start();
	return (void*) 0;
}

int main(int argc, char** argv) {
	char szCloudIp[32],szInterface[64];
	int nCloudPort = DEFAULT_CLOUDPORT;
	strcpy(szCloudIp, DEFAULT_CLOUDSERVER);

	signal(SIGTERM, SignalTerminateHandler);
	signal(SIGHUP, SignalTerminateHandler);
	signal(SIGINT, SignalTerminateHandler);

	g_bTerminated = false;
	strcpy(config_path, CONFIG_PATH);
	parse_commandline(argc, argv);

	config_t g_cfg;
	config_init(&g_cfg);
	if (!config_read_file(&g_cfg, config_path)) {
		EventLog::trace(TRACE_ERROR, "cann't read config from %s", config_path);
		config_destroy(&g_cfg);
		return (EXIT_FAILURE);
	}
	config_setting_t *setting;
	setting = config_lookup(&g_cfg, "cloudserver");
	if (setting != NULL) {
		const char* ip;
		int port;
		const char* interface;
		if (config_setting_lookup_string(setting, "ip", &ip)) {
			strcpy(szCloudIp, ip);
		}
		if (config_setting_lookup_int(setting, "port", &port)) {
			nCloudPort = port;
		}
		if (config_setting_lookup_string(setting, "Interface", &interface)) {
			strcpy(szInterface, interface);
		}
	}
	setting = config_lookup(&g_cfg, "auth");
	if (setting != NULL) {
		int count = config_setting_length(setting);
		for (int i = 0; i < count; ++i) {
			config_setting_t *auth = config_setting_get_elem(setting, i);
			Wifidog* pDog = new Wifidog(auth);
			g_lstWifidog.push_back(pDog);
		}
	}
	config_destroy(&g_cfg);

	//启动同步线程
	g_syncclient = new SyncClient(szCloudIp, nCloudPort,szInterface);
	pthread_t thread_sync;
	pthread_create(&thread_sync, NULL, SyncThread, g_syncclient);

	//启动wifidog线程
	vector<pthread_t> thread_wifidog_list;
	vector<Wifidog*>::iterator p = g_lstWifidog.begin();
	for (; p != g_lstWifidog.end(); ++p) {
		pthread_t thread_wifidog;
		pthread_create(&thread_wifidog, NULL, WifidogThread, *p);
		thread_wifidog_list.push_back(thread_wifidog);
	}

	//创建DHCP监控线程
	DhcpMon* pDhcpMon = new DhcpMon();
	pthread_t thread_dhcpmon;
	pthread_create(&thread_dhcpmon,NULL,DhcpmonThread,pDhcpMon);

	while (!g_bTerminated) {
		usleep(300 * 1000);
	}

	//停止并销毁DHCP监控线程
	EventLog::trace(TRACE_DEBUG, "Stop DhcpMon");
	pDhcpMon->stop();
	pthread_cancel(thread_dhcpmon);
	pthread_join(thread_dhcpmon,NULL);
	delete pDhcpMon;

	//停止Wifidog线程
	EventLog::trace(TRACE_DEBUG, "Stop Wifidog");
	p = g_lstWifidog.begin();
	for (; p != g_lstWifidog.end(); ++p) {
		(*p)->stop();
	}
	//等待线程结束
	vector<pthread_t>::iterator t = thread_wifidog_list.begin();
	for(;t!=thread_wifidog_list.end();++t){
		pthread_join(*t,NULL);
	}

	for (size_t i = 0; i < g_lstWifidog.size(); i++) {
		Wifidog* pDog = g_lstWifidog[i];
		delete pDog;
	}

	//停止同步线程，并清理
	EventLog::trace(TRACE_DEBUG, "Stop SyncClient");
	g_syncclient->stop();
	pthread_join(thread_sync, NULL);
	delete g_syncclient;
	g_syncclient = NULL;
	return 0;
}
