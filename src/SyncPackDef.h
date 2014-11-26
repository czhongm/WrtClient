/*
 * SyncPackDef.h
 *
 *  Created on: 2014年11月13日
 *      Author: czm
 */

#ifndef SYNCPACKDEF_H_
#define SYNCPACKDEF_H_


#define SYNCPACK_HEADTAG	0x88
#define SYNCPACK_VERSION		0x01

#define SYNCPACK_TYPE_AUTH		0x01
#define SYNCPACK_TYPE_AUTH_RESP		0x81
#define SYNCPACK_TYPE_DHCP	0x02
#define SYNCPACK_TYPE_DHCP_RESP		0x82
#define SYNCPACK_TYPE_APP	0x03
#define SYNCPACK_TYPE_APP_RESP		0x83
#define SYNCPACK_TYPE_COUNTER	0x04

#define MAX_QUEUE_LEN	256

struct _sync_pack_header{
	unsigned char tag;
	unsigned char ver;
	unsigned char mac[6];
	unsigned char type;
	unsigned short length;
};
struct _sync_pack_data_auth{
	unsigned char gw_index;//待认证接口编号
	unsigned char mac[6];//待认证主机MAC地址
	unsigned char ip[4];//ip地址
};
struct _sync_pack_data_auth_resp{
	unsigned char gw_index;//待认证接口编号
	unsigned char mac[6];//待认证主机MAC地址
	unsigned char ip[4];//ip地址
	unsigned char result; //认证结果
};

struct _sync_pack_data_app{
	unsigned char gw_index;//接口编号
	unsigned char appid[32]; //APP Id编号
	unsigned char mac[6];//APP用户MAC地址
};

#define DHCP_ACTION_ADD	1
#define DHCP_ACTION_OLD	2
#define DHCP_ACTION_DEL	3

struct _sync_pack_data_dhcp{
	unsigned char action;	//动作类型
	unsigned char mac[6]; //MAC地址
	unsigned char ip[4]; //IP地址
	unsigned char hostname[32];//主机名称
};

struct _sync_pack_data_counter{
	unsigned char mac[6]; //MAC地址
	unsigned char ip[4]; //IP地址
	unsigned long long sendbytes; //发送字节
	unsigned long long recvbytes;//接收字节
};

#endif /* SYNCPACKDEF_H_ */
