/*
 * Client.h
 *
 *  Created on: 2014年10月14日
 *      Author: czm
 */

#ifndef CLIENT_H_
#define CLIENT_H_

#include <string>

using namespace std;

#define STATE_INVALIDATE 		0xFF
#define STATE_VALIDATION 		0
#define STATE_ALLOWED 			1


namespace wrtclient {

class Client {
public:
	Client(const char* ip,const char* mac,int state);
	virtual ~Client();

	void setState(int state);
	int getState(){return m_state;}
	int getOldState(){return m_oldstate;};
public:
	string m_ip;
	string m_mac;
	unsigned long long m_recv;
	unsigned long long m_send;
	time_t	m_lastupdate;

protected:
	int 	m_state;
	int m_oldstate;
};

} /* namespace wrtclient */

#endif /* CLIENT_H_ */
