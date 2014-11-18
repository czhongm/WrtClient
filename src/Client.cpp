/*
 * Client.cpp
 *
 *  Created on: 2014年10月14日
 *      Author: czm
 */

#include "Client.h"

namespace wrtclient {

Client::Client(const char* ip,const char* mac,int state) :
	m_ip(ip),m_mac(mac),m_state(state),m_oldstate(STATE_INVALIDATE){
	m_lastupdate = 0;
	m_recv = 0;
	m_send = 0;
}

Client::~Client() {

}

void Client::setState(int state){
	m_oldstate = m_state;
	m_state = state;
}

} /* namespace wrtclient */
