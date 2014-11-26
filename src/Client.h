/*
 * Client.h
 *
 *  Created on: 2014年10月14日
 *      Author: czm
 */

#ifndef CLIENT_H_
#define CLIENT_H_



#define STATE_INVALIDATE 		0xFF
#define STATE_VALIDATION 		0
#define STATE_ALLOWED 			1
#define STATE_DENY						2

namespace wrtclient {

class Client {
public:
	Client(const char* szIp, const char* szMac, int state);
	Client(unsigned char* ip, unsigned char* mac, int state);
	virtual ~Client();

	void getIp(char* szIp);
	void getIp(unsigned char* ip);
	unsigned char* getIp(){return m_ip;};
	void getMac(char* szMac);
	void getMac(unsigned char* mac);
	unsigned char* getMac(){return m_mac;};
	void setState(int state);
	int getState() {
		return m_state;
	}
	int getOldState() {
		return m_oldstate;
	}
	time_t getLastupdate() const;
	unsigned long long getRecv() const;
	void setRecv(unsigned long long recv);
	unsigned long long getSend() const;
	void setSend(unsigned long long send);

	bool equalMac(unsigned char* mac);
	bool equalIp(unsigned char* ip);
protected:
	unsigned char m_ip[4];
	unsigned char m_mac[6];
	int m_state;
	int m_oldstate;
	unsigned long long m_recv;
	unsigned long long m_send;
	time_t m_lastupdate;
};

} /* namespace wrtclient */

#endif /* CLIENT_H_ */
