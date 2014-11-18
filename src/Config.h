/*
 * Config.h
 *
 *  Created on: 2014年10月13日
 *      Author: czm
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <string>

using namespace std;

namespace wrtclient {

class Config {
public:
	Config();
	virtual ~Config();

protected:
	string 	m_auth_server;
};

} /* namespace wrtclient */

#endif /* CONFIG_H_ */
