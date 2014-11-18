/*
 * global.h
 *
 *  Created on: 2014年11月3日
 *      Author: czm
 */

#ifndef GLOBAL_H_
#define GLOBAL_H_

#define MAX_BUF	4096

#define GW_PORT	2060

#include <libconfig.h>

using namespace std;
extern bool g_bTerminated;
extern config_t g_cfg;

#endif /* GLOBAL_H_ */
