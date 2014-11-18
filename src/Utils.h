/*
 * Utils.h
 *
 *  Created on: 2014年10月13日
 *      Author: czm
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>

using namespace std;

namespace wrtclient {

class Utils {
public:
	Utils();
	virtual ~Utils();

	static int execute(const char* cmd_line,bool quiet);

	static pid_t safe_fork() ;
	static void * safe_malloc (size_t size);
	static char * safe_strdup(const char *s);
	static int safe_asprintf(char **strp, const char *fmt, ...);
	static int safe_vasprintf(char **strp, const char *fmt, va_list ap);
	static string arp_get(const char *req_ip);
};

} /* namespace wrtclient */

#endif /* UTILS_H_ */
