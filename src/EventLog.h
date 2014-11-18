/*
 * EventLog.h
 *
 *  Created on: 2014年7月14日
 *      Author: czm
 *
 *      调试日志类
 */

#ifndef EVENTLOG_H_
#define EVENTLOG_H_

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__
#define TRACE_DEBUG     4, __FILE__, __LINE__

class EventLog {
public:
	EventLog();
	virtual ~EventLog();

public:
	static void trace(int eventTraceLevel, const char* file, int line, const char * format, ...);

	static int	s_debug_level;
};

#endif /* EVENTLOG_H_ */
