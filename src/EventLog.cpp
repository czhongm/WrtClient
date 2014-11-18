/*
 * EventLog.cpp
 *
 *  Created on: 2014年7月14日
 *      Author: czm
 */

#include "EventLog.h"
int EventLog::s_debug_level = 0;
EventLog::EventLog() {
}

EventLog::~EventLog() {
}

void EventLog::trace(int eventTraceLevel, const char* file, int line, const char * format, ...) {
	if (eventTraceLevel <= s_debug_level) {
		va_list va_ap;
		char buf[2048];
		char out_buf[640];
		char theDate[32];
		char extra_msg[32];
		time_t theTime = time(NULL);

		/* We have two paths - one if we're logging, one if we aren't
		 *   Note that the no-log case is those systems which don't support it (WIN32),
		 *                                those without the headers !defined(USE_SYSLOG)
		 *                                those where it's parametrically off...
		 */

		memset(buf, 0, sizeof(buf));
		strftime(theDate, sizeof(theDate), "%d/%b/%Y %H:%M:%S", localtime(&theTime));

		va_start(va_ap, format);
		vsnprintf(buf, sizeof(buf) - 1, format, va_ap);
		va_end(va_ap);

		if (eventTraceLevel == 0 /* TRACE_ERROR */)
			strcpy(extra_msg,"ERROR: ");
		else if (eventTraceLevel == 1 /* TRACE_WARNING */)
			strcpy(extra_msg, "WARNING: ");
		else
				extra_msg[0] = '\0';

		while (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		snprintf(out_buf, sizeof(out_buf), "%s [%11s:%4d] %s%s", theDate, file, line, extra_msg, buf);
		printf("%s\n", out_buf);
		fflush(stdout);
	}
}
