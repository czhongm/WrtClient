/*
 * Utils.cpp
 *
 *  Created on: 2014年10月13日
 *      Author: czm
 */

#include "Utils.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include "EventLog.h"

namespace wrtclient {

Utils::Utils() {

}

Utils::~Utils() {
}

int Utils::execute(const char* cmd_line, bool quiet) {
	int pid, status, rc;

	const char *new_argv[4];
	new_argv[0] = "/bin/sh";
	new_argv[1] = "-c";
	new_argv[2] = cmd_line;
	new_argv[3] = NULL;

	pid = safe_fork();
	if (pid == 0) { /* for the child process:         */
		/* We don't want to see any errors if quiet flag is on */
		if (quiet)
			close(2);
		if (execvp("/bin/sh", (char * const *) new_argv) == -1) { /* execute the command  */
			EventLog::trace(TRACE_ERROR, "execvp(): %s", strerror(errno));
		} else {
			EventLog::trace(TRACE_ERROR, "execvp() failed");
		}
		exit(1);
	}

	/* for the parent:      */
	EventLog::trace(TRACE_INFO, "Waiting for PID %d to exit", pid);
	rc = waitpid(pid, &status, 0);
	EventLog::trace(TRACE_INFO, "Process PID %d exited", rc);

	return (WEXITSTATUS(status));
}

pid_t Utils::safe_fork() {
	pid_t result;
	result = fork();

	if (result == -1) {
		EventLog::trace(TRACE_ERROR, "Failed to fork: %s.  Bailing out", strerror(errno));
		exit(1);
	} else if (result == 0) {
	}

	return result;
}
void * Utils::safe_malloc (size_t size) {
	void * retval = NULL;
	retval = malloc(size);
	if (!retval) {
		EventLog::trace(TRACE_ERROR, "Failed to malloc %d bytes of memory: %s.  Bailing out", size, strerror(errno));
		exit(1);
	}
	return (retval);
}

char * Utils::safe_strdup(const char *s) {
	char * retval = NULL;
	if (!s) {
		EventLog::trace(TRACE_ERROR, "safe_strdup called with NULL which would have crashed strdup. Bailing out");
		exit(1);
	}
	retval = strdup(s);
	if (!retval) {
		EventLog::trace(TRACE_ERROR, "Failed to duplicate a string: %s.  Bailing out", strerror(errno));
		exit(1);
	}
	return (retval);
}

int Utils::safe_asprintf(char **strp, const char *fmt, ...) {
	va_list ap;
	int retval;

	va_start(ap, fmt);
	retval = safe_vasprintf(strp, fmt, ap);
	va_end(ap);

	return (retval);
}

int Utils::safe_vasprintf(char **strp, const char *fmt, va_list ap) {
	int retval;

	retval = vasprintf(strp, fmt, ap);

	if (retval == -1) {
		EventLog::trace(TRACE_ERROR, "Failed to vasprintf: %s.  Bailing out", strerror(errno));
		exit (1);
	}
	return (retval);
}

string Utils::arp_get(const char *req_ip){
    FILE           *proc;
	 char ip[16];
	 char mac[18];
	 string reply;

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }

    /* Skip first line */
	 while (!feof(proc) && fgetc(proc) != '\n');

	 /* Find ip, copy mac in reply */
	 reply = "";
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		  if (strcmp(ip, req_ip) == 0) {
				reply = mac;
				break;
		  }
    }

    fclose(proc);

    return reply;
}


} /* namespace wrtclient */
