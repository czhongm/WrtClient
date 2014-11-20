/*
 * DhcpMon.cpp
 *
 *  Created on: 2014年10月11日
 *      Author: czm
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "global.h"
#include "DhcpMon.h"
#include "EventLog.h"
#include "Utils.h"
#include "SyncClient.h"
#include "Wifidog.h"

namespace wrtclient {

DhcpMon::DhcpMon() {
	m_bTerminated = false;
	m_socket = -1;
}

DhcpMon::~DhcpMon() {
}

void DhcpMon::start() {
	int *fd;
	char sock_name[64];
	struct sockaddr_un sa_un;
	int result;
	pthread_t tid;
	socklen_t len;

	strcpy(sock_name,DEFAULT_DHCPMON_SOCK);

	EventLog::trace(TRACE_DEBUG, "Starting dhcpmon.");

	memset(&sa_un, 0, sizeof(sa_un));
	EventLog::trace(TRACE_DEBUG, "Socket name: %s", sock_name);

	if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
		EventLog::trace(TRACE_ERROR, "DHCPMon socket name too long");
		exit(1);
	}

	EventLog::trace(TRACE_DEBUG, "Creating socket");
	m_socket = socket(PF_UNIX, SOCK_STREAM, 0);

	EventLog::trace(TRACE_DEBUG, "Got server socket %d", m_socket);

	/* If it exists, delete... Not the cleanest way to deal. */
	unlink(sock_name);

	EventLog::trace(TRACE_DEBUG, "Filling sockaddr_un");
	strcpy(sa_un.sun_path, sock_name);
	sa_un.sun_family = AF_UNIX;

	EventLog::trace(TRACE_DEBUG, "Binding socket (%s)", sa_un.sun_path, strlen(sock_name));

	/* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
	if (bind(m_socket, (struct sockaddr *) &sa_un, strlen(sock_name) + sizeof(sa_un.sun_family))) {
		EventLog::trace(TRACE_ERROR, "Could not bind control socket: %s", strerror(errno));
		pthread_exit (NULL);
	}

	if (listen(m_socket, 5)) {
		EventLog::trace(TRACE_ERROR, "Could not listen on control socket: %s", strerror(errno));
		pthread_exit (NULL);
	}

	while (!m_bTerminated) {
		len = sizeof(sa_un);
		memset(&sa_un, 0, len);
		fd = (int *) Utils::safe_malloc(sizeof(int));
		if ((*fd = accept(m_socket, (struct sockaddr *) &sa_un, &len)) == -1) {
			EventLog::trace(TRACE_ERROR, "Accept failed on control socket: %s", strerror(errno));
			free(fd);
		} else {
			EventLog::trace(TRACE_DEBUG, "Accepted connection on wdctl socket %d (%s)", fd, sa_un.sun_path);
			result = pthread_create(&tid, NULL, &DhcpMon::thread_handler, (void *) fd);
			if (result != 0) {
				EventLog::trace(TRACE_ERROR, "FATAL: Failed to create a new thread (wdctl handler) - exiting");
				free(fd);
			}
			pthread_detach(tid);
		}
	}

}

void * DhcpMon::thread_handler(void *arg){
	int	fd,
		done,
		i;
	char	request[MAX_BUF];
	ssize_t	read_bytes,
		len;

	EventLog::trace(TRACE_DEBUG, "Entering thread_handler....");

	fd = *((int *) arg);
	free(arg);
	EventLog::trace(TRACE_DEBUG, "Read bytes and stuff from %d", fd);

	/* Init variables */
	read_bytes = 0;
	done = 0;
	memset(request, 0, sizeof(request));

	/* Read.... */
	while (!done && read_bytes < (sizeof(request) - 1)) {
		len = read(fd, request + read_bytes,
				sizeof(request) - read_bytes);

		/* Have we gotten a command yet? */
		for (i = read_bytes; i < (read_bytes + len); i++) {
			if (request[i] == '\r' || request[i] == '\n') {
				request[i] = '\0';
				done = 1;
			}
		}

		/* Increment position */
		read_bytes += len;
	}
	EventLog::trace(TRACE_DEBUG,"request=%s",request);
	unsigned char action = 0;
	if (strncmp(request, " add", 4) == 0) {
		action = DHCP_ACTION_ADD;
	} else if (strncmp(request, " old", 4) == 0) {
		action = DHCP_ACTION_OLD;
	} else if (strncmp(request, " del", 4) == 0) {
		action = DHCP_ACTION_DEL;
	}
	if(g_syncclient) {
		char act[8],mac[32],ip[32],hostname[32];
		sscanf(request,"%s %s %s %s",act,mac,ip,hostname);
		g_syncclient->syncDhcp(action,mac,ip,hostname);
		for(unsigned int i=0;i<g_lstWifidog.size();i++){
			g_syncclient->authClient(i,mac,ip);
		}
	}

	if(write(fd, "Done", 4) == -1){
		EventLog::trace(TRACE_ERROR, "Unable to write Yes: %s", strerror(errno));
	}

	if (!done) {
		EventLog::trace(TRACE_ERROR, "Invalid dhcpmon request.");
		shutdown(fd, 2);
		close(fd);
		pthread_exit(NULL);
	}

	EventLog::trace(TRACE_DEBUG, "Request received: [%s]", request);

	shutdown(fd, 2);
	close(fd);
	EventLog::trace(TRACE_DEBUG, "Exiting thread_handler....");

	return NULL;
}

} /* namespace wrtclient */
