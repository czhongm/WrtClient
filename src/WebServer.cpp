/*
 * WebServer.cpp
 *
 *  Created on: 2014年10月14日
 *      Author: czm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "SyncClient.h"
#include "WebServer.h"
#include "EventLog.h"
#include "Utils.h"

namespace wrtclient {

static const struct table_entry {
	const char *extension;
	const char *content_type;
} content_type_table[] = { { "txt", "text/plain" }, { "c", "text/plain" }, { "h", "text/plain" }, { "html", "text/html" }, { "htm", "text/htm" }, { "css",
		"text/css" }, { "gif", "image/gif" }, { "jpg", "image/jpeg" }, { "jpeg", "image/jpeg" }, { "png", "image/png" }, { "pdf", "application/pdf" }, { "ps",
		"application/postsript" }, { NULL, NULL }, };

static const char *
guess_content_type(const char *path) {
	const char *last_period, *extension;
	const struct table_entry *ent;
	last_period = strrchr(path, '.');
	if (!last_period || strchr(last_period, '/'))
		goto not_found;
	/* no exension */
	extension = last_period + 1;
	for (ent = &content_type_table[0]; ent->extension; ++ent) {
		if (!evutil_ascii_strcasecmp(ent->extension, extension))
			return ent->content_type;
	}

	not_found: return "application/misc";
}

WebServer::WebServer(Wifidog* pParent, int port, const char* docroot) {
	m_pParent = pParent;
	m_port = port;
	m_docroot = docroot;
	m_evbase = NULL;
	m_evhttp = NULL;
	m_evhandler = NULL;
}

WebServer::~WebServer() {
	if (m_evhttp)
		evhttp_free(m_evhttp);
	if (m_evbase)
		event_base_free(m_evbase);
}

bool WebServer::init() {
	EventLog::trace(TRACE_DEBUG, "start init....");
	m_evbase = event_base_new();
	if (!m_evbase) {
		EventLog::trace(TRACE_ERROR, "couldn't create an event_base!");
		return false;
	}
	m_evhttp = evhttp_new(m_evbase);
	if (!m_evhttp) {
		EventLog::trace(TRACE_ERROR, "couldn't create an evhttp!");
		event_base_free(m_evbase);
		m_evbase = NULL;
		return false;
	}
	EventLog::trace(TRACE_DEBUG, "create an evhttp OK!");
	evhttp_set_cb(m_evhttp, "/html", WebServer::send_document_cb, this);
	evhttp_set_cb(m_evhttp, "/app", WebServer::do_app_cb, this);
	evhttp_set_gencb(m_evhttp, WebServer::do_wifidog_cb, this);

	EventLog::trace(TRACE_DEBUG, "evhttp_set_cb OK!");
	m_evhandler = evhttp_bind_socket_with_handle(m_evhttp, "0.0.0.0", m_port);
	if (!m_evhandler) {
		EventLog::trace(TRACE_ERROR, "couldn't bind socket by evhttp_bind !");
		evhttp_free(m_evhttp);
		m_evhttp = NULL;
		event_base_free(m_evbase);
		m_evbase = NULL;
		return false;
	}
	return true;
}

void WebServer::start() {
	if (m_evbase){
		event_base_dispatch(m_evbase);
	}
}

void WebServer::stop() {
	m_bTerminated = true;
	event_base_loopexit(m_evbase,NULL);

}

void WebServer::send_document_cb(struct evhttp_request *req, void *arg) {
	WebServer* pServer = (WebServer*) arg;
	if (pServer)
		pServer->do_senddoc(req);
}

void WebServer::do_wifidog_cb(struct evhttp_request* req, void* arg) {
	WebServer* pServer = (WebServer*) arg;
	if (pServer)
		pServer->do_wifidog(req);
}

void WebServer::do_app_cb(struct evhttp_request* req, void* arg) {
	WebServer* pServer = (WebServer*) arg;
	if (pServer)
		pServer->do_app(req);
}

void WebServer::do_senddoc(struct evhttp_request *req) {
	struct evbuffer *evb = NULL;
	const char *docroot = m_docroot.c_str();
	const char *uri = evhttp_request_get_uri(req);
	struct evhttp_uri *decoded = NULL;
	const char *path;
	char *decoded_path;
	char *whole_path = NULL;
	size_t len;
	int fd = -1;
	struct stat st;

	EventLog::trace(TRACE_DEBUG, "Start send doc....");

	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
		EventLog::trace(TRACE_WARNING, "Invalid method!");
		return;
	}

	/* Decode the URI */
	decoded = evhttp_uri_parse(uri);
	if (!decoded) {
		EventLog::trace(TRACE_WARNING, "It's not a good URI. Sending BADREQUEST");
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}

	/* Let's see what path the user asked for. */
	path = evhttp_uri_get_path(decoded);
	if (!path)
		path = "/";

	/* We need to decode it, to see what path the user really wanted. */
	decoded_path = evhttp_uridecode(path, 0, NULL);
	if (decoded_path == NULL)
		goto err;
	/* Don't allow any ".."s in the path, to avoid exposing stuff outside
	 * of the docroot.  This test is both overzealous and underzealous:
	 * it forbids aceptable paths like "/this/one..here", but it doesn't
	 * do anything to prevent symlink following." */
	if (strstr(decoded_path, ".."))
		goto err;

	len = strlen(decoded_path) + strlen(docroot) + 2;
	if (!(whole_path = (char*) malloc(len))) {
		EventLog::trace(TRACE_ERROR, "malloc");
		goto err;
	}
	evutil_snprintf(whole_path, len, "%s/%s", docroot, decoded_path);

	if (stat(whole_path, &st) < 0) {
		goto err;
	}

	/* This holds the content we're sending. */
	evb = evbuffer_new();

	if (S_ISDIR(st.st_mode)) { //default use index.html
		EventLog::trace(TRACE_DEBUG, "not support directory!");
		goto err;
	} else {
		/* Otherwise it's a file; add it to the buffer to get
		 * sent via sendfile */
		const char *type = guess_content_type(decoded_path);
		if ((fd = open(whole_path, O_RDONLY)) < 0) {
			EventLog::trace(TRACE_ERROR, "cann't open file %s", whole_path);
			goto err;
		}

		if (fstat(fd, &st) < 0) {
			/* Make sure the length still matches, now that we
			 * opened the file :/ */
			EventLog::trace(TRACE_ERROR, "cann't fstat %s", whole_path);
			goto err;
		}
		evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", type);
		evbuffer_add_file(evb, fd, 0, st.st_size);
	}

	evhttp_send_reply(req, 200, "OK", evb);
	goto done;
	err: evhttp_send_error(req, 404, "Document was not found");
	if (fd >= 0)
		close(fd);
	done: if (decoded)
		evhttp_uri_free(decoded);
	if (decoded_path)
		free(decoded_path);
	if (whole_path)
		free(whole_path);
	if (evb)
		evbuffer_free(evb);
}

void WebServer::send_html(struct evhttp_request *req, const char* path) {
	struct evbuffer *evb = NULL;
	const char *docroot = m_docroot.c_str();
	char *decoded_path;
	char *whole_path = NULL;
	size_t len;
	int fd = -1;
	struct stat st;

	/* We need to decode it, to see what path the user really wanted. */
	decoded_path = evhttp_uridecode(path, 0, NULL);
	if (decoded_path == NULL)
		goto err;
	/* Don't allow any ".."s in the path, to avoid exposing stuff outside
	 * of the docroot.  This test is both overzealous and underzealous:
	 * it forbids aceptable paths like "/this/one..here", but it doesn't
	 * do anything to prevent symlink following." */
	if (strstr(decoded_path, ".."))
		goto err;

	len = strlen(decoded_path) + strlen(docroot) + 2;
	if (!(whole_path = (char*) malloc(len))) {
		EventLog::trace(TRACE_ERROR, "malloc");
		goto err;
	}
	evutil_snprintf(whole_path, len, "%s/%s", docroot, decoded_path);

	EventLog::trace(TRACE_DEBUG, "whole_path=%s", whole_path);

	if (stat(whole_path, &st) < 0) {
		goto err;
	}

	/* This holds the content we're sending. */
	evb = evbuffer_new();

	if (S_ISDIR(st.st_mode)) { //default use index.html
		EventLog::trace(TRACE_DEBUG, "not support directory!");
		goto err;
	} else {
		/* Otherwise it's a file; add it to the buffer to get
		 * sent via sendfile */
		const char *type = guess_content_type(decoded_path);
		if ((fd = open(whole_path, O_RDONLY)) < 0) {
			EventLog::trace(TRACE_ERROR, "cann't open file %s", whole_path);
			goto err;
		}

		if (fstat(fd, &st) < 0) {
			/* Make sure the length still matches, now that we
			 * opened the file :/ */
			EventLog::trace(TRACE_ERROR, "cann't fstat %s", whole_path);
			goto err;
		}
		evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", type);
		evbuffer_add_file(evb, fd, 0, st.st_size);
	}

	evhttp_send_reply(req, 200, "OK", evb);
	EventLog::trace(TRACE_DEBUG, "200 OK");
	goto done;
	err: EventLog::trace(TRACE_DEBUG, "404 Document was not found");
	evhttp_send_error(req, 404, "Document was not found");
	if (fd >= 0)
		close(fd);
	done: if (decoded_path)
		free(decoded_path);
	if (whole_path)
		free(whole_path);
	if (evb)
		evbuffer_free(evb);
}

void WebServer::do_wifidog(struct evhttp_request* req) {
	char *peer_addr;
	ev_uint16_t peer_port;
	const char *uri = evhttp_request_get_uri(req);
	struct evhttp_uri *decoded = NULL;
	const char *path;
	char *decoded_path;
	decoded = evhttp_uri_parse(uri);
	if (!decoded) {
		EventLog::trace(TRACE_DEBUG, "It's not a good URI. Sending BADREQUEST\n");
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}

	/* Let's see what path the user asked for. */
	path = evhttp_uri_get_path(decoded);
	if (!path)
		path = "/";

	/* We need to decode it, to see what path the user really wanted. */
	decoded_path = evhttp_uridecode(path, 0, NULL);
	if (decoded_path != NULL) {
		if (strstr(decoded_path, "/html") == decoded_path) {
			EventLog::trace(TRACE_DEBUG, "static html from /html");
			if (decoded)
				evhttp_uri_free(decoded);
			if (decoded_path)
				free(decoded_path);
			do_senddoc(req);
			return;
		} else if (strstr(decoded_path, "/app.gif") == decoded_path) {
			EventLog::trace(TRACE_DEBUG, "do_app url=%s",uri);
			if (decoded)
				evhttp_uri_free(decoded);
			if (decoded_path)
				free(decoded_path);
			do_app(req);
			return;
		}
	}

	EventLog::trace(TRACE_DEBUG, "do_wifidog process %s", evhttp_request_get_host(req));
	struct evhttp_connection* conn = evhttp_request_get_connection(req);
	evhttp_connection_get_peer(conn, &peer_addr, &peer_port);
//根据ip地址获取mac地址
	Client* pClient = m_pParent->findClientByIp(peer_addr);
	if (pClient == NULL) {
		string mac = Utils::arp_get(peer_addr);
		pClient = new Client(peer_addr, mac.c_str(), STATE_VALIDATION);
		m_pParent->m_clients.push_back(pClient);
		EventLog::trace(TRACE_DEBUG, "can't find client ip=%s mac=%s", peer_addr, mac.c_str());
	} else {
		EventLog::trace(TRACE_DEBUG, "founded client ip=%s mac=%s.", pClient->m_ip.c_str(), pClient->m_mac.c_str());
	}
	if (strstr(decoded_path, "/checkimg.png") == decoded_path) {
		EventLog::trace(TRACE_DEBUG, "allow client ip=%s mac=%s.", pClient->m_ip.c_str(), pClient->m_mac.c_str());
		m_pParent->allowClient(pClient);
		send_html(req,"html/blank.png");
	} else {
		switch (pClient->getState()) {
		case STATE_VALIDATION:
			EventLog::trace(TRACE_DEBUG, "/html/index.html");
			send_html(req, "html/index.html");
			break;
		case STATE_ALLOWED:
			EventLog::trace(TRACE_DEBUG, "/html/welcome.html");
			send_html(req, "html/welcome.html");
			break;
		}
	}
	if (decoded)
		evhttp_uri_free(decoded);
	if (decoded_path)
		free(decoded_path);
//evhttp_connection_free(conn);
	EventLog::trace(TRACE_DEBUG, "end do_wifidog....");
}

void WebServer::do_app(struct evhttp_request* req) {
	struct evbuffer *evb = NULL;
	char *peer_addr;
	ev_uint16_t peer_port;
	char szAppId[32];
	EventLog::trace(TRACE_DEBUG, "Start do_app....");
	struct evkeyvalq *headers;
	struct evkeyval *header;
	memset(szAppId,0,sizeof(szAppId));
	headers = evhttp_request_get_input_headers(req);
	for (header = headers->tqh_first; header;
	    header = header->next.tqe_next) {
		EventLog::trace(TRACE_DEBUG,"  %s: %s\n", header->key, header->value);
	}

	struct evhttp_connection* conn = evhttp_request_get_connection(req);
	evhttp_connection_get_peer(conn, &peer_addr, &peer_port);
//根据ip地址获取mac地址
	Client* pClient = m_pParent->findClientByIp(peer_addr);
	if (pClient == NULL) {
		string mac = Utils::arp_get(peer_addr);
		pClient = new Client(peer_addr, mac.c_str(), STATE_ALLOWED);
		m_pParent->m_clients.push_back(pClient);
	} else {
		pClient->setState(STATE_ALLOWED);
	}
	m_pParent->allowClient(pClient);
	g_syncclient->postApp(m_pParent->m_index,szAppId,pClient->m_mac.c_str());

	evb = evbuffer_new();
	evbuffer_add_printf(evb, "ok");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/html");
	evhttp_send_reply(req, 200, "{success:true}", evb);
	evbuffer_free(evb);
//evhttp_connection_free(conn);
	EventLog::trace(TRACE_DEBUG, "End do_app....");
}

} /* namespace wrtclient */
