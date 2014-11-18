/*
 * WebServer.h
 *
 *  Created on: 2014年10月14日
 *      Author: czm
 */

#ifndef WEBSERVER_H_
#define WEBSERVER_H_

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include <string>

#include "Wifidog.h"

using namespace std;

namespace wrtclient {

class Wifidog;

class WebServer {
public:
	WebServer(Wifidog* pParent,int port,const char* docroot);
	virtual ~WebServer();

	bool	init();
	void start();
	void stop();

	static void send_document_cb(struct evhttp_request *req, void *arg);
	static void do_wifidog_cb(struct evhttp_request* req, void* arg);
	static void do_app_cb(struct evhttp_request* req,void* arg);
protected:
	void do_senddoc(struct evhttp_request *req);
	void do_wifidog(struct evhttp_request* req);
	void do_app(struct evhttp_request* req);
	void do_allow(struct evhttp_request* req);

	void send_html(struct evhttp_request* req,const char* path);

	int	m_port;
	string m_docroot;

	struct event_base*	m_evbase;
	struct evhttp *m_evhttp;
	struct evhttp_bound_socket *m_evhandler;

	Wifidog* m_pParent;

	bool m_bTerminated;
};

} /* namespace wrtclient */

#endif /* WEBSERVER_H_ */
