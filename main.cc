#include "co_base.h"
#include "co_thread.h"
#include "co_socket.h"
#include <vector>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "dns.h"
#include "http_parser.h"
#include "utils.h"
#include "conn_pool.h"
#include "http_upstream.h"
#include "http_downstream.h"
using namespace std;

struct relay_info {
	co_socket* sock_read;
	co_socket* sock_send;
};

struct access_log {
	int64_t request_ts;
	string url;
	string host;
	string request_method;
	string error_reason;

	string status_code;
	int64_t dns_resolve_ts;
	int64_t connect_ts;
	int64_t response_ts;
	int64_t complete_ts;
	bool is_reuse_connection;

	access_log() : status_code("-1"),
				 dns_resolve_ts(-1),
				 connect_ts(-1),
				 response_ts(-1),
				 complete_ts(-1),
				 is_reuse_connection(false) {}
};

static int abstract_timespan(int64_t ts1, int64_t ts2) {
	if(ts1 < 0 || ts2 < 0) {
		return -1;
	}
	return ts1 - ts2;
}

static void dump_access_log(access_log* log) {

	if(log->url.empty()) {
		return;
	}

	FILE* file = fopen("access_log.txt", "a+");
	if(!file) {
		file = fopen("access_log.txt", "w");
	}

	if(!file) {
		return;
	}



	fprintf(file,"%lld\t"  // request ts
		                    "%s\t"     // method
			    "%s\t"     // url			   
			    "%s\t"     // host
			    "%ld\t"     // resolve ms
			    "%ld\t"	   // connect ms
			    "%ld\t"     // wait ms
			    "%ld\t"     // fetch ms
			    "%s\n",	   // error_reason
			    log->request_ts,
			    log->request_method.c_str(),
				log->url.c_str(),
				
				log->host.c_str(),
				abstract_timespan(log->dns_resolve_ts, log->request_ts),
				abstract_timespan(log->connect_ts, log->dns_resolve_ts),
				abstract_timespan(log->response_ts, log->connect_ts),
				abstract_timespan(log->complete_ts, log->response_ts),
				log->error_reason.c_str());
	fclose(file);
}
static void* relay_cb(co_thread* thread, void* args) {
	char buf[4096] = {};
	relay_info* info = (relay_info*)args;
	for(;;) {
		int ret = co_socket_read(info->sock_read, buf, sizeof(buf));
		if(ret <= 0) {
			co_socket_cancel(info->sock_send);
			break;
		}
		ret = co_socket_write(info->sock_send, buf, ret);
		if(ret <= 0) {
			co_socket_cancel(info->sock_read);
			break;
		}
	}
	printf("https relay complete\n");
	return NULL;
}

typedef float (*func_ptr)(float);

class FuncNew {
	public:
		func_ptr old_ptr;
		FuncNew(func_ptr ptr) {
			old_ptr = ptr;
		}
		float operator()(float a) {
			return old_ptr(a);
		}
};


FuncNew get_new_func(func_ptr old) {
	return FuncNew(old);
}

float old_func(float val) {
	return val;
}

void test() {
	FuncNew new_func = get_new_func(old_func);
	float val = new_func(12.3f);
}

static void* connect_cb(co_thread* thread, void* args) {
	bool err = false;
	static char buf[4096] = {};
	co_base* base = co_thread_get_base(thread);
	co_socket* sock_client = (co_socket*)args;
	for(;;) {
		access_log log_item;

		char host_ip[255] = {};
		bool is_reuse_conn = false;
		int ms_resolved = -1;


		bool do_continue = true;
		http_upstream* upstream = NULL;
		http_downstream* downstream = NULL;
		http_response_header* resp_hdr = NULL;
		upstream = new http_upstream(base, sock_client);
		http_request_header* req_hdr = upstream->read_header();
		log_item.request_ts = get_ms_now();
		int status_code = 0;
		if(!req_hdr) {
			log_item.error_reason = "read_request_failed";
			do_continue = false;
			goto complete_session;
		}
		log_item.request_method = req_hdr->method;
		log_item.url = req_hdr->url;

		if(req_hdr->method == "CONNECT") {
			const char* resp_str= "HTTP/1.1 200 Connection Established\r\n\r\n";
			
			co_socket* sock_relay = co_socket_create(base);
			const char* ip = dns_resolve(req_hdr->url_host.c_str());

			if(!ip) {
				fprintf(stderr, "%s resolve failed\n",  req_hdr->url_host.c_str());
				log_item.error_reason = "dns_resolve_failed";
				co_socket_close(sock_relay);
				do_continue = false;
				goto complete_session;
			}
			log_item.host = ip;
			log_item.dns_resolve_ts = get_ms_now();
			if(co_socket_connect(sock_relay, ip, req_hdr->url_port) != 0) {
				resp_str= "HTTP/1.1 503 Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
				co_socket_write(sock_client, (char*)resp_str, strlen(resp_str));
				log_item.error_reason = "connect_host_failed";
				co_socket_close(sock_relay);
				do_continue = false;
				goto complete_session;
			}
			co_socket_write(sock_client, (char*)resp_str, strlen(resp_str));
			log_item.connect_ts = get_ms_now();
			log_item.response_ts = get_ms_now();
			log_item.status_code = 200;
			relay_info* relay1 = new relay_info;
			relay1->sock_read = sock_client;
			relay1->sock_send = sock_relay;
			relay_info* relay2 = new relay_info;
			relay2->sock_read = sock_relay;
			relay2->sock_send = sock_client;

			co_thread* thread_relay1 = co_thread_create(base, relay_cb, relay1);
			co_thread* thread_relay2 = co_thread_create(base, relay_cb, relay2);
			co_thread_join(thread_relay1);
			co_thread_join(thread_relay2);
			delete relay1;
			delete relay2;
			co_thread_free(thread_relay1);
			co_thread_free(thread_relay2);
			co_socket_close(sock_relay);
			do_continue = false;
			log_item.complete_ts = get_ms_now();
			log_item.error_reason = "success";
			goto complete_session;
		}

		if(req_hdr->method == "POST" || req_hdr->method == "PUT") {

			if(req_hdr->content_length.empty() && req_hdr->transfer_encoding.empty()) {
				log_item.error_reason = "upload_without_length_info";
				do_continue = false;
				goto complete_session;
			}
		}

		downstream = new http_downstream(base, req_hdr);
		if(downstream->connect(host_ip, &ms_resolved, &is_reuse_conn) != 0) {
			log_item.host = host_ip;
			log_item.is_reuse_connection = is_reuse_conn;
			if(ms_resolved >= 0) {
				log_item.dns_resolve_ts = log_item.request_ts + ms_resolved;
			}
			
			log_item.error_reason = "connect_host_failed";
			do_continue = false;
			goto complete_session;
		}

		log_item.host = host_ip;
		log_item.is_reuse_connection = is_reuse_conn;
		if(ms_resolved >= 0) {
			log_item.dns_resolve_ts = log_item.request_ts + ms_resolved;
		}
		log_item.connect_ts = get_ms_now();

		downstream->write_request_header();

		if(req_hdr->get_header_value("Expect") == "100-continue") {
			const char* resp_str= "HTTP/1.1 100 CONTINUE\r\n\r\n";
			if(co_socket_write(sock_client, (char*)resp_str, strlen(resp_str)) < 0) {
				do_continue = false;
				goto complete_session;
			}
		}

		if(req_hdr->method == "POST" || req_hdr->method == "PUT") {
			bool err = false;
			for(;;) {
				int len_read = upstream->read_body(buf, sizeof(buf));
				if(len_read < 0) {
					err = true;
					break;
				} else if(len_read ==0) {
					if(downstream->complete_body() < 0) {
						err = true;
					}
					break;
				} else {
					if(downstream->write_body(buf, len_read) < 0) {
						err = true;
						break;
					}
				}
			}

			if(err) {
				do_continue = false;
				goto complete_session;
			}
		}
read_hdr:
		resp_hdr = downstream->read_response_header();
		if(!resp_hdr) {
			log_item.error_reason = "read_response_faield";
			do_continue = false;
			goto complete_session;
		}
		log_item.response_ts = get_ms_now();
		log_item.status_code = resp_hdr->status_code;
		if(resp_hdr->status_code == "100") {
			delete resp_hdr;
			goto read_hdr;
		}
		printf("status code=%s\n", resp_hdr->status_code.c_str());
		
		if(upstream->write_response_header(resp_hdr) < 0) {
			do_continue = false;
			goto complete_session;
		}

		status_code = atoi(resp_hdr->status_code.c_str());
		if(req_hdr->method == "HEAD" ||
		   (status_code > 100 && status_code <200) ||
		   status_code == 204 ||
		   status_code == 304) {
		   	do_continue = false;
			goto complete_session;
		}

		
		for(;;) {
			int len_read = downstream->read_body(buf, sizeof(buf));
			printf("downstream readbody ret:%d\n", len_read);
			if(len_read < 0) {
				log_item.error_reason = "read_body_failed";
				err = true;
				break;
			} else if(len_read ==0) {
				if(upstream->complete_body() < 0) {
					log_item.error_reason = "complete_body_failed";
					err = true;
				} else {
					log_item.complete_ts = get_ms_now();
					log_item.error_reason = "success";
				}
				break;
			} else {
				if(upstream->write_body(buf, len_read) < 0) {
					err = true;
					log_item.error_reason = "write_body_failed";
					break;
				}
			}
		}

		if(err || resp_hdr->version_str != "HTTP/1.1") {
			do_continue = false;
		}

		if(resp_hdr->get_header_value("Connection") == "close") {
			do_continue = false;
		}

		if(resp_hdr->get_header_value("Proxy-Connection") == "close") {
			do_continue = false;
		}

complete_session:
		dump_access_log(&log_item);
		if(upstream) {
			delete upstream;
			upstream = NULL;
		}

		if(downstream) {
			delete downstream;
			downstream = NULL;
		}
		
		if(!do_continue) {
			break;
		}
		
	}
	co_socket_close(sock_client);
	printf("write complete\n");
	return NULL;
}

void* listen_cb(co_thread* thread, void* args) {
	printf("listen start\n");
	co_base* base = co_thread_get_base(thread);
	co_socket* sock = co_socket_create(base);
	co_socket_bind(sock, "0.0.0.0", 8123);
	co_socket_listen(sock, 5);
	while(1) {
		co_socket* sock_client = co_socket_accept(sock);
		printf("accept a client\n");
		if(!sock_client) {
			break;
		}
		co_thread* th1 = co_thread_create(base, connect_cb, sock_client);
		co_thread_detach(th1);
	}
	co_socket_close(sock);
	printf("listen exited\n");
	return NULL;
}
void sig_int(int sig) {
	dns_cancel_all();
	co_socket_error_all();
	pool_cancel_all();
}

int main() {
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, sig_int);
	co_base* base = co_base_create();
	dns_init(base, "127.0.1.1");
	printf("dns init complete\n");
	co_thread* thread_listen = co_thread_create(base, listen_cb, NULL);
	co_thread_detach(thread_listen);
	co_base_dispatch(base);
}
