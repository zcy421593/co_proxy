#ifndef HTTP_UPSTREAM_H
#define HTTP_UPSTREAM_H
#include "co_socket.h"
#include "http_request_header.h"
#include "http_response_header.h"
class http_upstream {
public:
	http_upstream(co_base* base, co_socket* sock);
	http_request_header* read_header();
	int write_response_header(http_response_header* resp);
	int write_body(char* body, int len);
	int read_body(char* body, int len);
	void complete_body();
	bool is_request_complete();
private:
	int read_chunk_hdr();
	co_socket* sock_client_;
	co_base* sock_base_;
	http_request_header* req;
	int current_chunk_len_;
	int chunk_read_len_;
	int64_t body_read_;
};
#endif
