#include "http_downstream.h"
#include "conn_pool.h"
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "dns.h"
using namespace std;
http_downstream::http_downstream(co_base* base, http_request_header* req) {
	this->base_ = base;
	this->req_ = req;
	this->current_chunk_len_ = -1;
	this->chunk_read_len_ = 0;
	this->body_read_ = 0;
}

int http_downstream::connect() {
	assert(this->req_);
	int fd = pool_get_connection(this->req_->url_host, this->req_->url_port);
	if(fd != -1) {
		this->sock_ = co_socket_create_with_fd(this->base_, fd);
		return 0;
	}
	const char* ip = dns_resolve(this->req_->url_host.c_str());

	if(!ip || !ip[0]) {
		return -1;
	}

	this->sock_ = co_socket_create(this->base_);
	return co_socket_connect(this->sock_, ip, this->req_->url_port);
}

static int read_response_line(co_socket* sock, http_response_header* header) {
	char readbuf[512] = {};
	int len = co_socket_readline(sock, readbuf, sizeof(readbuf));
	if(len < 0) {
		return -1;
	}

	char* pos = strchr(readbuf, ' ');
	char* pos2 = strchr(pos + 1, ' ');

	if(pos2 == pos) {
		return -1;
	}

	if(strchr(pos + 1, ' ') != pos2) {
		return -1;
	}

	header->version_str.resize(pos - readbuf);
	strncpy((char*)header->version_str.c_str(), readbuf, pos - readbuf);
	header->status_code.resize(pos2 - pos - 1);
	strncpy((char*)header->status_code.c_str(), pos + 1, pos2 - pos -1);
	header->status_str.resize(len - (pos2 - readbuf + 1));
	strncpy((char*)header->status_str.c_str(), pos2 + 1, len - (pos2 - readbuf + 1));
	return 0;
}


static int read_response_field(co_socket* sock, vector<pair<string, string> >* vec_headers) {
	char readbuf[4096] = {};
	pair<string, string> p;
	int len = co_socket_readline(sock, readbuf, sizeof(readbuf));
	printf("read_response_field ,line len=%d\n", len);
	if(len < 0) {
		return -1;
	}

	if(len == 0) {
		return 1;
	}

	char* pos = strchr(readbuf, ':');
	if(!pos) {
		return -1;
	}

	p.first.resize(pos - readbuf);
	
	
	strncpy((char*)p.first.c_str(), readbuf, pos - readbuf);

	pos ++;
	//printf("after add pos=%s\n", pos);
	 while(*pos == ' ') {
	 	pos ++;
	 }
	 p.second.resize(len - (pos - readbuf));
	 strncpy((char*)p.second.c_str(), pos, len - (pos - readbuf));
	 vec_headers->push_back(p);
	 return 0;
}

static int read_response_header(co_socket* sock, http_response_header* header) {
	if(read_response_line(sock, header) != 0) {
		printf("read response line failed\n");
		return -1;
	}

	for(;;) {
		int ret = read_response_field(sock, &header->vec_headers);
		if(ret < 0) {
			return -1;
		}

		if(ret == 1) {
			break;
		}

		pair<string, string>& p = header->vec_headers[header->vec_headers.size() - 1];
		if(strcasecmp(p.first.c_str(), "Content-Length") == 0) {
			header->content_length = p.second;
		} else if(strcasecmp(p.first.c_str(), "Transfer-Encoding") == 0) {
			printf("read transfer encoding:%s\n", p.second.c_str());
			header->transfer_encoding = p.second;
		}

		printf("%s: %s\n", p.first.c_str(), p.second.c_str());



		
	}
	return 0;
}

int http_downstream::write_request_header() {
	std::string req_str;
	string req_path = req_->url_path;
	if(req_path.empty()) {
		req_path = "/";
	}

	if(!req_->url_query.empty()) {
		req_path.append("?").append(req_->url_query);
	}

	if(!req_->url_flagment.empty()) {
		req_path.append("#").append(req_->url_flagment);
	}

	append_format_string(req_str, "%s %s %s\r\n", 
						req_->method.c_str(),
						req_path.c_str(),
						req_->version_str.c_str());

	for(int i = 0; i < req_->vec_headers.size(); i++) {
		pair<string, string>& p = req_->vec_headers[i];
		append_format_string(req_str, "%s: %s\r\n", p.first.c_str(), p.second.c_str());
	}
	req_str.append("\r\n");
	printf("request hdr=%s\n", req_str.c_str());
	return co_socket_write(sock_, (char*)req_str.c_str(), req_str.size());
}

http_response_header* http_downstream::read_response_header() {
	this->resp_ = new http_response_header;
	if(::read_response_header(this->sock_, this->resp_) != 0) {
		delete this->resp_;
		this->resp_ = NULL;
		return NULL;
	}
	int status_code = atoi(this->resp_->status_code.c_str());
	if((status_code > 100 && status_code < 200) ||
		status_code == 204 ||
		status_code == 304) {
		int fd = co_socket_detach_fd(sock_);
		pool_queue_connection(this->base_->base , this->req_->url_host, this->req_->url_port, fd);
	}
	return this->resp_;
}

int http_downstream::read_chunk_hdr() {
	char readbuf[4096] = {};
	int len_line = co_socket_readline(sock_, readbuf, sizeof(readbuf));
	printf("read resp chunk hdr=%s\n", readbuf);
	if(len_line < 0) {
		return -1;
	}
	sscanf(readbuf, "%x", &this->current_chunk_len_);
	return 0;
}

int http_downstream::read_body(char* body, int len) {
	int len_read = 0;
	printf("http_downstream::readbody\n");
	char buf_readline[64] = {};
	 if(this->resp_->transfer_encoding == "chunked") {
	 	if(this->current_chunk_len_ == -1) {
	 		if(this->read_chunk_hdr() != 0) {
	 			return -1;
	 		}
	 	}

	 	if(this->current_chunk_len_ > 0) {
	 		int len_left = this->current_chunk_len_ - this->chunk_read_len_;
		 	int len_cpy = len_left < len ? len_left : len;
		 	int len_real_read = co_socket_read(this->sock_, body, len_cpy);
		 	if(len_real_read <= 0) {
		 		return -1;
		 	}
		 	this->chunk_read_len_ += len_real_read;
		 	if(this->chunk_read_len_ == this->current_chunk_len_) {
		 		// todo check ret value
		 		co_socket_readline(sock_, buf_readline, sizeof(buf_readline));
		 		this->current_chunk_len_ = -1;
		 		this->chunk_read_len_ = 0;
		 	}

		 	return len_real_read;
	 	}

	 	if(this->current_chunk_len_ == 0) {
	 		char buf[16] = {};
	 		int ret = co_socket_read(sock_, buf, sizeof(buf));
	 		if(ret != 2) {
	 			return -1;
	 		}
	 		return 0;
	 	}
	 	return -1;
	 	
	 } else if(!resp_->content_length.empty()){
	 	int64_t content_len = atoll(resp_->content_length.c_str());

	 	if(content_len == 0) {
	 		return 0;
	 	}

	 	if(this->body_read_ == content_len) {
	 		return 0;
	 	}

	 	int64_t len_left = content_len - this->body_read_;
	 	int len_cpy = len_left < len ? len_left : len;
	 	int len_real_read = co_socket_read(this->sock_, body, len_cpy);

	 	if(len_real_read <= 0) {
	 		return -1;
	 	}

	 	this->body_read_ += len_real_read;
	 	return len_real_read;
	 } else {
	 	return co_socket_read(this->sock_, body, len);
	 }
}

int http_downstream::write_body(char* body, int len) {
	if(this->req_->transfer_encoding == "chunked") {
		char buf[64] = {};
		snprintf(buf, sizeof(buf), "%x\r\n", len);
		co_socket_write(sock_, buf, strlen(buf));
		co_socket_write(sock_, body, len);
		return co_socket_write(sock_, (char*)"\r\n", 2);
	} else {
		return co_socket_write(sock_, body, len);
	}
}

int http_downstream::complete_body() {
	if(this->req_->transfer_encoding == "chunked") {
		const char* resp = "0\r\n\r\n";		
		return co_socket_write(sock_, (char*)resp, strlen(resp));
	}
	return 0;
}