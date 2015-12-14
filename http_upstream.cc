#include "http_upstream.h"
#include "http_parser.h"
#include "co_thread.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <string>
using namespace std;

static int read_request_line(co_socket* sock, http_request_header* header) {
	http_parser_url parser_url;
	char readbuf[4096 * 512] = {};
	char* buf_tmp;
	int len = co_socket_readline(sock, readbuf, sizeof(readbuf));
	if(len < 0) {
		return -1;
	}

	char* pos = strchr(readbuf, ' ');
	char* pos2 = strrchr(readbuf, ' ');

	if(pos2 == pos) {
		return -1;
	}

	if(strchr(pos + 1, ' ') != pos2) {
		return -1;
	}

	
	buf_tmp = strndup(readbuf, pos - readbuf);
	header->method = buf_tmp;
	free(buf_tmp);

	buf_tmp = strndup(pos + 1, pos2 - pos -1);
	header->url = buf_tmp;
	free(buf_tmp);

	buf_tmp = strndup(pos2 + 1, len - (pos2 - readbuf + 1));
	header->version_str = buf_tmp;
	free(buf_tmp);

	http_parser_parse_url(header->url.c_str(), header->url.size(), header->method == "CONNECT", &parser_url);

	if(parser_url.field_set & (1 << UF_HOST)) {
		
		buf_tmp = strndup(header->url.c_str() + parser_url.field_data[UF_HOST].off,
			    parser_url.field_data[UF_HOST].len);
		header->url_host = buf_tmp;
		free(buf_tmp);
	}

	if(parser_url.field_set & (1 << UF_QUERY)) {
		buf_tmp = strndup(header->url.c_str() + parser_url.field_data[UF_QUERY].off,
			    parser_url.field_data[UF_QUERY].len);
		header->url_query = buf_tmp;
		free(buf_tmp);
	}

	if(parser_url.field_set & (1 << UF_PORT)) {
		char port[10] = {};
		strncpy(port, 
				header->url.c_str() + parser_url.field_data[UF_PORT].off,
				parser_url.field_data[UF_PORT].len);
		header->url_port = atoi(port);	
	}

	if(parser_url.field_set & (1 << UF_PATH)) {
		bzero(buf_tmp, sizeof(buf_tmp));
		buf_tmp = strndup(header->url.c_str() + parser_url.field_data[UF_PATH].off,
			    parser_url.field_data[UF_PATH].len);
		header->url_path = buf_tmp;
	}

	if(parser_url.field_set & (1 << UF_FRAGMENT)) {
		buf_tmp = strndup(header->url.c_str() + parser_url.field_data[UF_FRAGMENT].off,
			    parser_url.field_data[UF_FRAGMENT].len);
		header->url_flagment = buf_tmp;
		free(buf_tmp);
	}
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


static int read_request_header(co_socket* sock, http_request_header* header) {
	if(read_request_line(sock, header) != 0) {
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
		} else if(strcasecmp(p.first.c_str(), "transfer_encoding") == 0) {
			header->transfer_encoding = p.second;
		}
	}
	return 0;
}

void* relaycb(co_thread* thread, void* args) {
	pair<co_socket*, co_socket*>* p = (pair<co_socket*, co_socket*>*)args;
	char buf[4096] = {};
	for(;;) {
		int ret = co_socket_read(p->first, buf, sizeof(buf));
		if(ret <=0) {
			break;
		}

		ret = co_socket_write(p->second, buf, ret);

		if(ret <= 0) {
			break;
		}
	}
	return NULL;
}

http_upstream::http_upstream(co_base* base, co_socket* sock) {
	this->sock_base_ = base;
	this->sock_client_ = sock;
	this->current_chunk_len_ = -1;
	this->chunk_read_len_ = 0;
	this->body_read_ = 0;
	this->req_ = NULL;
}

http_request_header* http_upstream::read_header() {
	if(this->req_) {
		delete this->req_;
	}
	this->req_ = new http_request_header();
	if(read_request_header(this->sock_client_, this->req_) != 0) {
		goto err;
	}
	return this->req_;
err:
	if(this->req_) {
		delete this->req_;
		this->req_ = NULL;
	}
	return NULL;

}

int http_upstream::write_response_header(http_response_header* resp_hdr) {
	this->resp_ = resp_hdr;
	string resp_str;
	append_format_string(resp_str, "%s %s %s\r\n", resp_hdr->version_str.c_str(), resp_hdr->status_code.c_str(), resp_hdr->status_str.c_str());
		for(int i = 0; i < resp_hdr->vec_headers.size(); i++) {
			pair<string, string>& p = resp_hdr->vec_headers[i];
			append_format_string(resp_str, "%s: %s\r\n", p.first.c_str(), p.second.c_str());
		}
		resp_str.append("\r\n");
	printf("resp hde=%s", resp_str.c_str());
	if(co_socket_write(sock_client_, (char*)resp_str.c_str(), resp_str.size()) > 0) {
		return 0;
	}
	return -1;
}

int http_upstream::read_chunk_hdr() {
	char readbuf[4096] = {};
	int len_line = co_socket_readline(sock_client_, readbuf, sizeof(readbuf));
	if(len_line < 0) {
		return -1;
	}
	sscanf(readbuf, "%x", &this->current_chunk_len_);
	return 0;
}

int http_upstream::read_body(char* body, int len) {
	int len_read = 0;
	char buf_readline[64] = {};
	 if(this->req_->transfer_encoding == "chunked") {
	 	if(this->current_chunk_len_ == -1) {
	 		if(this->read_chunk_hdr() != 0) {
	 			return -1;
	 		}
	 	}

	 	if(this->current_chunk_len_ > 0) {
	 		int len_left = this->current_chunk_len_ - this->chunk_read_len_;
		 	int len_cpy = len_left < len ? len_left : len;
		 	int len_real_read = co_socket_read(this->sock_client_, body, len_cpy);
		 	if(len_real_read <= 0) {
		 		return -1;
		 	}
		 	this->chunk_read_len_ += len_real_read;
		 	if(this->chunk_read_len_ == this->current_chunk_len_) {
		 		co_socket_readline(sock_client_, buf_readline, sizeof(buf_readline));
		 		this->current_chunk_len_ = -1;
		 		this->chunk_read_len_ = 0;
		 	}
		 	return len_real_read;
	 	}

	 	if(this->current_chunk_len_ == 0) {
	 		char buf[16] = {};
	 		int ret = co_socket_read(sock_client_, buf, sizeof(buf));
	 		if(ret != 0) {
	 			return -1;
	 		}
	 		return 0;
	 	}
	 	return -1;
	 	
	 } else if(!req_->content_length.empty()){
	 	int64_t content_len = atoll(req_->content_length.c_str());

	 	if(content_len == 0) {
	 		return 0;
	 	}

	 	if(this->body_read_ == content_len) {
	 		return 0;
	 	}

	 	int64_t len_left = content_len - this->body_read_;
	 	int len_cpy = len_left < len ? len_left : len;
	 	int len_real_read = co_socket_read(this->sock_client_, body, len_cpy);

	 	if(len_real_read <= 0) {
	 		return -1;
	 	}

	 	this->body_read_ += len_real_read;
	 	return len_real_read;
	 } else {
	 	return co_socket_read(this->sock_client_, body, len);
	 }
}

int http_upstream::write_body(char* body, int len) {
	int ret = 0;
	if(this->resp_->transfer_encoding == "chunked") {
		char buf[64] = {};
		snprintf(buf, sizeof(buf), "%x\r\n", len);
		ret = co_socket_write(sock_client_, buf, strlen(buf));
		if(ret < 0) {
			return -1;
		}
		ret = co_socket_write(sock_client_, body, len);
		if(ret < 0) {
			return -1;
		}
		ret = co_socket_write(sock_client_, (char*)"\r\n", 2);
		if(ret < 0) {
			return -1;
		}
		return 0;
	} else {
		return co_socket_write(sock_client_, body, len);
	}
}

int http_upstream::complete_body() {
	if(this->resp_->transfer_encoding == "chunked") {
		printf("complete body called\n");
		const char* resp = "0\r\n\r\n";		
		return co_socket_write(sock_client_, (char*)resp, strlen(resp));
	}
	return 0;
}