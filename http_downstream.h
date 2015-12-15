#include "http_request_header.h"
#include "http_response_header.h"
#include "co_socket.h"
class http_downstream {
public:
	http_downstream(co_base* base, http_request_header* req);
	~http_downstream();
	int connect();
	int write_request_header();
	http_response_header* read_response_header();
	bool is_response_complete();
	int write_body(char* body, int len);
	int complete_body();
	int read_body(char* body, int len);
private:
	int read_chunk_hdr();
	co_base* base_;
	co_socket* sock_;
	http_request_header* req_;
	http_response_header* resp_;

	int current_chunk_len_;
	int chunk_read_len_;
	int64_t body_read_;
};