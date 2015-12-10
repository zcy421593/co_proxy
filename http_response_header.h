#ifndef HTTP_REAPONSE_HEADER_H
#define HTTP_REAPONSE_HEADER_H
#include <string>
#include <vector>
#include <stdint.h>
class http_response_header {
public:
	std::string version_str;
	std::string status_code;
	std::string status_str;
	std::string content_length;
	std::string transfer_encoding;
	std::vector<std::pair<std::string, std::string> > vec_headers;

	bool has_content_length();
	bool is_chunked();
	int64_t get_content_length();
	int get_status_code();
};
#endif
