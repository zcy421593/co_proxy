#ifndef HTTP_REQUEST_HEADER_H
#define HTTP_REQUEST_HEADER_H
#include <string>
#include <vector>
class http_request_header {
public:
	std::string method;
	std::string url;

	std::string url_host;
	std::string url_path;
	std::string url_query;
	std::string url_flagment;
	int url_port;
	
	std::string version_str;
	std::string content_length;
	std::string transfer_encoding;
	std::string host;

	std::vector<std::pair<std::string, std::string> > vec_headers;

	http_request_header() {
		this->url_port = 80;
	}

	std::string get_header_value(std::string field);
};
#endif
