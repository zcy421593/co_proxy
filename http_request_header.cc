#include "http_request_header.h"
#include "string.h"
std::string http_request_header::get_header_value(std::string field) {
	for(int i = 0; i < this->vec_headers.size(); i++) {
		if(strcasecmp(vec_headers[i].first.c_str(), field.c_str()) == 0) {
			return vec_headers[i].second;
		} 
	}
	return "";
}