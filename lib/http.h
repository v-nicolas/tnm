/*
 *  Author: Vilmain Nicolas <nicolas.vilmain@gmail.com>
 *
 *  This file is part of TNM.
 *
 *  tnm is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  tnm is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with tnm. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NM_HTTP_H
#define NM_HTTP_H

#include <time.h>
#include <string.h>

#include "sbuf.h"

#define HTTP_DATE_SIZE 64

#define HTTP_AUTH_BASIC  "Basic"
#define HTTP_AUTH_BEARER "Bearer"

#define HTTP_VERSION_SIZE 9
#define HTTP_VERSION_1   "HTTP/1.0"
#define HTTP_VERSION_1_1 "HTTP/1.1"
#define HTTP_VERSION_2   "HTTP/2.0"
#define HTTP_VERSION_3   "HTTP/3.0"

#define HTTP_METHOD_SIZE 8
#define HTTP_OPTIONS "OPTIONS"
#define HTTP_GET     "GET"
#define HTTP_HEAD    "HEAD"
#define HTTP_PUT     "PUT"
#define HTTP_POST    "POST"
#define HTTP_DELETE  "DELETE"
#define HTTP_PATCH   "PATCH"

#define HTTP_BEARER_STR "Bearer"

#define HTTP_USER_AGENT_DEFAULT "Default-http-lib-agent"

#define HTTP_CONTENT_TYPE_STR	"Content-Type:"
#define HTTP_CONTENT_LEN_STR	"Content-Length"
#define HTTP_AUTHORIZATION_STR	"Authorization:"

#define HTTP_RESPONSE_FIRSTLINE_SIZE 128
#define HTTP_STATUS_CODE_SIZE 5
#define HTTP_PATH_SIZE 2048
#define HTTP_USER_AGENT_SIZE 255
#define HTTP_CONTENT_TYPE_SIZE 64
#define HTTP_AUTHORIZATION_SIZE 255

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_NOT_FOUND 404
#define HTTP_STATUS_ACCESS_FORBIDDEN 403
#define HTTP_STATUS_INTERNAL_ERROR 501

struct http_header {
    int status_code;
    
    /* Basic, Bearer ... */
    char *auth_value;
    char *payload;
    char *param;
    
    struct sbuf header;
    char version[HTTP_VERSION_SIZE];
    char method[HTTP_METHOD_SIZE];
    char path[HTTP_PATH_SIZE];
    char user_agent[HTTP_USER_AGENT_SIZE];
    char auth_type[HTTP_AUTHORIZATION_SIZE];
    char content_type[HTTP_CONTENT_TYPE_SIZE];
};

static inline int http_check_method(const char *s) {
    return (s != NULL && *s != 0 &&
	    (!strcmp(s, HTTP_OPTIONS) ||
	     !strcmp(s, HTTP_GET) ||
	     !strcmp(s, HTTP_HEAD) ||
	     !strcmp(s, HTTP_PUT) ||
	     !strcmp(s, HTTP_POST) ||
	     !strcmp(s, HTTP_DELETE) ||
	     !strcmp(s, HTTP_PATCH))) ? 0 : -1;
}

static inline int http_check_version(const char *s) {
    return (s != NULL && *s != 0 &&
	    (!strcmp(s, HTTP_VERSION_1) ||
	     !strcmp(s, HTTP_VERSION_1_1) ||
	     !strcmp(s, HTTP_VERSION_2) ||
	     !strcmp(s, HTTP_VERSION_3))) ? 0 : -1;
}

void http_header_init(struct http_header *http);
void http_header_free(struct http_header *http);
void http_header_free_data(struct http_header *http);
void http_make_header(struct http_header *http, const char *host, const char *ip);
int http_get_status_code(const char *str);
int http_parse_first_line(struct http_header *http);
int http_get_content_type(const char *str, char *content_type);
char *http_get_payload(const char *str);
int http_get_authorization(const char *str, char *auth_type, char **value);
int http_get_route(const char *str);
void http_delete_header_payload(char *str);
const char * http_get_date(time_t timestamp, char *date);

#endif /* !NM_HTTP_H */
