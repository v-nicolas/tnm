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

#include <ctype.h>

#include "http.h"
#include "log.h"
#include "mem.h"
#include "str.h"

#define HTTP_JUMP_BLANK(y) for (;*y && isblank(*y); y++)

enum http_parse_str_option {
    HTTP_STR_OPT_BLANK = (1 << 0),
};

static int http_parse_path_and_param(struct http_header *http, char *lineptr);
static int http_copy_next_part(const char *src, char *dst,
			       int max_size, int option);
static int http_get_next_part_size(const char *src, int max_size, int option);

static const char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
			"Aug", "Sep", "Oct", "Nov", "Dec"};

void
http_header_init(struct http_header *http)
{
    memset(http, 0, sizeof(struct http_header));
    sbuf_init(&http->header);
}

void
http_header_free(struct http_header *http)
{
    if (http == NULL) {
	return;
    }
    http_header_free_data(http);
    xfree(http);
}

void
http_header_free_data(struct http_header *http)
{
    if (http == NULL) {
	return;
    }
    sbuf_free(&http->header);
    xfree(http->auth_value);
    xfree(http->param);
    xfree(http->payload);
}

void
http_make_header(struct http_header *http, const char *hostname, const char *ip)
{
    sbuf_vadd(&http->header, "%s %s %s\r\n"
	      "Host: %s\r\n"
	      "Accept: */*\r\n"
	      "User-agent: %s\r\n"
	      "%s: 0\r\n",
	      http->method, http->path, http->version,
	      (hostname != NULL && hostname[0] != 0) ? hostname : ip,
	      http->user_agent, HTTP_CONTENT_LEN_STR);

    if (http->auth_type[0] != 0 && http->auth_value != NULL) {
	sbuf_vadd(&http->header, "Authorization: %s %s\r\n",
		  http->auth_type, http->auth_value);
    }
    
    sbuf_add(&http->header, "Connection: Close\r\n\r\n");
}

/* Example: HTTP/1.1 200 OK */
int
http_get_status_code(const char *str)
{
    int i;
    int status_code;
    char status[HTTP_STATUS_CODE_SIZE];
    
    if (str == NULL) {
	return -1;
    }

    /* Jump the potiential blank char */
    for (;*str && isblank(*str); str++);

    /* Jump to the first digit char */
    if (isblank(*str) == 0 && isdigit(*str) == 0) {
	/* Jump the next word and blank chars */
	for (;*str && isblank(*str) == 0; str++);
	HTTP_JUMP_BLANK(str);
    }

    /* copy the digit code in string format */
    i = 0;
    while (i < HTTP_STATUS_CODE_SIZE-1 && isdigit(*str)) {
	status[i++] = *str++;
    }
    status[i] = 0;

    /* convert to integer and return this */
    status_code = -1;
    if (i > 0) {
	if (xstrtol(status, &status_code, 10) < 0) {
	    DEBUG("Fail to convert status code <%s>", status);
	    return -1;
	}
    }

    return status_code;
}

int
http_parse_first_line(struct http_header *http)
{
    int size;
    char *lineptr = NULL;
    /*
     * A request-line begins with a method token, followed by a single space
     * (SP), the request-target, another single space (SP), the protocol
     * version, and ends with CRLF.
     * request-line   = method SP request-target SP HTTP-version CRLF
     * source: https://www.rfc-editor.org/rfc/rfc7230#section-3.1.1
     */

    lineptr = http->header.buf;
    if (http_copy_next_part(lineptr, http->method,
			    HTTP_METHOD_SIZE,
			    HTTP_STR_OPT_BLANK) < 1) {
	DEBUG("HTTP bad method.:\n");
	return -1;
    }
    if (http_check_method(http->method) < 0) {
	DEBUG("HTTP method unknow.\n");
	return -1;
    }
    lineptr += strlen(http->method);
    if (*lineptr != ' ') {
	DEBUG("Bad space after method.\n");
	return -1;
    }
    lineptr++;

    size = http_parse_path_and_param(http, lineptr);
    if (size < 1) {
	return -1;
    }
    lineptr += size;
    if (*lineptr != ' ') {
	DEBUG("Bad space after path.\n");
	return -1;
    }
    lineptr++;

    if (http_copy_next_part(lineptr, http->version,
			    HTTP_VERSION_SIZE,
			    HTTP_STR_OPT_BLANK) < 1) {
	DEBUG("HTTP bad version.\n");
	return -1;
    }
    if (http_check_version(http->version) < 0) {
	DEBUG("HTTP unknown protocol version.\n");
	return -1;
    }
    lineptr += strlen(http->version);
    if (strncmp(lineptr, "\r\n", 2) != 0) {
	DEBUG("HTTP not terminted by CRLF.\n");
	return -1;
    }
    
    return 0;
}

static int
http_parse_path_and_param(struct http_header *http, char *lineptr)
{
    int size;
    char *param = NULL;
    
    size = http_copy_next_part(lineptr, http->path,
			       HTTP_PATH_SIZE,
			       HTTP_STR_OPT_BLANK);
    if (size < 1) {
	DEBUG("Invalid path size.\n");
	return -1;
    }

    /* Copy param and delete to path */
    param = strchr(http->path, '?');
    if (param == NULL) {
	/* no param */
	return size;
    }
    
    *param = 0; /* delete to path */
    param++;
    if (*param != 0) {
	http->param = xstrdup(param);
    }
    // todo parse all params in array
    // struct http_params {
    //     char name[];
    //     char value[];
    // }
    return size;
}

int
http_get_content_type(const char *str, char *content_type)
{
    char *buffer = NULL;

    memset(content_type, 0, HTTP_CONTENT_TYPE_SIZE);
    buffer = strstr(str, HTTP_CONTENT_TYPE_STR);
    if (buffer == NULL) {	
	return -1;
    }

    buffer += strlen(HTTP_CONTENT_TYPE_STR);
    HTTP_JUMP_BLANK(buffer);
    if (http_copy_next_part(buffer,
			    content_type,
			    HTTP_CONTENT_TYPE_SIZE, 0) < 0) {
	return -1;
    }

    return 0;
}

/*
 * HTTP authorization syntax:
 * Authorization: <type> <credentials>
 */
int
http_get_authorization(const char *str, char *auth_type, char **auth_value)
{
    int size;
    char *buffer = NULL;

    *auth_value = NULL;
    memset(auth_type, 0, HTTP_AUTHORIZATION_SIZE);
    
    buffer = strstr(str, HTTP_AUTHORIZATION_STR);
    if (buffer == NULL) {
	return -1;
    }
    
    buffer += strlen(HTTP_AUTHORIZATION_STR);
    http_copy_next_part(buffer, auth_type,
			HTTP_AUTHORIZATION_SIZE,
			HTTP_STR_OPT_BLANK);
    HTTP_JUMP_BLANK(buffer);
    buffer += strlen(auth_type);

    HTTP_JUMP_BLANK(buffer);
    size = http_get_next_part_size(buffer, -1, 0);
    if (size == 0) {
	return 0;
    }
    *auth_value = xmalloc(((size_t)(size+1)) * sizeof(char));
    strncpy(*auth_value, buffer, (size_t)size);
    (*auth_value)[size] = 0;    
    return 0;
}

char *
http_get_payload(const char *str)
{
    char *buffer = NULL;

    buffer = strstr(str, "\r\n\r\n");
    if (buffer == NULL || *(buffer + 4) == 0) {
	return NULL;
    }
    return xstrdup((buffer + 4));
}

/* return the len of copy */
static int
http_copy_next_part(const char *src, char *dst, int max_size, int option)
{
    int i;
    int j;
    
    HTTP_JUMP_BLANK(src);
    i = http_get_next_part_size(src, max_size, option);
    if (i < 1) {
	return -1;
    }

    /* Copy */
    for (j = 0; j < i; j++) {
	dst[j] = src[j];
    }

    return i;
}

/* If max_size = -1 is ignored */
static int
http_get_next_part_size(const char *src, int max_size, int option)
{
    int i;
    
    /* Get and check size */
    for (i = 0; src[i] && src[i] != '\r'; i++) {
	if ((option & HTTP_STR_OPT_BLANK) && isblank(src[i])) {
	    break;
	}
    }
    if (max_size != -1 && i >= max_size) {
	return -1;
    }
    return i;
}

void
http_delete_header_payload(char *str)
{
    char *buffer = NULL;
    
    buffer = strstr(str, "\r\n\r\n");
    if (buffer != NULL) {
	*buffer = 0;
    }
}

const char *
http_get_date(time_t timestamp, char *date)
{
    struct tm *tm = NULL;

    memset(date, 0, HTTP_DATE_SIZE);
    tm = gmtime(&timestamp);
    if (tm != NULL) {
	snprintf(date, (HTTP_DATE_SIZE-1),
		 "%s, %d %s %d %02d:%02d:%02d GMT",
		 days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon],
		 tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);
    }
    if (date[0] == 0) {
        strncpy(date, "[get_date_error]", HTTP_DATE_SIZE);
    }
    return date;
}
