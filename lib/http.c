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

void
http_header_free(struct http_header *http)
{
    if (http != NULL) {
	sbuf_free(&http->header);
	xfree(http->auth_type);
	xfree(http->auth_value);
	xfree(http);
    }
}

void
http_make_header(struct http_header *http, const char *hostname, const char *ip)
{
    sbuf_vadd(&http->header, "%s %s %s\r\n"
	      "Host: %s\r\n"
	      "Accept: */*\r\n"
	      "User-agent: %s\r\n",
	      http->method, http->path, http->version,
	      (hostname != NULL && hostname[0] != 0) ? hostname : ip,
	      http->user_agent);

    if (http->auth_type != NULL && http->auth_value != NULL) {
	sbuf_vadd(&http->header, "Authorization: %s %s\r\n",
		  http->auth_type, http->auth_value);
    }
    
    sbuf_add(&http->header, "Connection: Close\r\n\r\n");
}

/* Example: HTTP/1.1  OK 200 */
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
	for (;*str && isblank(*str); str++);
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
