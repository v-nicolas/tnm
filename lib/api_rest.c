/*
 *  Author: Vilmain Nicolas <nicolas.vilmain@gmail.com>
 *
 *  This file is part of lib api rest.
 *
 *  lib api rest is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  lib api rest is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with lib api rest. If not, see <http://www.gnu.org/licenses/>.
 */

#include "api_rest.h"

#include <ctype.h>
#include <stdlib.h>

#include "attr.h"
#include "mem.h"
#include "sock.h"
#include "log.h"
#include "dlist.h"
#include "file_utils.h"

static int api_rest_add_route(struct api_rest *api,
			      const char *http_method,
			      const char *path,
			      api_rest_handler_t handler,
			      void *handler_argument);
static int api_rest_route_exists(struct api_rest_route *route,
				 const char *path,
				 const char *method);
    
struct api_rest *
api_rest_new(void)
{
    struct api_rest *api = NULL;

    api = xcalloc(sizeof(struct api_rest));
    api->srv_ip_version = SOCK_OPT_IPv4_IPv6;
    api->srv_port = API_REST_DEFUALT_PORT;
    api->read_timeout = API_REST_DEFUALT_READ_TIMEOUT;
    api->route_protected = 1;
    
    return api;
}

void
api_rest_set_route_protected(struct api_rest *api, int enable)
{
    api->route_protected = enable;
}

void
api_rest_free(struct api_rest *api)
{
    if (api == NULL) {
	return;
    }
    xfree(api->bearer);
    xfree(api->srv_bind_addr);
    xclose(api->srv_fd);
    xfree(api);
}

int
api_rest_create_server(struct api_rest *api)
{
    api->srv_fd = sock_server_create(api->srv_bind_addr,
				 api->srv_port,
				 api->srv_ip_version);
    if (api->srv_fd < 0) {
	return -1;
    }
    return 0;
}

int
api_rest_add_route_get(struct api_rest *api, const char *path,
		       api_rest_handler_t handler, void *handler_arg)
{
    return api_rest_add_route(api, HTTP_GET, path, handler, handler_arg);
}

int
api_rest_add_route_post(struct api_rest *api, const char *path,
			api_rest_handler_t handler, void *handler_arg)
{
    return api_rest_add_route(api, HTTP_POST, path, handler, handler_arg);
}

int
api_rest_add_route_put(struct api_rest *api,const char *path,
		       api_rest_handler_t handler, void *handler_arg)
{
    return api_rest_add_route(api, HTTP_PUT, path, handler, handler_arg);
}

int
api_rest_add_route_delete(struct api_rest *api, const char *path,
			  api_rest_handler_t handler, void *handler_arg)
{
    return api_rest_add_route(api, HTTP_DELETE, path,  handler, handler_arg);
}

static int
api_rest_add_route(struct api_rest *api,
		   const char *http_method,
		   const char *path,
		   api_rest_handler_t handler,
		   void *handler_argument)
{
    size_t i;
    struct api_rest_route *new_route = NULL;
    char method[HTTP_METHOD_SIZE];
    
    if (path == NULL || path[0] == 0) {
	err("Fail to add new route, path is empty.\n");
	return -1;
    }
    if (handler == NULL) {
	err("Fail to add new route, handler is empty.\n");
	return -1;
    }

    memset(method, 0, HTTP_METHOD_SIZE);
    strncpy(method, http_method, (HTTP_METHOD_SIZE-1));
    for (i = 0; i < strlen(method); i++) {
	method[i] = (char) toupper(method[i]);
    }

    if (http_check_method(method) < 0) {
	err("Fail to add new route, HTTP method invalid.\n");
	return -1;
    }
    if (api_rest_route_exists(api->route, path, method) == 1) {
	err("Fail to add new route, %s %s already exists", method, path);
	return -1;
    }
	    
    new_route = xcalloc(sizeof(struct api_rest_route));
    new_route->handler = handler;
    new_route->handler_argument = handler_argument;
    strncpy(new_route->method, method, (HTTP_METHOD_SIZE-1));
    strncpy(new_route->path, path, (API_REST_ROUTE_SIZE-1));
    if (api->route_protected) {
	new_route->option |= API_ROUTE_OPT_PROTECTED;
    }
    SLIST_LINK_HEAD(api->route, new_route);
    return 0;
}

/* return: 0 success
 *         else the status code of error
 */
int
api_rest_parse_request(struct http_header *http)
{
    /* Get payload and set the first retline to 0
     * to not interfere with parsing of other http fields */
    http->payload = http_get_payload(http->header.buf);
    http_delete_header_payload(http->header.buf);

    if (http_parse_first_line(http) < 0) {
	return 501;
    }
    
    (void) http_get_content_type(http->header.buf, http->content_type);
    (void) http_get_authorization(http->header.buf,
				  http->auth_type,
				  &http->auth_value);

    DEBUG("New HTTP request received:\n"
	  "\tMethod        : %s\n"
	  "\tPath          : %s\n"
	  "\tVersion       : %s\n"
	  "\tContent Type  : %s\n"
	  "\tAuth type     : %s\n"
	  "\tAuth value    : %s\n"
	  "\tPayload:      :\n%s\n\n",
	  http->method, http->path,
	  http->version, http->content_type,
	  (http->auth_type[0]) ? http->auth_type : "-",
	  (http->auth_value != NULL && http->auth_value[0] != 0) ?
	  http->auth_value : "-",
	  (http->payload != NULL && http->payload[0] != 0) ?
	  http->payload : "-");
    // parse url param

    return 0;
}

int
api_rest_read(struct api_rest *api, int cli_fd, struct http_header *http)
{
    ATTR_AUTOFREE char *buffer;

    sbuf_reset(&http->header);
    buffer = sock_read_alloc_timeout(cli_fd, api->read_timeout);
    if (buffer == NULL) {
	return -1;
    }

    sbuf_add(&http->header, buffer);
    if (api_rest_parse_request(http) < 0) {
	return -1;
    }
    
    return 0;
}

static int
api_rest_route_exists(struct api_rest_route *route,
		      const char *path,
		      const char *method)
{
    struct api_rest_route *routeptr = NULL;
    
    LIST_FOREACH (route, routeptr) {
	if (strcmp(route->path, path) == 0 &&!
	    strcmp(route->method, method) == 0) {
	    return 1;
	}
    }
    return 0;
}
