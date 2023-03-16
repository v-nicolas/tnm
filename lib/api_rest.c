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

#include <time.h>
#include <ctype.h>
#include <stdlib.h>

#include "attr.h"
#include "mem.h"
#include "sock.h"
#include "log.h"
#include "dlist.h"
#include "file_utils.h"

#define API_REST_ERR_NOT_FOUND \
    "{\"status\": \"error\", \"info\":\"page not found\"}"
#define API_REST_ERR_ACCESS_FORBIDDEN \
    "{\"status\": \"error\", \"info\":\"access forbidden\"}"
#define API_REST_ERR_INTERNAL_ERROR \
    "{\"status\": \"error\", \"info\":\"internal error\"}"

static void api_rest_free_routes(struct api_rest_route *route);
static int api_rest_add_route(struct api_rest *api,
			      const char *http_method,
			      const char *path,
			      api_rest_handler_t handler,
			      void *handler_argument);
static int api_rest_router(struct api_rest *api,
			   struct api_rest_ctx *ctx, int cli_fd);
static int api_rest_route_check_auth(struct api_rest *api,
				     struct http_header *in);
static struct api_rest_route * api_rest_get_route(struct api_rest_route *route,
						  const char *path,
						  const char *method);
static int api_rest_route_not_found(struct api_rest_ctx *ctx, void *arg);
static int api_rest_route_access_forbidden(struct api_rest_ctx *ctx, void *arg);
static int api_rest_route_internal_error(struct api_rest_ctx *ctx, void *arg);
    
struct api_rest *
api_rest_new(void)
{
    struct api_rest *api = NULL;

    api = xcalloc(sizeof(struct api_rest));
    api->srv_ip_version = SOCK_OPT_IPv4_IPv6;
    api->srv_port = API_REST_DEFUALT_PORT;
    api->read_timeout = API_REST_DEFUALT_READ_TIMEOUT;
    api->route_protected = 1;
    api->route_not_found = api_rest_route_not_found;
    api->route_access_forbidden = api_rest_route_access_forbidden;
    api->route_internal_error = api_rest_route_internal_error;
    
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
    api_rest_free_routes(api->route);
    xfree(api);
}

static void
api_rest_free_routes(struct api_rest_route *route)
{
    struct api_rest_route *nextptr = NULL;

    while (route) {
	nextptr = route->next;
	xfree(route);
	route = nextptr;
    }
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
api_rest_set_error_route(struct api_rest *api, int errcode,
			 api_rest_handler_t handler,
			 void *handler_arg)
{
    if (handler == NULL) {
	warn("Handler is null.\n");
	return -1;
    }

    switch (errcode) {
    case 404:
	api->arg_404 = handler_arg;
	api->route_not_found = handler;
	break;
    case 403:
	api->arg_403 = handler_arg;
	api->route_access_forbidden = handler;
	break;
    case 501:
	api->arg_501 = handler_arg;
	api->route_internal_error = handler;
	break;
    default:
	warn("Invalid errcode <%d>.\n", errcode);
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
    if (api_rest_get_route(api->route, path, method) != NULL) {
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

int
api_rest_client_handler(struct api_rest *api, int cli_fd)
{
    int ret;
    struct api_rest_ctx ctx;

    sbuf_init(&ctx.out);
    http_header_init(&ctx.in);

    ret = api_rest_router(api, &ctx, cli_fd);
    if (sbuf_len(&ctx.out) > 0) {
	(void) sock_write_fd(cli_fd, ctx.out.buf, ctx.out.offset);
    }
    
    sbuf_free(&ctx.out);
    http_header_free_data(&ctx.in);
    return ret;
}

static int
api_rest_router(struct api_rest *api, struct api_rest_ctx *ctx, int cli_fd)
{
    struct api_rest_route *route = NULL;
    
    if (api_rest_read(api, cli_fd, &ctx->in) < 0) {
	api->route_internal_error(ctx, NULL);
	return -1;
    }

    route = api_rest_get_route(api->route, ctx->in.path, ctx->in.method);
    if (route == NULL) {
	err("API REST: %s %s not found.\n", ctx->in.method, ctx->in.path);
	api->route_not_found(ctx, NULL);
	return -1;
    }

    if ((route->option & API_ROUTE_OPT_PROTECTED)) {
	if (api_rest_route_check_auth(api, &ctx->in) < 0) {
	    api->route_access_forbidden(ctx, NULL);
	    return -1; 
	}
    }
    
    return route->handler(ctx, route->handler_argument);
}

static int
api_rest_route_check_auth(struct api_rest *api, struct http_header *in)
{
    if (api->bearer == NULL || api->bearer[0] == 0) {
	err("API REST: %s %s is protected but api bearer is empty.\n",
	    in->method, in->path);
	return -1;
    }
	
    if (strcmp(in->auth_type, HTTP_BEARER_STR) != 0) {
	err("API REST: %s %s auth type <%s> invalid.\n",
	    in->method, in->path, in->auth_value);
	return -1;	
    }

    if (in->auth_value == NULL ||
	strcmp(in->auth_value, api->bearer) != 0) {
	err("API REST: %s %s Bad bearer value <%s>.\n",
	    in->method, in->path,
	    (in->auth_value) ? "-" : in->auth_value);
	return -1;
    }
    
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
	  "\tParam         : %s\n"
	  "\tVersion       : %s\n"
	  "\tContent Type  : %s\n"
	  "\tAuth type     : %s\n"
	  "\tAuth value    : %s\n"
	  "\tPayload:      :\n%s\n\n",
	  http->method, http->path, http->param,
	  http->version, http->content_type,
	  (http->auth_type[0]) ? http->auth_type : "-",
	  (http->auth_value != NULL && http->auth_value[0] != 0) ?
	  http->auth_value : "-",
	  (http->payload != NULL && http->payload[0] != 0) ?
	  http->payload : "-");

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

static struct api_rest_route *
api_rest_get_route(struct api_rest_route *route,
		   const char *path, const char *method)
{
    struct api_rest_route *routeptr = NULL;

    printf("Search route: <%s> -- <%s>\n", method, path);
    LIST_FOREACH (route, routeptr) {
	printf("<%s> -- <%s>\n", routeptr->method, routeptr->path);
	if (strcmp(routeptr->path, path) == 0 &&
	    strcmp(routeptr->method, method) == 0) {
	    
	    return routeptr;
	}
    }
    return NULL;
}

static int
api_rest_route_not_found(struct api_rest_ctx *ctx, void *arg ATTR_UNUSED)
{
    char date[HTTP_DATE_SIZE];
    
    sbuf_vadd(&ctx->out, "%s 404 Not found\r\n"
	      "Date: %s\r\n"
	      "Content-Type: application/json; charset=UTF-8\r\n"
	      "Content-Length: %lu\r\n"
	      "Connection: Closed\r\n"
	      "\r\n"
	      "%s",
	      HTTP_VERSION_1_1, http_get_date(time(NULL), date),
	      strlen(API_REST_ERR_NOT_FOUND),
	      API_REST_ERR_NOT_FOUND);
    return 0;
}

static int
api_rest_route_access_forbidden(struct api_rest_ctx *ctx, void *arg ATTR_UNUSED)
{
    char date[HTTP_DATE_SIZE];
    
    sbuf_vadd(&ctx->out, "%s 403 Access forbidden\r\n"
	      "Date: %s\r\n"
	      "Content-Type: application/json; charset=UTF-8\r\n"
	      "Content-Length: %lu\r\n"
	      "Connection: Closed\r\n"
	      "\r\n"
	      "%s",
	      HTTP_VERSION_1_1, http_get_date(time(NULL), date),
	      strlen(API_REST_ERR_ACCESS_FORBIDDEN),
	      API_REST_ERR_ACCESS_FORBIDDEN);
    return 0;
}

static int
api_rest_route_internal_error(struct api_rest_ctx *ctx, void *arg ATTR_UNUSED)
{
    char date[HTTP_DATE_SIZE];
    
    sbuf_vadd(&ctx->out, "%s 501 Internal error\r\n"
	      "Date: %s\r\n"
	      "Content-Type: application/json; charset=UTF-8\r\n"
	      "Content-Length: %lu\r\n"
	      "Connection: Closed\r\n"
	      "\r\n"
	      "%s",
	      HTTP_VERSION_1_1, http_get_date(time(NULL), date),
	      strlen(API_REST_ERR_INTERNAL_ERROR),
	      API_REST_ERR_INTERNAL_ERROR);
    return 0;
}
