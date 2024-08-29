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
#include "str.h"
#include "mem.h"
#include "sock.h"
#include "log.h"
#include "list.h"
#include "json_utils.h"
#include "file_utils.h"

#define API_REST_ROUTE(ctx, route) route.func(ctx, route.arg)
#define API_REST_SET_ROUTE(route, handler, arg)	\
    do {						\
	route.func = handler;				\
	route.arg = arg;				\
    } while (0)

#define API_REST_ERR(str) "{\"status\": \"error\", \"info\":"#str"}" 
#define API_REST_ERR_BAD_REQUEST API_REST_ERR("bad request")
#define API_REST_ERR_UNAUTHORIZED API_REST_ERR("unauthorized")
#define API_REST_ERR_ACCESS_FORBIDDEN API_REST_ERR("access forbidden")
#define API_REST_ERR_NOT_FOUND API_REST_ERR("page not found")
#define API_REST_ERR_REQUEST_TIMEOUT API_REST_ERR("request timeout")
#define API_REST_ERR_INTERNAL_ERROR API_REST_ERR("internal error")

static void api_rest_free_routes(struct api_rest_route *route);
static int api_rest_add_route(struct api_rest *api,
			      const char *http_method,
			      const char *path,
			      api_rest_handler_t handler,
			      void *handler_argument);
static void api_rest_req_ctx_free(struct api_rest_req_ctx *ctx);
static int api_rest_accept_client(int srv_fd, struct api_rest_req_ctx *ctx);
static void api_rest_build_response(struct api_rest *api,
				    struct api_rest_req_ctx *ctx);
static int api_rest_router(struct api_rest *api,
			   struct api_rest_req_ctx *ctx, int cli_fd);
static int api_rest_route_check_auth(struct api_rest *api,
				     struct http_header *in);
static struct api_rest_route * api_rest_get_route(struct api_rest_route *route,
						  const char *path,
						  const char *method);
static int api_rest_not_found(struct api_rest_req_ctx *ctx, void *arg);
static int api_rest_unauthorized(struct api_rest_req_ctx *ctx, void *arg);
static int api_rest_access_forbidden(struct api_rest_req_ctx *ctx, void *arg);
static int api_rest_bad_request(struct api_rest_req_ctx *ctx, void *arg);
static int api_rest_request_timeout(struct api_rest_req_ctx *ctx,
					  void *arg);
static int api_rest_internal_error(struct api_rest_req_ctx *ctx, void *arg);
static void api_rest_inc_err(struct api_rest *api, unsigned long long *err);
    
struct api_rest *
api_rest_new(void)
{
    struct api_rest *api = NULL;
    struct api_rest_err_routes *err = NULL;

    api = xcalloc(sizeof(struct api_rest));
    err = &api->err;
    api->srv_ip_version = SOCK_OPT_IPv4_IPv6;
    api->srv_port = API_REST_DEFUALT_PORT;
    api->read_timeout = API_REST_DEFUALT_READ_TIMEOUT;
    /* route is protected by default */
    api->route_protected = 1;
    /* set handler's error default route */
    err->bad_request.func = api_rest_bad_request;
    err->access_forbidden.func = api_rest_access_forbidden;
    err->not_found.func = api_rest_not_found;
    err->request_timeout.func = api_rest_request_timeout;
    err->internal_error.func = api_rest_internal_error;
    err->unauthorized.func = api_rest_unauthorized;
    return api;
}

void
api_rest_get_stats(struct api_rest *api, struct sbuf *str)
{
    sbuf_vadd(str, JSON_SET_INT("enable",
				(api->option & API_OPT_STATS) ? 1 : 0));
    sbuf_vadd(str, JSON_SET_ULLONG("nreq", api->stats.nreq));
    sbuf_vadd(str, JSON_SET_ULLONG("err", api->stats.err));
    sbuf_vadd(str, JSON_SET_ULLONG("bad_request", api->stats.bad_request));
    sbuf_vadd(str, JSON_SET_ULLONG("unauthorized", api->stats.unauthorized));
    sbuf_vadd(str, JSON_SET_ULLONG("access_forbidden",
				   api->stats.access_forbidden));
    sbuf_vadd(str, JSON_SET_ULLONG("not_found", api->stats.not_found));
    sbuf_vadd(str, JSON_SET_ULLONG("req_timeouted", api->stats.req_timeout));
    sbuf_vadd(str, JSON_SET_ULLONG("internal_error", api->stats.internal_err));
}

void
api_rest_stats_enable(struct api_rest *api)
{
    if (api == NULL) {
	warn("API is not initialized\n");
	return;
    }
    api->option |= API_OPT_STATS;
}

/* Disable and clean stats */
void
api_rest_stats_disable(struct api_rest *api)
{
    if (api == NULL) {
	warn("API is not initialized\n");
	return;
    }
    api->option &= ~(API_OPT_STATS);
    memset(&api->stats, 0, sizeof(struct api_rest_stats));
}


void
api_rest_set_route_protected(struct api_rest *api, int enable)
{
    if (api == NULL) {
	warn("API is not initialized\n");
	return;
    }
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
    api_rest_free_routes(api->routes);
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
			 api_rest_handler_t handler, void *arg)
{
    struct api_rest_err_routes *route = NULL;
    
    if (handler == NULL) {
	warn("Handler is null.\n");
	return -1;
    }

    route = &api->err;
    switch (errcode) {
    case HTTP_STATUS_BAD_REQUEST:
	API_REST_SET_ROUTE(route->bad_request, handler, arg);
	break;
    case HTTP_STATUS_UNAUTHORIZED:
	API_REST_SET_ROUTE(route->unauthorized, handler, arg);
	break;
    case HTTP_STATUS_ACCESS_FORBIDDEN:
	API_REST_SET_ROUTE(route->access_forbidden, handler, arg);
	break;
    case HTTP_STATUS_NOT_FOUND:
	API_REST_SET_ROUTE(route->not_found, handler, arg);
	break;
    case HTTP_STATUS_REQUEST_TIMEOUT:
	API_REST_SET_ROUTE(route->request_timeout, handler, arg);
	break;
    case HTTP_STATUS_INTERNAL_ERROR:
	API_REST_SET_ROUTE(route->internal_error, handler, arg);
	break;
    default:
	warn("Invalid errcode <%d>.\n", errcode);
	return -1;
    }
    return 0;
}

#define API_REST_ADD_ROUTE(method)					\
int									\
api_rest_add_route_##method(struct api_rest *api,			\
			    const char *path,				\
			    api_rest_handler_t handler,			\
			    void *handler_arg)				\
{									\
    return api_rest_add_route(api, #method, path, handler, handler_arg);\
}
/* method is converted to upper case in api_rest_add_route */
API_REST_ADD_ROUTE(get)
API_REST_ADD_ROUTE(post)
API_REST_ADD_ROUTE(put)
API_REST_ADD_ROUTE(delete)

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
    if (api_rest_get_route(api->routes, path, method) != NULL) {
	err("Fail to add new route, %s %s already exists", method, path);
	return -1;
    }
	    
    new_route = xcalloc(sizeof(struct api_rest_route));
    new_route->handler.func = handler;
    new_route->handler.arg = handler_argument;
    strncpy(new_route->method, method, (HTTP_METHOD_SIZE-1));
    /* Only for warning, this variable is cleaned by xcalloc on structure */
    new_route->method[HTTP_METHOD_SIZE-1] = 0;
    strncpy(new_route->path, path, (API_REST_ROUTE_SIZE-1));
    if (api->route_protected) {
	new_route->option |= API_ROUTE_OPT_PROTECTED;
    }
    SLIST_LINK_HEAD(api->routes, new_route);
    return 0;
}

int
api_rest_client_handler(struct api_rest *api)
{
    int cli_fd;
    struct api_rest_req_ctx ctx;

    cli_fd = api_rest_accept_client(api->srv_fd, &ctx);
    if (cli_fd < 0) {
	return -1;
    }
    
    http_header_init(&ctx.in);
    http_header_init(&ctx.out);

    (void) api_rest_router(api, &ctx, cli_fd);
    api_rest_build_response(api, &ctx);
    if (sbuf_len(&ctx.out.header) > 0) {
	(void) sock_write_fd(cli_fd, ctx.out.header.buf, ctx.out.header.offset);
    }
    
    api_rest_req_ctx_free(&ctx);
    (void) xclose(cli_fd);
    return 0;
}

static void
api_rest_req_ctx_free(struct api_rest_req_ctx *ctx)
{
    http_header_free_data(&ctx->in);
    http_header_free_data(&ctx->out);
}

static int
api_rest_accept_client(int srv_fd, struct api_rest_req_ctx *ctx)
{
    int cli_fd;
    socklen_t len;
    struct sockaddr_storage sock_cli_info;

    len = sizeof(struct sockaddr_storage);
    cli_fd = accept(srv_fd, (struct sockaddr *)&sock_cli_info, &len);
    if (cli_fd < 0) {
	err("APIREST accept: %s\n", STRERRNO);
	return -1;
    }
    if (sock_addr_to_str(sock_cli_info.ss_family,
			 ctx->client_ip,
			 &sock_cli_info) < 0) {
	strncpy(ctx->client_ip, "<ip_convert_error>", (INET6_ADDRSTRLEN-1));
    }
    
    info("APIREST new client <%s> connected.\n", ctx->client_ip);
    return cli_fd;
}

static void
api_rest_build_response(struct api_rest *api, struct api_rest_req_ctx *ctx)
{
    const char *firstlinestr = NULL;
    char date[HTTP_DATE_SIZE];

    switch (ctx->out.status_code) {
    case HTTP_STATUS_OK:
	firstlinestr = "OK";
	break;
    case HTTP_STATUS_BAD_REQUEST:
	firstlinestr = "Bad request";
	api_rest_inc_err(api, &api->stats.bad_request);
	break;
    case HTTP_STATUS_UNAUTHORIZED:
	firstlinestr = "Unauthorized";
	api_rest_inc_err(api, &api->stats.unauthorized);
	break;
    case HTTP_STATUS_ACCESS_FORBIDDEN:
	firstlinestr = "Access forbidden";
	api_rest_inc_err(api, &api->stats.access_forbidden);
	break;
    case HTTP_STATUS_NOT_FOUND:
	firstlinestr = "Not found";
	api_rest_inc_err(api, &api->stats.not_found);
	break;
    case HTTP_STATUS_REQUEST_TIMEOUT:
	firstlinestr = "Request timouted";
	api_rest_inc_err(api, &api->stats.req_timeout);
	break;
    case HTTP_STATUS_INTERNAL_ERROR:
	firstlinestr = "Internal error";
	api_rest_inc_err(api, &api->stats.internal_err);
	break;
    default:
	firstlinestr = "";
	break;
    }
    
    sbuf_vadd(&ctx->out.header, "%s %d %s\r\n"
	      "Date: %s\r\n"
	      "Content-Type: application/json; charset=UTF-8\r\n"
	      "Content-Length: %lu\r\n"
	      "Connection: Closed\r\n"
	      "\r\n"
	      "%s",
	      HTTP_VERSION_1_1, ctx->out.status_code,
	      firstlinestr, http_get_date(time(NULL), date),
	      strlen(ctx->out.payload), ctx->out.payload);
}

static int
api_rest_router(struct api_rest *api, struct api_rest_req_ctx *ctx, int cli_fd)
{
    int ret;
    struct api_rest_route *route = NULL;

    if ((api->option & API_OPT_STATS)) {
	api->stats.nreq++;
    }
    
    /* api_rest_read return 0 if success else return
     * the http statue code of error. */
    ret = api_rest_read(api, cli_fd, ctx);
    if (ret != 0) {
	if (ret == HTTP_STATUS_BAD_REQUEST) {
	    (void) API_REST_ROUTE(ctx, api->err.bad_request);  
	} else {
	    (void) API_REST_ROUTE(ctx, api->err.request_timeout);
	}
	return -1;
    }

    route = api_rest_get_route(api->routes, ctx->in.path, ctx->in.method);
    if (route == NULL) {
	info("API REST: client:%s method:%s path:%s not found.\n",
	     ctx->client_ip, ctx->in.method, ctx->in.path);
	(void) API_REST_ROUTE(ctx, api->err.not_found);
	return -1;
    }

    if ((route->option & API_ROUTE_OPT_PROTECTED)) {
	if (api_rest_route_check_auth(api, &ctx->in) < 0) {
	    info("API REST: client:%s method:%s path:%s unauthorized.\n",
		 ctx->client_ip, ctx->in.method, ctx->in.path);
	    (void) API_REST_ROUTE(ctx, api->err.unauthorized);
	    return -1; 
	}
    }
    
    return API_REST_ROUTE(ctx, route->handler);
}

static int
api_rest_route_check_auth(struct api_rest *api, struct http_header *in)
{
    if (api->bearer == NULL || api->bearer[0] == 0) {
	err("API REST: <%s %s> is protected but api bearer is empty.\n",
	    in->method, in->path);
	return -1;
    }
    if (STRNEQ(in->auth_type, HTTP_BEARER_STR)) {
	err("API REST: <%s %s> auth type <%s> invalid.\n",
	    in->method, in->path, in->auth_type);
	return -1;	
    }
    if (in->auth_value == NULL || STRNEQ(in->auth_value, api->bearer)) {
	err("API REST: <%s %s> Bad bearer value <%s>.\n",
	    in->method, in->path,
	    (in->auth_value) ? "-" : in->auth_value);
	return -1;
    }
    
    return 0;
}

/* return 0 if success else return the http error status code */
int
api_rest_read(struct api_rest *api, int cli_fd,
	      struct api_rest_req_ctx *ctx)
{
    ATTR_AUTOFREE char *buffer;

    buffer = sock_read_alloc_timeout(cli_fd, api->read_timeout);
    if (buffer == NULL) {
	info("APIREST client:%s fail socket read.\n", ctx->client_ip);
	return HTTP_STATUS_INTERNAL_ERROR;
    }

    sbuf_add(&ctx->in.header, buffer);
    if (api_rest_parse_request(&ctx->in) < 0) {
	info("APIREST client:%s HTTP request invalid.\n", ctx->client_ip);
	return HTTP_STATUS_BAD_REQUEST;
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
	return HTTP_STATUS_BAD_REQUEST;
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

static struct api_rest_route *
api_rest_get_route(struct api_rest_route *route,
		   const char *path, const char *method)
{
    struct api_rest_route *routeptr = NULL;

    DEBUG("Search route: <%s> <%s>\n", method, path);
    LIST_FOREACH (route, routeptr) {
	if (STREQ(routeptr->path, path) &&
	    STREQ(routeptr->method, method)) {
	    return routeptr;
	}
    }
    return NULL;
}

/* ret (return) */
void
api_rest_ret(struct api_rest_req_ctx *ctx, int status_code, const char *payload)
{
    ctx->out.status_code = status_code;
    xfree(ctx->out.payload);
    if (payload != NULL && *payload != 0) {
	ctx->out.payload = xstrdup(payload);
    } else {
	/* put an empty payload to avoid checking if
	 * payload equal NULL when build the response */
	ctx->out.payload = xstrdup("");
    }
}

static int
api_rest_not_found(struct api_rest_req_ctx *ctx, void *arg ATTR_UNUSED)
{
    api_rest_ret(ctx, HTTP_STATUS_NOT_FOUND, API_REST_ERR_NOT_FOUND);
    return 0;
}

static int
api_rest_bad_request(struct api_rest_req_ctx *ctx, void *arg ATTR_UNUSED)
{
    api_rest_ret(ctx, HTTP_STATUS_BAD_REQUEST, API_REST_ERR_BAD_REQUEST);
    return 0;
}

static int
api_rest_unauthorized(struct api_rest_req_ctx *ctx, void *arg ATTR_UNUSED)
{
    api_rest_ret(ctx, HTTP_STATUS_UNAUTHORIZED, API_REST_ERR_UNAUTHORIZED);
    return 0;
}

static int
api_rest_access_forbidden(struct api_rest_req_ctx *ctx,
				void *arg ATTR_UNUSED)
{
    api_rest_ret(ctx, HTTP_STATUS_ACCESS_FORBIDDEN,
		 API_REST_ERR_ACCESS_FORBIDDEN);
    return 0;
}

static int
api_rest_request_timeout(struct api_rest_req_ctx *ctx,
			       void *arg ATTR_UNUSED)
{
    api_rest_ret(ctx, HTTP_STATUS_REQUEST_TIMEOUT, API_REST_ERR_REQUEST_TIMEOUT);
    return 0;
}

static int
api_rest_internal_error(struct api_rest_req_ctx *ctx,
			      void *arg ATTR_UNUSED)
{
    api_rest_ret(ctx, HTTP_STATUS_INTERNAL_ERROR, API_REST_ERR_INTERNAL_ERROR);
    return 0;
}

static void
api_rest_inc_err(struct api_rest *api, unsigned long long *err)
{
    if ((api->option & API_OPT_STATS)) {
	(*err)++;
	api->stats.err++;
    }
}
