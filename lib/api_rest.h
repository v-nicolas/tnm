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

#ifndef API_REST_H
#define API_REST_H

#include <netinet/in.h>

#include "http.h"

#define API_REST_ERR_TIMEOUTED "Timeouted"

#define API_REST_DEFUALT_PORT 8000
#define API_REST_DEFUALT_READ_TIMEOUT 2

#define API_REST_ROUTE_SIZE 255

#define API_REST_ENBALE_PROTECTED_ROUTE  1
#define API_REST_DISABLE_PROTECTED_ROUTE 0

/* To easely change the prototype of handlers */
#define DECLARE_HTTP_ROUTE(name) \
    int http_route_##name(struct api_rest_req_ctx *s, void *arg)

enum api_rest_route_options {
    API_ROUTE_OPT_PROTECTED = (1 << 0),
};

enum api_rest_options {
    API_OPT_SRV_SSL	= (1 << 0), /* not yet */
    API_OPT_STATS	= (1 << 1),
};

struct api_rest_req_ctx {
    char client_ip[INET6_ADDRSTRLEN];
    struct http_header in;
    struct http_header out;
};

typedef int (*api_rest_handler_t)(struct api_rest_req_ctx *, void *);

struct api_rest_route_handler {
    void *arg;
    api_rest_handler_t func;
};

struct api_rest_route {
    int option;
    struct api_rest_route *next;
    struct api_rest_route_handler handler;
    char method[HTTP_METHOD_SIZE];
    char path[API_REST_ROUTE_SIZE];
};

struct api_rest_err_routes {    
    struct api_rest_route_handler bad_request;
    struct api_rest_route_handler unauthorized;
    struct api_rest_route_handler access_forbidden;
    struct api_rest_route_handler not_found;
    struct api_rest_route_handler request_timeout;
    struct api_rest_route_handler internal_error;
};

struct api_rest_stats {
    unsigned long long nreq;
    unsigned long long err;
    unsigned long long bad_request;
    unsigned long long unauthorized;
    unsigned long long access_forbidden;
    unsigned long long not_found;
    unsigned long long req_timeout;
    unsigned long long internal_err;
};

struct api_rest {
    int option;
    int srv_fd;
    int srv_ip_version;
    int srv_port;
    int route_protected;
    unsigned int read_timeout;
    char *srv_bind_addr;
    char *bearer;
    struct api_rest_route *routes;
    struct api_rest_err_routes err;
    struct api_rest_stats stats;
};

struct api_rest * api_rest_new(void);
void api_rest_get_stats(struct api_rest *api, struct sbuf *str);
void api_rest_stats_enable(struct api_rest *api);
void api_rest_stats_disable(struct api_rest *api);
void api_rest_set_route_protected(struct api_rest *api, int enable);
void api_rest_free(struct api_rest *api);
int api_rest_create_server(struct api_rest *api);
int api_rest_set_error_route(struct api_rest *api, int errcode,
			     api_rest_handler_t handler,
			     void *handler_arg);
int api_rest_add_route_get(struct api_rest *api, const char *path,
			   api_rest_handler_t handler, void *handler_arg);
int api_rest_add_route_post(struct api_rest *api, const char *path,
			    api_rest_handler_t handler, void *handler_arg);
int api_rest_add_route_put(struct api_rest *api,const char *path,
			   api_rest_handler_t handler, void *handler_arg);
int api_rest_add_route_delete(struct api_rest *api, const char *path,
			      api_rest_handler_t handler, void *handler_arg);
int api_rest_client_handler(struct api_rest *api);
int api_rest_parse_request(struct http_header *http);
int api_rest_read(struct api_rest *api, int cli_fd,
		  struct api_rest_req_ctx *ctx);
void api_rest_ret(struct api_rest_req_ctx *ctx,
		  int status_code, const char *payload);

#endif /* !API_REST_H */
