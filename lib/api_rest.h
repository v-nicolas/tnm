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

#include "http.h"

#define API_REST_ERR_TIMEOUTED "Timeouted"

#define API_REST_DEFUALT_PORT 8000
#define API_REST_DEFUALT_READ_TIMEOUT 2

#define API_REST_ROUTE_SIZE 255

enum api_rest_route_option {
    API_ROUTE_OPT_PROTECTED = (1 << 0),
};

struct api_rest {
    int srv_fd;
    int srv_ip_version;
    int srv_port;
    int route_protected;
    unsigned int read_timeout;
    char *srv_bind_addr;
    char *bearer;
    struct api_rest_route *route;
    
    /* 404 */
    void *(*route_not_found)(struct http_header *, void *);
};

//struct api_rest_ctx {
    
//};

typedef int (*api_rest_handler_t)(void *, void *);
struct api_rest_route {
    int option;
    api_rest_handler_t handler;
    void *handler_argument;
    struct api_rest_route *next;
    char method[HTTP_METHOD_SIZE];
    char path[API_REST_ROUTE_SIZE];
};


struct api_rest * api_rest_new(void);
void api_rest_set_route_protected(struct api_rest *api, int enable);
void api_rest_free(struct api_rest *api);
int api_rest_create_server(struct api_rest *api);
int api_rest_add_route_get(struct api_rest *api, const char *path,
			   api_rest_handler_t handler, void *handler_arg);
int api_rest_add_route_post(struct api_rest *api, const char *path,
			    api_rest_handler_t handler, void *handler_arg);
int api_rest_add_route_put(struct api_rest *api,const char *path,
			   api_rest_handler_t handler, void *handler_arg);
int api_rest_add_route_delete(struct api_rest *api, const char *path,
			      api_rest_handler_t handler, void *handler_arg);
int api_rest_parse_request(struct http_header *http);
int api_rest_read(struct api_rest *api, int cli_fd, struct http_header *http);

#endif /* !API_REST_H */
