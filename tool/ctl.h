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

#ifndef TOOL_CTL_H
#define TOOL_CTL_H

#include <stddef.h>
#include <netinet/in.h>
#include <limits.h>

#include "../lib/uuid.h"
#include "../lib/http.h"

#define HOSTNAME_LEN 255

#define IP_STR_VERSION6 "6"
#define IP_STR_VERSION4 "4"

#define SNM_PORT_MIN 0x01
#define SNM_PORT_MAX 0xffff

#define SNM_TIMEOUT_MAX 30
#define SNM_TIMEOUT_MIN 1

#define FREQUENCY_ONCE "once"
#define SNM_FREQUENCY_MIN 10 
#define SNM_FREQUENCY_MAX 172800 // 48 hours

struct control {
    int fd;
    char *sockpath;
    int cmd;
    int port;
    int monit;
    int ip_version;
    int timeout;
    int frequency;
    int protocol;
    int options;
    char *http_auth_type;
    char *http_auth_value;
    char http_path[HTTP_PATH_SIZE];
    char http_method[HTTP_METHOD_SIZE];
    char http_version[HTTP_VERSION_SIZE];
    char http_user_agent[HTTP_USER_AGENT_SIZE];
    char uuid[UUID_SIZE];
    char ip[INET6_ADDRSTRLEN];
    char hostname[HOSTNAME_LEN];
    char path[PATH_MAX];
};

int control_run(struct control *x);
void control_exit(int code, struct control *x);
void control_free(struct control *x);
int set_str_value(char *var_value,
		  const char *var_name,
		  size_t len, const char *arg);
int set_monit_type(int *type, const char *v);
int set_ip_version(int *ip_version, const char *v);
int set_timeout(int *timeout, const char *v);
int set_frequency(int *freq, const char *v);
int set_port(int *port, const char *v);
int sock_unix_client_create(const char *path);
int set_ip(char *strip, const char *v, int *version);

#endif /* not have TOOL_CTL_H */
