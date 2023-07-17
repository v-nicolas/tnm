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

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "../lib/log.h"
#include "../lib/mem.h"
#include "../lib/str.h"
#include "../lib/sock.h"
#include "../lib/attr.h"
#include "../lib/uuid.h"
#include "../lib/nm_common.h"
#include "../lib/file_utils.h"

#include "ctl.h"

void /* no retiurn */
control_exit(int code, struct control *x)
{
    control_free(x);
    exit(code);
}

void
control_free(struct control *x)
{
    xfree(x->sockpath);
    xfree(x->http_auth_value);
    xclose(x->fd);
}

int
set_str_value(char *var_value,
	      const char *var_name,
	      size_t len, const char *arg)
{
    if (arg == NULL || *arg == 0) {
	err("%s is empty\n", var_name);
	return -1;	
    }
    
    memset(var_value, 0, len);

    len--;
    if (strlen(arg) > len) {
	err("%s `%s' size is too big\n", var_name, arg);
	return -1;
    }

    strncpy(var_value, arg, len);
    return 0;
}

int
set_ip_version(int *ip_version, const char *v)
{
    *ip_version = 0;
    
    if (STREQ(v, "4")) {
	*ip_version = 4;
    } else if (STREQ(v, "6")) {
	*ip_version = 6;
    }

    if (*ip_version == 0) {
	err("IP version `%s' invalid\n", v);
	return -1;
    }
    
    return 0;
}

int
set_monit_type(int *type, const char *v)
{
    *type = -1;
    
    if (STREQ("port", v)) {
	*type = MONIT_PORT;
    } else if (STREQ("ping", v)) {
	*type = MONIT_PING;
    } else if (STREQ("http", v)) {
	*type = MONIT_HTTP;
    }

    if (*type < 0) {	
	err(NM_ERR_MONIT_TYPE_INVALID);
	return -1;
    }

    return 0;
}

int
set_port(int *port, const char *v)
{
    unsigned long int buf;

    if (xstrtoul(v, &buf, 10) < 0) {
	err("Timeout invalid integer value `%s'\n", v);
	return -1;
    }

    *port = (int) buf;
    if (*port > NM_PORT_MAX || *port < NM_PORT_MIN) {
	err("Timeout value `%d' invalid value (max <= %d, min >=%d)\n",
	    *port, NM_PORT_MAX, NM_PORT_MIN);
	return -1;
    }

    return 0;
}

int
set_ip(char *strip, const char *v, int *version)
{
    ATTR_AUTOFREE unsigned char *buf = NULL;

    if (v == NULL || *v == 0) {
	err("IP is empty;\n");
	return -1;
    }

    buf = xcalloc(sizeof(struct in6_addr));

    /* Is ipv4 ? */
    if (inet_pton(AF_INET, v, buf) == 1) {
	strncpy(strip, v, INET_ADDRSTRLEN);
	*version = 4;
	return 0;
    }

    /* Is ipv6 */
    if (inet_pton(AF_INET6, v, buf) == 1) {
	strncpy(strip, v, INET6_ADDRSTRLEN);
	*version = 6;
	return 0;
    }

    /* Invalid IP format */
    err("Invalid IP `%s' format (not IPv4/IPv6)\n", v);
    return -1;
}

int
set_timeout(int *timeout, const char *v)
{
    unsigned long int buf;

    if (xstrtoul(v, &buf, 10) < 0) {
	err("Timeout invalid integer value `%s'\n", v);
	return -1;
    }

    *timeout = (int) buf;
    if (*timeout > SNM_TIMEOUT_MAX || *timeout < SNM_TIMEOUT_MIN) {
	err("Timeout value `%d' invalid value (max <= %d, min >=%d)\n",
	    *timeout, SNM_TIMEOUT_MAX, SNM_TIMEOUT_MIN);
	return -1;
    }

    return 0;
}

int
set_frequency(int *freq, const char *v)
{
    unsigned long int buf;
    
    if (STREQ(FREQUENCY_ONCE, v)) {
	*freq = 0;
	return 0;
    }
    
    if (xstrtoul(v, &buf, 10) < 0) {
	err("Frequency invalid integer value `%s'\n", v);
	return -1;
    }
    if (buf < SNM_FREQUENCY_MIN || buf > SNM_FREQUENCY_MAX) {
	err("Frequency value `%d' invalid value (max <= %d, min >=%d)\n",
	    (int) buf, SNM_FREQUENCY_MAX, SNM_FREQUENCY_MIN);
	return -1;
    }

    *freq = (int) buf;
    return 0;
}
