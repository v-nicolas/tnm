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

#include <stdlib.h>

#include "log.h"
#include "nm_common.h"
#include "http.h"

#define NM_ERR_RESET(e,r)			\
    do {					\
	r = 0;					\
	if (e != NULL) {			\
	    *e = NULL;				\
	}					\
    } while (0)

#define NM_ERR_SET(e,msg,r)			\
    do {					\
    	r = -1;					\
	if (e != NULL) {			\
	    *e = dump_err(msg);			\
	}					\
    } while (0)

int
nm_check_frequency(int value, char **err)
{
    int ret;

    NM_ERR_RESET(err, ret);
    if (NM_INVALID_FREQ(value) == 1) {
	NM_ERR_SET(err, NM_ERR_FREQ_INVALID, ret);
    }
    return ret;
}

int
nm_check_timeout(int value, char **err)
{
    int ret;

    NM_ERR_RESET(err, ret);
    if (NM_INVALID_TIMEOUT(value) == 1) {
	NM_ERR_SET(err, NM_ERR_TIMEOUT_INVALID, ret);	
    }
    return ret;
}

int
nm_check_port(int value, char **err)
{
    int ret;

    NM_ERR_RESET(err, ret);
    if (NM_INVALID_PORT(value) == 1) {
	NM_ERR_SET(err, NM_ERR_PORT_INVALID, ret);
    }
    return ret;
}

int
nm_ip_version_to_sock_family(int *sock_family, char **err)
{
    int ret;

    NM_ERR_RESET(err, ret);
    switch (*sock_family) {
    case NM_IPv4:
        *sock_family = AF_INET;
        break;
    case NM_IPv6:
        *sock_family = AF_INET6;
        break;
    default:
        if (*sock_family != 0) {
	    NM_ERR_SET(err, NM_ERR_IP_VERSION_INVALID, ret);
        } else {
	    *sock_family = AF_UNSPEC;
	}
        break;
    }
    return ret;
}

int
nm_check_http_method(const char *str, char **err)
{
    int ret;
    
    NM_ERR_RESET(err, ret);
    if (http_check_method(str) < 0) {
	NM_ERR_SET(err, NM_ERR_HTTP_METHOD_INVALID, ret);
    }
    return ret;
}

int
nm_check_http_version(const char *str, char **err)
{
    int ret;
    
    NM_ERR_RESET(err, ret);
    if (http_check_version(str) < 0) {
	NM_ERR_SET(err, NM_ERR_HTTP_METHOD_INVALID, ret);
    }
    return ret;
}

int
nm_check_http_auth(const char *auth_type, const char *auth_value, char **err)
{
    int ret;
    
    NM_ERR_RESET(err, ret);
    if ((auth_type[0] != 0 && auth_value == NULL) ||
	(auth_type[0] == 0 && auth_value != NULL)) {
	NM_ERR_SET(err, NM_ERR_HTTP_AUTH_INVALID, ret);
    }
    return ret;
}
