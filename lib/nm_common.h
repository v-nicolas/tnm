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

#ifndef LIB_NM_COMMON_H
#define LIB_NM_COMMON_H

#include "sock.h"
#include "http.h"

#define SOCKU_CTL_DEFAULT_PATH "/tmp/nm_ctl.sock"

#define NM_IPv4 4
#define NM_IPv6 6

#define NM_PORT_MIN 1
#define NM_PORT_MAX 65535

#define NM_TIMEOUT_MIN 5
#define NM_TIMEOUT_MAX 30

#define NM_FREQ_MIN 15
#define NM_FREQ_MAX 86400 /* 3600*24 (one day) */

#define NM_INVALID_FREQ(f) (f < NM_FREQ_MIN || f > NM_FREQ_MAX)
#define NM_INVALID_TIMEOUT(t) (t < NM_TIMEOUT_MIN || t > NM_TIMEOUT_MAX)
#define NM_INVALID_PORT(p) (p < NM_PORT_MIN || p > NM_PORT_MAX)

#define NM_ERR_UNKNOW                "Unknown error occurred."
#define NM_ERR_TIMEOUT               "Operation timeouted."
#define NM_ERR_JSON_INVALID          "Fail to parse JSON." /* todo: is used ? */
#define NM_ERR_TYPE_INVALID          "Command type missing or invalid."
#define NM_ERR_TYPE_CTRL_INVALID     "Command type control missing or invalid."
#define NM_ERR_UUID_MISSING          "UUID missing or empty."
#define NM_ERR_UUID_NOT_FOUND        "UUID not found."
#define NM_ERR_UUID_ALREADY_USED     "UUID already used."
#define NM_ERR_UUID_GENERATE         "Fail to generate new UUID."
#define NM_ERR_MONIT_TYPE_INVALID    "Monitoring type invalid or empty."
#define NM_ERR_ADDR_MISSING          "Host IP and hostname is empty."
#define NM_ERR_FREQ_INVALID          "Frequency invalid."
#define NM_ERR_TIMEOUT_INVALID       "Timeout invalid."
#define NM_ERR_PORT_INVALID          "Port out of range."
#define NM_ERR_IP_VERSION_INVALID    "IP version invalid."
#define NM_ERR_RESOLV_ADDR_FAIL      "Cannot resolv address."
#define NM_ERR_START_PROCESS_FAIL    "Cannot start new processus."
#define NM_ERR_KILL_PROCESS_FAIL     "Cannot kill the processus."
#define NM_ERR_HTTP_METHOD_INVALID   "HTTP method invalid."
#define NM_ERR_HTTP_AUTH_INVALID     "HTTP auth invalid."
#define NM_ERR_RELOAD_CRITICAL       "Reload hosts fail, maybe need restart the program."
#define NM_ERR_NO_COMPIL_WITH_LIBSSL "Add new host with SSL option fail, this program not compiled with libssl"

enum commands_names {
    CMD_ERROR         = -1,
    CMD_SUCCESS       = 0,
    CMD_ADD           = 1,
    CMD_DEL           = 2,
    CMD_UPDATE        = 3,
    CMD_LIST          = 4,
    CMD_MONIT_SUSPEND = 5,
    CMD_MONIT_RESUME  = 6,
    CMD_CONTROL       = 7,
};

enum commands_control {
    CMD_CTRL_RELOAD_HOSTS,
    CMD_CTRL_API_REST_STATS,
    CMD_CTRL_API_REST_STATS_ENABLE,
    CMD_CTRL_API_REST_STATS_DISABLE,
};

enum monoting_list {
    MONIT_ERR     = -1,
    MONIT_ERR0    = 0,
    MONIT_PING    = 1,
    MONIT_HTTP    = 2,
    MONIT_PORT    = 3,
    MONIT_ERR_MAX = 4,
};

enum monit_options {
    MONIT_OPT_SSL = (1 << 0),
};

int nm_check_frequency(int value, char **err);
int nm_check_timeout(int value, char **err);
int nm_check_port(int value, char **err);
int nm_ip_version_to_sock_family(int *sock_family, char **err);
int nm_check_http_method(const char *str, char **err);
int nm_check_http_version(const char *str, char **err);
int nm_check_http_auth(const char *auth_type, const char *auth_value, char **err);

#endif /* !LIB_NM_COMMON_H */
