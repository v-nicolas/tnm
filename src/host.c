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

#include "host.h"
#include "nm.h"
#include "db.h"

#include "../lib/mem.h"
#include "../lib/log.h"
#include "../lib/dlist.h"
#include "../lib/str.h"
#include "../lib/json_utils.h"
#include "../lib/nm_common.h"

struct host *
host_init_ptr(void)
{
    struct host *host = NULL;
    
    host = xcalloc(sizeof(struct host));
    host_init(host);
    return host;
}

void
host_init(struct host *host)
{
    memset(host, 0, sizeof(struct host));
    host->http = xcalloc(sizeof(struct http_header));
    sbuf_init(&host->http->header);
}

void
host_free(void *arg)
{
    struct host *host = NULL;

    host = arg;
    http_header_free(host->http);
    if (host->sock.close != NULL) {
	host->sock.close(&host->sock);
    }
    xfree(host);
}

void
host_delete_by_process(struct nm_process *process)
{
    struct host *host = NULL;

    /* Cannot delete host before unlist,
     * The db type file list all host and write.
     * Need unlist before rewrite the file.
     * With mongo no problem.
     */
    DLIST_UNLINK(nm->monitoring, process);
    host = process->data;
    db_host_del(host->uuid);
    nm_process_free(process);
}

int
host_set_uuid(struct host *new_host, char **err)
{
    if (new_host->uuid[0] != 0) {
        if (host_get_by_uuid(new_host->uuid) != NULL) {
	    *err = dump_err(NM_ERR_UUID_ALREADY_USED);
            return -1;
        }
    } else {
	if (host_get_unused_uuid(new_host->uuid) < 0) {
	    *err = dump_err(NM_ERR_UUID_GENERATE);
            return -1;
        }
    }
    return 0;
}

struct nm_process *
host_add(struct host *host, char **err ATTR_UNUSED)
{
    struct nm_process *process = NULL;

    process = host_link(host);
    db_host_add(host);
    return process;
}

struct nm_process *
host_link(struct host *host)
{
    struct nm_process *process = NULL;

    host->state = HOST_STATE_UP;
    process = xcalloc(sizeof(*process));
    process->state = NM_PROCESS_KILL;
    process->data = host;
    process->free_data = host_free;
    DLIST_LINK(nm->monitoring, process);
    return process;
}

struct nm_process *
host_get_process_by_uuid(const char *uuid)
{
    struct host *host = NULL;
    struct nm_process *monitoring = NULL;
    
    LIST_FOREACH(nm->monitoring, monitoring) {
	host = monitoring->data;
	if (STREQ(host->uuid, uuid)) {
	    return monitoring;
	}
    }
    return NULL;
}

struct host *
host_get_by_uuid(const char *uuid)
{
    struct host *host = NULL;
    struct nm_process *monitoring = NULL;
    
    LIST_FOREACH(nm->monitoring, monitoring) {
	host = monitoring->data;
	if (STREQ(host->uuid, uuid)) {
	    return host;
	}
    }
    return NULL;
}

void
host_free_unused(const char *uuid)
{
    struct host *host = NULL;
    struct nm_process *monitoring = NULL;
    struct nm_process *nextptr = NULL;
    
    for (monitoring = nm->monitoring; monitoring; monitoring = nextptr) {
	nextptr = monitoring->next;
	host = monitoring->data;
	if (STRNEQ(host->uuid, uuid)) {
	    DLIST_UNLINK(nm->monitoring, monitoring);
	    nm_process_free(monitoring);
	}
    }

#ifndef NDEBUG   
    if (nm->monitoring == NULL ||
	nm->monitoring->next != NULL ||
	nm->monitoring->prev != NULL) {
	fatal("Fail to clean unused hosts list");
    }
#endif /* !NDEBUG */
}

int
host_get_unused_uuid(char *uuid)
{
    int ret;

    do {
        ret = uuid_generate(uuid, 0);
        if (ret < 0) {
            return -1;
        }
	ret = db_uuid_exists(uuid);
    } while (ret > 0);

    return 0;
}

int
host_parse_json(struct host *host, cJSON *json_host)
{
    int i;
    struct json_var host_json_vars[] = {
        JSON_INIT_NBR("options", &host->options),
        JSON_INIT_NBR("monitoring_type", &host->monit_type),
        JSON_INIT_NBR("timeout", &host->timeout),
        JSON_INIT_NBR("frequency", &host->frequency),
        JSON_INIT_NBR("port", &host->sock.port),
        JSON_INIT_NBR("ip_version", &host->sock.family),
        JSON_INIT_STR(INET6_ADDRSTRLEN, "ip", host->sock.straddr),
        JSON_INIT_STR(HOSTNAME_LEN, "hostname", host->hostname),
        JSON_INIT_STR(UUID_SIZE, "uuid", host->uuid),
        JSON_INIT_STR(HTTP_METHOD_SIZE, "http_method", host->http->method),
        JSON_INIT_STR(HTTP_VERSION_SIZE, "http_version", host->http->version),
        JSON_INIT_STR(HTTP_PATH_SIZE, "http_path", host->http->path),
        JSON_INIT_STR(HTTP_USER_AGENT_SIZE, "http_user_agent",
		      host->http->user_agent),
        JSON_INIT_STR(HTTP_AUTHORIZATION_SIZE, "http_auth_type",
		      host->http->auth_type),
        JSON_INIT_STRPTR("http_auth_value", &host->http->auth_value),
        JSON_INIT_LAST,
    };

    for (i = 0; host_json_vars[i].name != NULL; i++) {
        if (json_get_var_opts(json_host,
                              &host_json_vars[i],
                              JSON_OPT_OMITEMPTY) < 0) {
            err("parse_json: %s\n", host_json_vars[i].err);
            return -1;
        }
    }
    
    DEBUG("host parsed:\n"
          "\toption: %d\n"
          "\toption_ssl: %d\n"
          "\tmonit_type: %d\n"
          "\ttimeout: %d\n"
          "\tfrequency: %d\n"
          "\tports: %d\n"
          "\tip: %s\n"
          "\tip_version: %d\n"
          "\thostname: %s\n"
          "\tuuid: %s\n"
          "\thttp_method: %s\n"
          "\thttp_version: %s\n"
          "\thttp_path: %s\n"
          "\thttp_user_agent: %s\n"
          "\thttp_auth_type: %s\n"
          "\thttp_auth_value: %s\n",
          host->options, (host->options & MONIT_OPT_SSL),
	  host->monit_type, host->timeout,
          host->frequency, host->sock.port,
          host->sock.straddr, host->sock.family, host->hostname,
	  host->uuid, host->http->method, host->http->version,
	  host->http->path, host->http->user_agent,
	  host->http->auth_type, host->http->auth_value);

    return 0;
}
