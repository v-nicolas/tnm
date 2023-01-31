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

#include "command.h"
#include "nm.h"
#include "host.h"

#include "../lib/log.h"
#include "../lib/mem.h"
#include "../lib/str.h"
#include "../lib/sbuf.h"
#include "../lib/dlist.h"
#include "../lib/sock.h"
#include "../lib/http.h"
#include "../lib/json_utils.h"
#include "../lib/nm_common.h"

#ifndef CMD_SIZE
# define CMD_SIZE 2048
#endif /* !CMD_SIZE */

static int cmd_read(struct cmd *cmd);
static int cmd_parse(const char *buffer, struct cmd *cmd);
static int cmd_exec(struct cmd *cmd);
static int cmd_monit_type_port(struct cmd *cmd);
static int cmd_monit_type_ping(struct cmd *cmd);
static int cmd_monit_type_http(struct cmd *cmd);
static int cmd_host_del(struct cmd *cmd);
static int cmd_host_reload(struct cmd *cmd);
static int cmd_host_suspend(struct cmd *cmd);
static int cmd_host_resume(struct cmd *cmd);
static int cmd_change_state(struct cmd *cmd, int new_state);
static void cmd_reply_add_host_info(struct sbuf *str, struct host *host);
static void cmd_reply_add_suspend_info(struct sbuf *str,
				       struct nm_process_suspend *suspend);
static void cmd_reply_add_host_state(struct cmd *cmd, struct host *host);
static void cmd_reply_add_monit_type(struct cmd *cmd, struct host *host);
static void cmd_reply_add_host(struct cmd *cmd, struct host *host);
static void cmd_build_err_msg(struct cmd *cmd);

void
cmd_handler(int fdcli)
{
    int ret;
    struct cmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    sbuf_init(&cmd.reply);
    cmd.sockcli = fdcli;
    cmd.host = host_init_ptr();

    ret = cmd_read(&cmd);
    if (ret == 0) {
	ret = cmd_exec(&cmd);
    }

    if (ret < 0 && cmd.error == NULL) {
	cmd.error = dump_err(NM_ERR_UNKNOW);
    }

    if (cmd.error != NULL) {
	cmd_build_err_msg(&cmd);
    } else {
	/* Always in reply */
	sbuf_vadd(&cmd.reply, JSON_SET_INT("status", 0));
	sbuf_vadd(&cmd.reply, JSON_SET_INT("command", cmd.type));
    }

    sbuf_add_to_offset(&cmd.reply, 0, JSON_OPEN);
    json_close(&cmd.reply, JSON_CLOSE);
    DEBUG("Send: %s\n", cmd.reply.buf);
    (void) sock_write_fd(fdcli, cmd.reply.buf, sbuf_len(&cmd.reply));

    if (cmd.type != CMD_ADD || cmd.error != NULL) {
	xfree(cmd.host->http);
	xfree(cmd.host);
    }
    
    xfree(cmd.error);
    sbuf_free(&cmd.reply);
    cJSON_Delete(cmd.monitor);
}

static int
cmd_read(struct cmd *cmd)
{
    ssize_t ret;
    char buffer[CMD_SIZE];

    memset(buffer, 0, CMD_SIZE);
    ret = sock_read_fd(cmd->sockcli, buffer, CMD_SIZE, 2);
    if (ret == SOCK_RET_TIMEOUT) {
        cmd->error = dump_err(NM_ERR_TIMEOUT);
    }
    if (ret < 1) {
	return -1;
    }

    DEBUG("Command recieved: %s\n", buffer);
    return cmd_parse(buffer, cmd);
}

static int
cmd_parse(const char *buffer, struct cmd *cmd)
{
    struct json_var jvar = JSON_INIT_NBR("command", &cmd->type);
    
    cmd->monitor = cJSON_Parse(buffer);
    if (cmd->monitor == NULL) {
	cmd->error = dump_err("%s", cJSON_GetErrorPtr2());
        return -1;
    }

    if (json_get_var(cmd->monitor, &jvar) < 0) {
        cmd->error = dump_err(NM_ERR_TYPE_INVALID);
	return -1;
    }
    cmd->type_init = 1;
    
    return host_parse_json(cmd->host, cmd->monitor);
}

static int
cmd_exec(struct cmd *cmd)
{
    int ret;

    switch (cmd->type) {
    case CMD_ADD:
	ret = cmd_add_host(cmd);
	break;
    case CMD_DEL:
	ret = cmd_host_del(cmd);
	break;
    case CMD_LIST:
	ret = cmd_host_list(cmd);
	break;
    case CMD_RELOAD_HOSTS_FILE:
	ret = cmd_host_reload(cmd);
	break;
    case CMD_MONIT_RESUME:
	ret = cmd_host_resume(cmd);
	break;
    case CMD_MONIT_SUSPEND:
	ret = cmd_host_suspend(cmd);
	break;
    default:
	cmd->error = dump_err(NM_ERR_TYPE_INVALID);
	ret = -1;
    }
    
    if (ret < 0) {
	return -1;
    }
    
    return 0;
}

int
cmd_add_host(struct cmd *cmd)
{
    struct nm_process *process = NULL;
    
    if (cmd_check_host_fields(cmd) < 0) {
	return -1;
    }

    process = host_add(cmd->host, &cmd->error);
    if (process == NULL) {
	return -1;
    }

    if (nm_process_run(process, nm_host_monitoring) < 0) {
	cmd->error = dump_err(NM_ERR_START_PROCESS_FAIL);
	host_delete_by_process(process);
	return -1;
    }

    cmd_reply_add_host(cmd, cmd->host);
    return 0;
}

int
cmd_check_host_fields(struct cmd *cmd)
{
    int ret;
    char *buf = NULL;
    
    if (nm_check_frequency(cmd->host->frequency, &cmd->error) < 0) {
	return -1;
    }
    if (nm_check_timeout(cmd->host->timeout, &cmd->error) < 0) {
	return -1;
    }

    switch (cmd->host->monit_type) {
    case MONIT_PORT:
        ret = cmd_monit_type_port(cmd);
        break;
    case MONIT_PING:
        ret = cmd_monit_type_ping(cmd);
        break;
    case MONIT_HTTP:
        ret = cmd_monit_type_http(cmd);
        break;
    default:
        ret = -1;
        cmd->error = dump_err(NM_ERR_MONIT_TYPE_INVALID);
        break;
    }
    if (ret == -1) {
        return -1;
    }

    if (cmd->host->monit_type != MONIT_PING) {
	if (nm_check_port(cmd->host->sock.port, &cmd->error) < 0) {
	    return -1;
	}
    }

    if (nm_ip_version_to_sock_family(&cmd->host->sock.family,
				     &cmd->error) < 0) {
	return -1;
    }

    buf = cmd->host->sock.straddr;
    if (cmd->host->sock.straddr[0] == 0) {
        if (cmd->host->hostname[0] == 0) {
	    cmd->error = dump_err(NM_ERR_ADDR_MISSING);
            return -1;
        }
        buf = cmd->host->hostname;
    }

    if (sock_resolv_addr(buf, &cmd->host->sock) < 0) {
        cmd->error = dump_err(NM_ERR_RESOLV_ADDR_FAIL);
        return -1;
    }

    if (host_set_uuid(cmd->host, &cmd->error) < 0) {
	return -1;
    }
    
    if (cmd->host->monit_type == MONIT_PING &&
	cmd->host->sock.family == AF_INET6) {
        cmd->host->sock.proto = IPPROTO_ICMPV6;
    }

     return 0;
}

static int
cmd_monit_type_port(struct cmd *cmd)
{
    cmd->host->sock.type = SOCK_STREAM;
    cmd->host->sock.proto = 0;
    http_header_free(cmd->host->http);
    cmd->host->http = NULL;
    return 0;
}

static int
cmd_monit_type_ping(struct cmd *cmd)
{
    cmd->host->sock.port = 0;
    cmd->host->sock.type = SOCK_RAW;
    cmd->host->sock.proto = IPPROTO_ICMP;
    http_header_free(cmd->host->http);
    cmd->host->http = NULL;
    return 0;
}

static int
cmd_monit_type_http(struct cmd *cmd)
{
    struct host *host = NULL;

    host = cmd->host;
    if (nm_check_http_auth(host->http->auth_type,
			   host->http->auth_value,
			   &cmd->error) < 0) {
	return -1;
    }

    if (host->http->user_agent[0] == 0) {
	strncpy(host->http->user_agent,
		HTTP_USER_AGENT_DEFAULT,
		HTTP_USER_AGENT_SIZE);
    }
    
    if (host->http->method[0] == 0) {
	strncpy(host->http->method, HTTP_GET, HTTP_METHOD_SIZE);
    } else {
	if (nm_check_http_method(host->http->method, &cmd->error) < 0) {
	    return -1;
	}
    }

    if (host->http->version[0] == 0) {
	strncpy(host->http->version, HTTP_VERSION_1_1, HTTP_VERSION_SIZE);
    } else {
	if (nm_check_http_version(host->http->version, &cmd->error) < 0) {
	    return -1;
	}
    }

    // todo: path is empty: set by default

    host->sock.type = SOCK_STREAM;
    if (host->options & MONIT_OPT_SSL) {
        if (host->sock.port == 0) {
            host->sock.port = PORT_HTTPS;
        }
    } else {
        if (host->sock.port == 0) {
            host->sock.port = PORT_HTTP;
        }
    }
    return 0;
}

static int
cmd_host_del(struct cmd *cmd)
{
    struct host *host = NULL;
    struct nm_process *process = NULL;

    if (cmd->host->uuid[0] == 0) {
	cmd->error = dump_err(NM_ERR_UUID_MISSING);
	return -1;
    }
    
    process = host_get_process_by_uuid(cmd->host->uuid);
    if (process == NULL) {
	cmd->error = dump_err(NM_ERR_UUID_NOT_FOUND);
	return -1;
    }
    if (nm_process_kill_and_wait(process) < 0) {
	cmd->error = dump_err(NM_ERR_KILL_PROCESS_FAIL);
	return -1;
    }

    host = process->data;
    sbuf_vadd(&cmd->reply, JSON_SET_STR("uuid", host->uuid));
    sbuf_vadd(&cmd->reply, JSON_SET_INT("command", cmd->type));

    host_delete_by_process(process);
    return 0;
}

static int
cmd_host_reload(struct cmd *cmd)
{
    char cmd_path[PATH_SIZE];
    const char *path = NULL;
    struct json_var jvar = JSON_INIT_STR(PATH_SIZE, "path", cmd_path);

    memset(cmd_path, 0, sizeof(cmd_path));
    (void) json_get_var(cmd->monitor, &jvar);
    path = (cmd_path[0] == 0) ? nm->hosts_path : cmd_path;
    if (nm_reload_hosts(path) < 0) {
	cmd->error = xstrdup(NM_ERR_RELOAD_CRITICAL);
	return -1;
    }
    return 0;
}

static int
cmd_host_suspend(struct cmd *cmd)
{
    return cmd_change_state(cmd, NM_PROCESS_SUSPEND);
}

static int
cmd_host_resume(struct cmd *cmd)
{
    return cmd_change_state(cmd, NM_PROCESS_RESUME);
}

static int
cmd_change_state(struct cmd *cmd, int new_state)
{
    unsigned int opts;
    struct nm_process *process = NULL;

    if (cmd->host->uuid[0] == 0) {
	process = nm->monitoring;
	opts = NM_PROCESS_OPT_ALL;
	if (new_state == NM_PROCESS_SUSPEND) {
	    nm_process_suspend_init(&nm->suspend, cmd->host->timeout);
	}
	strncpy(cmd->host->uuid, "all", UUID_SIZE);
    } else {
	process = host_get_process_by_uuid(cmd->host->uuid);
	if (process == NULL) {
	    cmd->error = xstrdup(NM_ERR_UUID_NOT_FOUND);
	    return -1;
	}
	opts = NM_PROCESS_OPT_ONE;
	if (new_state == NM_PROCESS_SUSPEND) {
	    nm_process_suspend_init(&process->suspend, cmd->host->timeout);
	}
    }
    return nm_process_change_state(new_state, opts, process);
}

int
cmd_host_list(struct cmd *cmd)
{
    struct host *host = NULL;
    struct nm_process *monitoring = NULL;
    
    if (cmd->host->uuid[0] != 0) {
	host = host_get_by_uuid(cmd->host->uuid);
	if (host == NULL) {
	    cmd->error = dump_err(NM_ERR_UUID_NOT_FOUND);
	    return -1;
	}
	cmd_reply_add_host(cmd, host);
	cmd_reply_add_host_state(cmd, host);
    } else {
	sbuf_add(&cmd->reply, "\"hosts\":"JSON_ARRAY_OPEN);
	LIST_FOREACH(nm->monitoring, monitoring) {
	    host = monitoring->data;
	    cmd_host_to_json(cmd, host);
	    sbuf_add(&cmd->reply, ",");
	}
	json_close(&cmd->reply, JSON_ARRAY_CLOSE);
	sbuf_add(&cmd->reply, ",");
    }
    return 0;
}

void
cmd_host_to_json(struct cmd *cmd, struct host *host)
{
    sbuf_add(&cmd->reply, JSON_OPEN);
    cmd_reply_add_host(cmd, host);
    cmd_reply_add_host_state(cmd, host);
    json_close(&cmd->reply, JSON_CLOSE);
}

static void
cmd_reply_add_host(struct cmd *cmd, struct host *host)
{
    int ip_version;

    if (host->sock.family == AF_INET) {
        ip_version = 4;
    } else {
        ip_version = 6;
    }

    cmd_reply_add_host_info(&cmd->reply, host);
    cmd_reply_add_monit_type(cmd, host);
    sbuf_vadd(&cmd->reply, JSON_SET_INT("ip_version", ip_version));
}

static void
cmd_reply_add_host_info(struct sbuf *str, struct host *host)
{
    sbuf_vadd(str, JSON_SET_STR("uuid", host->uuid));
    sbuf_vadd(str, JSON_SET_STR("ip", host->sock.straddr));
    sbuf_vadd(str, JSON_SET_INT("frequency", host->frequency));
    sbuf_vadd(str, JSON_SET_INT("timeout", host->timeout));
    sbuf_vadd(str, JSON_SET_INT("options", host->options));
    if (host->hostname[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("hostname", host->hostname));
    }
}

static void
cmd_reply_add_host_state(struct cmd *cmd, struct host *host)
{
    struct nm_process *process = NULL;
    
    sbuf_vadd(&cmd->reply, JSON_SET_INT("state", host->state));
    sbuf_vadd(&cmd->reply, JSON_SET_STR("str_state",
                                        nm_get_state_str(host->state)));
    if (nm->suspend != NULL) {
	cmd_reply_add_suspend_info(&cmd->reply, nm->suspend);
    } else {
	process = host_get_process_by_uuid(host->uuid);
	if (process != NULL && process->suspend != NULL) {
	    cmd_reply_add_suspend_info(&cmd->reply, process->suspend);
	}
    }
}

static void
cmd_reply_add_suspend_info(struct sbuf *str, struct nm_process_suspend *suspend)
{
    sbuf_vadd(str, "\"suspend\": {");
    sbuf_vadd(str, JSON_SET_ULONG("duration", suspend->duration));
    sbuf_vadd(str, JSON_SET_ULONG("start", suspend->start));
    json_close(str, JSON_CLOSE",");
}

static void
cmd_reply_add_monit_type(struct cmd *cmd, struct host *host)
{
    struct sbuf *str = NULL;
    
    if (cmd->type_init == 0) {
	return;
    }

    str = &cmd->reply;
    sbuf_vadd(str, JSON_SET_INT("monitoring_type", host->monit_type));
    sbuf_vadd(str, JSON_SET_STR("monit_type_str",
				nm_get_monit_type_str(host->monit_type,
						      host->options)));
    
    sbuf_vadd(str, JSON_SET_INT("port", host->sock.port));
    sbuf_vadd(str, JSON_SET_INT("ssl", host->options & MONIT_OPT_SSL));
    
    if (host->http != NULL) {
	sbuf_vadd(str, JSON_SET_STR("http_method", host->http->method));
	sbuf_vadd(str, JSON_SET_STR("http_path", host->http->path));
	sbuf_vadd(str, JSON_SET_STR("http_version", host->http->version));
	sbuf_vadd(str, JSON_SET_STR("http_user_agent", host->http->user_agent));
	
	if (host->http->auth_type != NULL) {
	    sbuf_vadd(str, JSON_SET_STR("http_auth_type",
					host->http->auth_type));
	}
	if (host->http->auth_value != NULL) {
	    sbuf_vadd(str, JSON_SET_STR("http_auth_value",
					host->http->auth_value));
	}
    }
}

static void
cmd_build_err_msg(struct cmd *cmd)
{
    if (cmd->host->uuid[0] != 0) {
	sbuf_vadd(&cmd->reply, JSON_SET_STR("uuid", cmd->host->uuid));
    }
    if (cmd->type_init) {
	sbuf_vadd(&cmd->reply, JSON_SET_INT("command", cmd->type));
    }
    sbuf_vadd(&cmd->reply, JSON_SET_STR("error", cmd->error));
    sbuf_vadd(&cmd->reply, JSON_SET_INT("status", -1));
}

void
cmd_free_data(struct cmd *cmd)
{
    xfree(cmd->error);
    sbuf_free(&cmd->reply);
    host_free(cmd->host);
    cJSON_Delete(cmd->monitor);
}
