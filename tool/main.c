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

#include <getopt.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/mem.h"
#include "../lib/str.h"
#include "../lib/attr.h"
#include "../lib/sbuf.h"
#include "../lib/nm_common.h"
#include "../lib/json_utils.h"

#include "ctl.h"

#define VERSION "0.1.0"

enum prog_options {
    ARG_SSL,
    ARG_RELOAD_HOSTS,
    ARG_MONIT_SUSPEND,
    ARG_MONIT_RESUME,
    ARG_HUMAN_OUTPUT,
    ARG_HTTP_METHOD,
    ARG_HTTP_VERSION,
    ARG_HTTP_PATH,
    ARG_HTTP_USER_AGENNT,
    ARG_HTTP_AUTH_TYPE,
    ARG_HTTP_AUTH_VALUE,
};

static int run(struct control *x);
static int host_add(struct control *x, struct sbuf *str);
static int host_del(struct control *x, struct sbuf *str);
static int host_list(struct control *x, struct sbuf *str);
static int host_reload(struct control *x, struct sbuf *str);
static int host_monit_suspend(struct control *x, struct sbuf *str);
static int host_monit_resume(struct control *x, struct sbuf *str);
static int send_cmd(struct control *x, struct sbuf *str);
static int cmd_output(struct control *x, const char *reply);
static int parse_program_options(int argc, char **argv, struct control *x);
static int chk_config(struct control *x, int ipv);
static void usage(void);
static void version(void);

const char *progname;

int
main(int argc, char **argv)
{
    struct control x;

    progname = argv[0];
    memset(&x, 0, sizeof(x));
    log_init_default_output();
    x.protocol = -1;
    
    if (parse_program_options(argc, argv, &x) < 0) {
	control_exit(EXIT_FAILURE, &x);
    }
    if (run(&x) < 0) {
	control_exit(EXIT_FAILURE, &x);
    }
    
    control_free(&x);
    return EXIT_SUCCESS;
}

static int
run(struct control *x)
{
    int ret;
    struct sbuf str = SBUF_INIT; 

    switch (x->cmd) {
    case CMD_ADD:
	ret = host_add(x, &str);
	break;
    case CMD_DEL:
	ret = host_del(x, &str);
	break;
    case CMD_LIST:
	ret = host_list(x, &str);
	break;
    case CMD_RELOAD_HOSTS_FILE:
	ret = host_reload(x, &str);
	break;
    case CMD_MONIT_SUSPEND:
	ret = host_monit_suspend(x, &str);
	break;
    case CMD_MONIT_RESUME:
	ret = host_monit_resume(x, &str);
	break;
    default:
	fatal("Unknow command `%d'.\n", x->cmd);
	return -1;
    }

    sbuf_free(&str);
    return ret;
}

static int
host_add(struct control *x, struct sbuf *str)
{
    if (x->hostname[0] == 0 && x->ip[0] == 0) {
	err("Add host error: hostname and IP not set.\n");
	return -1;
    }
    if (x->monit <= MONIT_ERR || x->monit >= MONIT_ERR_MAX) {
	err("Add host fail, monitoring type not set.\n");
	return -1;
    }
    if (x->timeout < 1) {
	err("Add host fail, timeout not set.\n");
	return -1;
    }
    if (x->frequency < 1) {
	err("Add host fail, frequency not set.\n");
	return -1;
    }

    sbuf_add(str, JSON_OPEN);

    sbuf_vadd(str, JSON_SET_INT("command", CMD_ADD));
    sbuf_vadd(str, JSON_SET_INT("monitoring_type", x->monit));
    sbuf_vadd(str, JSON_SET_INT("timeout", x->timeout));
    sbuf_vadd(str, JSON_SET_INT("frequency", x->frequency));

    if (x->protocol != -1) {
	sbuf_vadd(str, JSON_SET_INT("protocol", x->protocol));	
    }
    if (x->port > 0) {
	sbuf_vadd(str, JSON_SET_INT("port", x->port));
    }
    if (x->hostname[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("hostname", x->hostname));
    }
    if (x->ip[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("ip", x->ip));
    }
    if (x->ip_version != 0) {
	sbuf_vadd(str, JSON_SET_INT("ip_version", x->ip_version));
    }
    if (x->uuid[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("uuid", x->uuid));
    }
    if (x->options != 0) {
	sbuf_vadd(str, JSON_SET_INT("options", x->options));
    }
    

    if (x->http_method[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("http_method", x->http_method));
    }
    if (x->http_version[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("http_version", x->http_version));
    }
    if (x->http_path[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("http_path", x->http_path));
    }
    if (x->http_auth_type != NULL) {
	sbuf_vadd(str, JSON_SET_STR("http_auth_type", x->http_auth_type));
    }
    if (x->http_auth_value != NULL) {
	sbuf_vadd(str, JSON_SET_STR("http_auth_value", x->http_auth_value));
    }
    if (x->http_user_agent[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("http_user_agent", x->http_user_agent));
    }
    
    return send_cmd(x, str);
}

static int
host_del(struct control *x, struct sbuf *str)
{
    if (x->uuid[0] == 0) {
	err("UUID field missing.\n");
	return -1;
    }
    sbuf_add(str, JSON_OPEN);
    sbuf_vadd(str, JSON_SET_INT("command", CMD_DEL));
    sbuf_vadd(str, JSON_SET_STR("uuid", x->uuid));
    return send_cmd(x, str);
}

static int
host_list(struct control *x, struct sbuf *str)
{
    sbuf_add(str, JSON_OPEN);
    sbuf_vadd(str, JSON_SET_INT("command", CMD_LIST));
    return send_cmd(x, str);
}

static int
host_reload(struct control *x, struct sbuf *str)
{
    sbuf_add(str, JSON_OPEN);
    sbuf_vadd(str, JSON_SET_INT("command", CMD_RELOAD_HOSTS_FILE));
    if (x->path[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("path", x->path));
    }
    return send_cmd(x, str);
}

static int
host_monit_suspend(struct control *x, struct sbuf *str)
{
    sbuf_add(str, JSON_OPEN);
    sbuf_vadd(str, JSON_SET_INT("command", CMD_MONIT_SUSPEND));
    if (x->timeout > 0) {
	sbuf_vadd(str, JSON_SET_INT("timeout", x->timeout));
    }
    if (x->uuid[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("uuid", x->uuid));
    }
    return send_cmd(x, str);
}

static int
host_monit_resume(struct control *x, struct sbuf *str)
{
    sbuf_add(str, JSON_OPEN);
    sbuf_vadd(str, JSON_SET_INT("command", CMD_MONIT_RESUME));
    if (x->uuid[0] != 0) {
	sbuf_vadd(str, JSON_SET_STR("uuid", x->uuid));
    }
    return send_cmd(x, str);
}

static int
send_cmd(struct control *x, struct sbuf *str)
{
    ATTR_AUTOFREE char *reply = NULL;

    json_close(str, JSON_CLOSE);
    x->fd = socku_client_create(x->sockpath);
    if (x->fd < 0) {
	return -1;
    }

#ifndef NDEBUG
    cJSON *monitor = NULL;
    const char *errbuf = NULL;

    monitor = cJSON_Parse(str->buf);
    if (monitor == NULL) {
	errbuf = cJSON_GetErrorPtr();
	err("Json: %s\n", (errbuf != NULL && *errbuf != 0) ? errbuf : "Unknow");
	cJSON_Delete(monitor);
	return -1;
    }
    cJSON_Delete(monitor);
#endif /* !NDEBUG */
    
    if (sock_write_fd(x->fd, str->buf, sbuf_len(str)) < 0) {
	return -1;
    }
    reply = sock_read_alloc_timeout(x->fd, 5);
    if (reply == NULL) {
	return -1;
    }

    printf("%s\n", reply);
    return cmd_output(x, reply);
}

static int
cmd_output(struct control *x, const char *reply)
{
    /* Todo */
    return 0;
}

static int
parse_program_options(int argc, char **argv, struct control *x)
{
    int ip_version;
    int current_arg;
    static struct option const opt_index[] = {
	{"help",       no_argument,       NULL, 'h'},
	{"version",    no_argument,       NULL, 'v'},
	{"sock-path",  required_argument, NULL, 's'},
	{"path",       required_argument, NULL, 'p'},

	/* command */
	{"add",           no_argument,       NULL, 'a'},
	{"remove",        no_argument,       NULL, 'r'},
	{"list",          no_argument,       NULL, 'l'},
	{"suspend",       required_argument, NULL, ARG_MONIT_SUSPEND},
	{"resume",        no_argument,       NULL, ARG_MONIT_RESUME},
	{"reload-hosts",  no_argument,       NULL, ARG_RELOAD_HOSTS},

	/* command arguments */
	{"hostname",   required_argument, NULL, 'H'},
	{"ip",         required_argument, NULL, 'I'},
	{"monit",      required_argument, NULL, 'M'},
	{"port",       required_argument, NULL, 'P'},
	{"ip-version", required_argument, NULL, 'V'},
	{"timeout",    required_argument, NULL, 'T'},
	{"frequency",  required_argument, NULL, 'F'},
	{"uuid",       required_argument, NULL, 'U'},
	{"ssl",        no_argument,       NULL, ARG_SSL},
	/* http */
	{"http-method",      required_argument, NULL, ARG_HTTP_METHOD},
	{"http-version",     required_argument, NULL, ARG_HTTP_VERSION},
	{"http-path",        required_argument, NULL, ARG_HTTP_PATH},
	{"http-user-agent",  required_argument, NULL, ARG_HTTP_USER_AGENNT},
	{"http-auth-type",   required_argument, NULL, ARG_HTTP_AUTH_TYPE},
	{"http-auth-value",  required_argument, NULL, ARG_HTTP_AUTH_VALUE},

	/* output */
	{"no-json",    no_argument,       NULL, ARG_HUMAN_OUTPUT},
	{NULL,         0,                 NULL, 0},
    };

    ip_version = 0;
    
    do {
#define OPT_LIST "hvs:p:arlH:I:M:P:V:T:F:U:"
        current_arg = getopt_long(argc, argv, OPT_LIST, opt_index, NULL);
        switch(current_arg) {
        case 'h':
            usage();
            break;
        case 'v':
            version();
            break;
        case 's':
	    xfree(x->sockpath);
	    x->sockpath = xstrdup(optarg);
            break;
	case 'p':
	    strncpy(x->path, optarg, (PATH_MAX-1));
            break;

	/* Command */
	case 'a':
	    x->cmd = CMD_ADD;
	    break;
	case 'r':
	    x->cmd = CMD_DEL;
	    break;
	case 'l':
	    x->cmd = CMD_LIST;
	    break;
	case ARG_RELOAD_HOSTS:
	    x->cmd = CMD_RELOAD_HOSTS_FILE;
	    break;
	case ARG_MONIT_SUSPEND:
	    x->cmd = CMD_MONIT_SUSPEND;
	    if (xstrtol(optarg, &x->timeout, 10) < 0) {
		fatal("Suspend invalid time.\n");
	    }
	    break;
	case ARG_MONIT_RESUME:
	    x->cmd = CMD_MONIT_RESUME;
	    break;

	/* Command arguments */
	case 'H':
	    if (set_str_value(x->hostname,
			      "hostname",
			      HOSTNAME_LEN,  optarg) < 0) {
		return -1;
	    }
	    break;
	case 'I':
	    if (set_ip(x->ip, optarg, &ip_version) < 0) {
		return -1;
	    }
	    break;
	case 'M':
	    if (set_monit_type(&x->monit, optarg) < 0) {
		return -1;
	    }
	    break;
	case 'P':
	    if (set_port(&x->port, optarg) < 0) {
		return -1;
	    }
	    break;
	case 'V':
	    if (set_ip_version(&x->ip_version, optarg) < 0) {
		return -1;
	    }
	    break;
	case 'T':
	    if (set_timeout(&x->timeout, optarg) < 0) {
		return -1;
	    }
	    break;
	case 'F':
	    if (set_frequency(&x->frequency, optarg) < 0) {
		return -1;
	    }
	    break;
	case 'U':
	    if (set_str_value(x->uuid,
			      "UUID",
			      UUID_SIZE,  optarg) < 0) {
		return -1;
	    }
	    break;
	case ARG_SSL:
	    x->options |= MONIT_OPT_SSL;
	    break;
	case ARG_HTTP_METHOD:
	    if (set_str_value(x->http_method,
			      "HTTP method",
			      HTTP_METHOD_SIZE,  optarg) < 0) {
		return -1;
	    }
	    break;
	case ARG_HTTP_VERSION:
	    if (set_str_value(x->http_version,
			      "HTTP version",
			      HTTP_VERSION_SIZE,  optarg) < 0) {
		return -1;
	    }
	    break;
	case ARG_HTTP_PATH:
	    if (set_str_value(x->http_path,
			      "HTTP path",
			      HTTP_PATH_SIZE,  optarg) < 0) {
		return -1;
	    }
	    break;
	case ARG_HTTP_USER_AGENNT:
	    if (set_str_value(x->http_user_agent,
			       "HTTP user agent",
			      HTTP_USER_AGENT_SIZE,  optarg) < 0) {
		return -1;
	    }
	    break;
	case ARG_HTTP_AUTH_TYPE:
	    x->http_auth_type = xstrdup(optarg);
	    break;
	case ARG_HTTP_AUTH_VALUE:
	    x->http_auth_value = xstrdup(optarg);
	    break;
	default: break;
        }
    } while (current_arg != -1);

    if (chk_config(x, ip_version) < 0) {
	return -1;
    }

    return 0;
}

static int
chk_config(struct control *x, int ipv)
{
    char *error = NULL;
    
    if (ipv != 0 && x->ip_version != 0 &&  ipv != x->ip_version) {
	err("Conflict IP version.\n");
	return -1;
    }
    
    if (x->monit == MONIT_PORT) {
	if (x->port == 0) {
	    err("Missing port number\n.");
	    return -1;
	}
    }

    if (nm_check_http_auth(x->http_auth_type,
			   x->http_auth_value,
			   &error) < 0) {
	err("%s\n", error);
	return -1;
    }
	
    
    if (x->sockpath == NULL) {
	x->sockpath = xstrdup(SOCKU_CTL_DEFAULT_PATH);
    }
    return 0;
}

static void ATTR_NORETURN
usage(void)
{
    printf("%s usage: %s cmd [OPTIONS...]\n"
	   "Arguments:\n"
	   "  -h, --help      : Show program usage and exit.\n"
	   "  -v, --version   : Show program version and exit.\n"
	   "  -s, --sock-path : Socket unix path to dial with the program.\n"
	   "  -p, --path      : file path (example reload).\n"
	   "\n"
	   "Commands:\n"
	   "  -a, --add    : Add new hosts.\n"
	   "  -r, --remove : Remove one host by uuid.\n"
	   "  -l, --list   : List all hosts.\n"
	   "\n"
	   "Commands arguments:\n"
	   "  -H, --hostname   : Set hostname.\n"
	   "  -I, --ip         : Set host IP.\n"
	   "  -M, --monit      : Set monitoring type.\n"
	   "  -P, --port       : If monitoring type is port set port value.\n"
	   "  -V, --ip-version : Set IP version.\n"
	   "  -T, --timeout    : Set timeout (min:%d max:%d.\n"
	   "  -F, --frequency  : Set host monitoring frequency (min:%d max:%d).\n"
	   "  -U, --uuid       : Set host UUID.\n"
	   "      --ssl        : Use SSL to monitoring type port && HTTP.\n"
	   "\n"
	   "HTTP options:\n"
	   "      --http-method        : Set http method (default: GET).\n"
	   "      --http-version       : Set HTTP protocol version (Default HTTP 1.1).\n"
	   "      --http-path          : Set HTTP path (example: /index.html).\n"
	   "      --http-user-agent    : Set HTTP user agent.\n"
	   "      --http-auth-type     : Set HTTP authentification type (example: Basic or Bearer)\n."
	   "      --http-auth-value    : Set HTTP authentification value (token or other).\n",
	   progname, progname, NM_TIMEOUT_MIN, NM_TIMEOUT_MAX,
	   NM_FREQ_MIN, NM_FREQ_MAX);
    exit(EXIT_SUCCESS);
}

static void ATTR_NORETURN
version(void)
{
    printf("%s %s\n", progname, VERSION);
    exit(EXIT_SUCCESS);
}
