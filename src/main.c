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
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>

#include "nm.h"
#include "db.h"
#include "version.h"
#include "nm_prepare.h"

#include "../lib/attr.h"
#include "../lib/log.h"
#include "../lib/str.h"
#include "../lib/mem.h"
#include "../lib/sock.h"
#include "../lib/json_utils.h"

#define CONF_FILE_LOCAL_DIR     "./config/nm-conf.json"
#define CONF_FILE_ETC_DIR       "/etc/nm/nm-conf.json"

static void parse_config_file(void);
static void set_config_var(cJSON *monitor,
			   const char *name,
			   char *var, size_t size,
			   struct json_var *jvar);
static void parse_program_options(int argc, char **argv);
static void daemonize(void);
static int write_pid_file(void);
static void usage(void);
static void version(void);

enum program_arguments {
    ARG_NO_HOST_FILE,
    ARG_NO_DB,
    ARG_CONFIG_FILE,
    ARG_HTTP_STATS,
    ARG_HTTP_PORT,
    ARG_HTTP_BIND_ADDR,
    ARG_HTTP_BEARER,
    ARG_HTTP_IPV4_ONLY,
    ARG_HTTP_IPV6_ONLY,
    ARG_HTTP_DISABLE_API_REST,
};

const char *progname;
#include "../lib/http.h"
int
main(int argc, char **argv)
{
    int ret;

    nm_init(argv[0]);
    parse_program_options(argc, argv);
    parse_config_file();
    daemonize();
    nm_prepare();
    ret = nm_main_loop();
    nm_free();
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void
parse_config_file(void)
{
    int error;
    const char *path = NULL;
    cJSON *m = NULL;
    char buffer[1024];
    struct json_var jvar = {
	.type = cJSON_String,
	.str_size = sizeof(buffer),
	.name = NULL,
	.sval = buffer,
	.err = {0},
    };

    if (nm->conf_file[0] == 0) {
	path = files_access(CONF_FILE_ETC_DIR, CONF_FILE_LOCAL_DIR, R_OK);
	if (path == NULL) {
	    warn("config file path is empty.\n");
	    return;
	}
	strncpy(nm->conf_file, path, (PATH_SIZE-1));
    }

    m = json_parse_file(nm->conf_file, &error);
    if (m == NULL) {
	if (error == JSON_RDFILE_ERROR) {
	    
	}
	return;
    }

    jvar.name = "daemon";
    if (json_get_var(m, &jvar) == 0) {
	if (STREQ(jvar.sval, YES)) {
	    nm->options |= OPT_RUN_BG;
	}
    }

    /* Database type */
    jvar.name = "db_type";
    if (json_get_var(m, &jvar) == 0) {
	if (STREQ(jvar.sval, "mongo")) {
	    nm->db_type = DB_TYPE_MONGO;
	} else if (STREQ(jvar.sval, "file")) {
	    nm->db_type = DB_TYPE_FILE;
	}
    }

    /* Bearer value (string pointer)
     * Only parsed if not set by argument
     */
    if (nm->api->bearer == NULL) {
	jvar.name = "http_bearer";
	jvar.str_size = 0;
	jvar.svalptr = &nm->api->bearer;
	(void) json_get_var(m, &jvar);
    }

    /* todo add http port option */
    /* todo add http bind option */
    jvar.svalptr = NULL;
    jvar.sval = buffer;
    jvar.str_size = sizeof(buffer);
    set_config_var(m, "script_path", nm->script_path, PATH_SIZE, &jvar);
    set_config_var(m, "pid_file", nm->pid_file, PATH_SIZE, &jvar);
    set_config_var(m, "script", nm->script_path, PATH_SIZE, &jvar);
    set_config_var(m, "hosts_path", nm->hosts_path, PATH_SIZE, &jvar);
    set_config_var(m, "socket_private", nm->priv_sock_path, PATH_SIZE, &jvar);
    set_config_var(m, "socket_control", nm->ctl_sock_path, PATH_SIZE, &jvar);
    
    cJSON_Delete(m);
}

static void
set_config_var(cJSON *monitor,
		  const char *name,
		  char *var, size_t size,
		  struct json_var *jvar)
{
    jvar->name = name;
    if (json_get_var(monitor, jvar) == 0) {
	strncpy(var, jvar->sval, (size-1));
    }
}

static void
parse_program_options(int argc, char **argv)
{
    int arg;
    struct option const opt_index[] = {
	{"help",             no_argument,       NULL, 'h'},
	{"version",          no_argument,       NULL, 'v'},
	{"daemon",           no_argument,       NULL, 'd'},
	{"conf",             required_argument, NULL, ARG_CONFIG_FILE},
	{"pid-file",         required_argument, NULL, 'P'},
	{"no-db",            no_argument,       NULL, ARG_NO_DB},
	{"ctl-sock-path",    required_argument, NULL, 'c'},
	{"priv-sock-path",   required_argument, NULL, 'p'},
	{"http-stats",	     no_argument,	NULL, ARG_HTTP_STATS},
	{"http-port",        required_argument, NULL, ARG_HTTP_PORT},
	{"http-bind-addr",   required_argument, NULL, ARG_HTTP_BIND_ADDR},
	{"http-bearer",	     required_argument, NULL, ARG_HTTP_BEARER},
	{"http-ipv6-only",   no_argument,       NULL, ARG_HTTP_IPV6_ONLY},
	{"http-ipv4-only",   no_argument,       NULL, ARG_HTTP_IPV4_ONLY},
	{"disable-api-rest", no_argument,       NULL, ARG_HTTP_DISABLE_API_REST},
	{"db_uri",           required_argument, NULL, 'U'},
	{"db_file",          required_argument, NULL, 'F'},
	{"script",           required_argument, NULL, 's'},
	{"log-file-err",     required_argument, NULL, 'E'},
	{"log-file-info",    required_argument, NULL, 'I'},
	{NULL,             0,                 NULL, 0},
    };
    
    do {
#define OPT_LIST "hvdP:c:p:U:F:s:E:I:"
	arg = getopt_long(argc, argv, OPT_LIST, opt_index, NULL);
	switch(arg) {
	case 'h':
	    usage();
	    break;
	case 'v':
	    version();
	    break;
	case 'd':
	    nm->options |= OPT_RUN_BG;
	    break;
	case ARG_CONFIG_FILE:
	    strncpy(nm->conf_file, optarg, (PATH_SIZE-1));
	    break;
	    
	case 'P':
	    strncpy(nm->pid_file, optarg, (PATH_SIZE-1));
	    break;
	case ARG_NO_DB:
	    nm->options |= OPT_NO_DB;
	    break;
	    
	case 'c':
	    xstrredup(&nm->ctl_sock_path, optarg);
	    break;
	case 'p':
	    xstrredup(&nm->priv_sock_path, optarg);
	    break;
	    
	/* HTTP arguments */
	case ARG_HTTP_STATS:
	    nm->api->option |= API_OPT_STATS;
	    break;
	case ARG_HTTP_PORT:
	    if (xstrtol(optarg, &nm->api->srv_port, 10) < 0) {
		fatal("Invalid HTTP port\n");
	    }
	    break;
	case ARG_HTTP_BIND_ADDR:
	    xstrredup(&nm->api->srv_bind_addr, optarg);
	    break;
	case ARG_HTTP_BEARER:
	    xstrredup(&nm->api->bearer, optarg);
	    break;
	case ARG_HTTP_IPV4_ONLY:
	    nm->api->srv_ip_version = SOCK_OPT_IPv4_ONLY;
	    break;
	case ARG_HTTP_IPV6_ONLY:
	    nm->api->srv_ip_version = SOCK_OPT_IPv6_ONLY;
	    break;
	case ARG_HTTP_DISABLE_API_REST:
	    nm->options |= OPT_DISABLE_API_REST;
	    break;
	    
	case 'U':
	    nm->db_type = DB_TYPE_MONGO;
	    strncpy(nm->hosts_path, optarg, (PATH_SIZE-1));
	    break;
	case 'F':
	    nm->db_type = DB_TYPE_FILE;
	    strncpy(nm->hosts_path, optarg, (PATH_SIZE-1));
	    break;
	    
	case's':
	    strncpy(nm->script_path, optarg, (PATH_SIZE-1));
	    break;
	case 'E':
	    if (log_set_output(LOG_OUTPUT_ERR, optarg) < 0) {
		fatal("Open log file <error> fail.\n");
	    }
	    break;
	case 'I':
	    if (log_set_output(LOG_OUTPUT_INFO, optarg) < 0) {
		fatal("Open log file <info> fail.\n");
	    }
	    break;
	default: ; break;
	}
    } while (arg != -1);
}

void
daemonize(void)
{
    pid_t pid;

    if ((nm->options & OPT_RUN_BG) == 0) {
	nm->pid_file[0] = 0;
	return;
    }
    
    pid = fork();
    if (pid == -1) {
	fatal("daemonize: fork: %s\n", STRERRNO);
    } else if (pid > 0) {
	info("Daemonize pid %d\n", pid);
	exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
	fatal("setsid: %s\n", STRERRNO);
    }
    (void) umask(0);
    (void) close(STDIN_FILENO);
    (void) close(STDOUT_FILENO);
    (void) close(STDERR_FILENO);
    (void) write_pid_file();
}

static int
write_pid_file(void)
{
    FILE *f = NULL;

    if (nm->pid_file[0] == 0) {
	return 0;
    }
    f = fopen(nm->pid_file, "w+");
    if (f == NULL) {
	err("Fail to open file <%s>: %s\n", nm->pid_file, STRERRNO);
	return -1;
    }
    fprintf(f, "%d", getpid());
    fclose(f);
    return 0;
}

static void ATTR_NORETURN
usage(void)
{
    printf("%s usage: %s [OPTIONS]\n"
           "Options:\n"
           "  -h, --help            : Show usage and exit.\n"
           "  -v, --version         : Show version and exit.\n"
           "  -d, --daemon          : Run the program in background.\n"
	   "      --conf            : Set the configuration path file.\n"
           "  -P, --pid-file        : Set the full path to write the daemon PID "
	   "(defailt: /run/nm.pid).\n"
	   "      --no-db           : Cannot use a database.\n"
	   "  -U, --db-uri          : Use a mongodb and set the uri.\n"
	   "  -F, --db-file         : Use file like a DB and set the path (JSON format).\n"
	   "  -s, --script          : Set the script to run when a host have changed state.\n"
           "  -c, --ctl-sock-path   : Set the full path to control socket unix.\n"
           "  -p, --priv-sock-path  : Set the full path to private socket unix.\n"
	   "      --http-stats      : Enable API REST stats.\n"
	   "      --http-port       : Set HTTP server port to enbale API REST option\n"
	   "      --http-bind-addr  : Set binding address (default any).\n"
	   "      --http-bearer     : Set the Bearer token to secure access "
	   "      --http-ipv4-only  : If bind address not set, HTTP server use"
	   " only IPv4 (by default use v4 and v6).\n"
	   "      --http-ipv6-only  : If bind address not set, HTTP server use"
	   " only IPv6 (by default use v4 and v6).\n"
	   "      --disable-api-rest: Disable API REST server.\n"
	   "at the API REST.\n"
	   "  -E, --log-file-err    : Log error in specifics file (default stderr).\n"
	   "  -I, --log-file-info   : Log information in specifics file (default stdout).\n",
           progname, progname);
    exit(EXIT_SUCCESS);
}

static void ATTR_NORETURN
version(void)
{
    printf("%s version %s\n", progname, VERSION);
    exit(EXIT_SUCCESS);
}
