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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/select.h>

#include "nm.h"
#include "command.h"
#include "icmp.h"
#include "misc.h"
#include "host.h"
#include "db.h"
#include "nm_prepare.h"

#include "../lib/log.h"
#include "../lib/mem.h"
#include "../lib/str.h"
#include "../lib/progname.h"
#include "../lib/list.h"
#include "../lib/sock.h"
#include "../lib/file_utils.h"
#include "../lib/nm_common.h"
#include "../lib/json_utils.h"

#define NM_PROCESS_WAIT_NONBLOCK WNOHANG

#define NM_PID_FILE_DEFAULT     "/var/run/nm.pid"
#define SOCKU_PRIV_DEFAULT_PATH "/tmp/nm_priv.sock"

struct nm_script_arg {
    struct host *host;
    struct nm_priv_msg msg;
    const char *str_state;
    char str_time[24];
};

static int nm_process_kill_all_and_free(struct nm_process *root);
static void nm_client(void);
static void nm_process_script(void);
static void nm_process_suspend(void);
static int nm_process_suspend_check_duration(struct nm_process *process,
					     struct nm_process_suspend **suspend,
					     unsigned int options);
static int nm_accept_client(int fd, int sock_type);
static void nm_socku_cmd(int cli_fd);
static void nm_update_host_state(int fdcli);
static int nm_script_exec(void *arg);
static void nm_terminate_threads(void);
static int nm_ssl_init(struct sock *sock);
static void nm_eval_monitoring_res(struct host *host, int *last_state,
				   int *wait_time,
				   unsigned long timestamp);
static int nm_monit_ping(struct host *host);
static int nm_monit_port(struct host *host);
static int nm_monit_http(struct host *host);

struct nm *nm = NULL;
extern char **environ;

void
nm_init(const char *pname)
{
    nm = xcalloc(sizeof(struct nm));
    
    set_program_name(pname);
    log_init_default_output();

    nm->api = api_rest_new();
    nm->ctl_sock_path = xstrdup(SOCKU_CTL_DEFAULT_PATH);
    nm->priv_sock_path = xstrdup(SOCKU_PRIV_DEFAULT_PATH);
    if (MUTEX_INIT(&nm->run_mutex) < 0) {
	fatal("mutex_init: %s\n", STRERRNO);
    }
}

void
nm_free(void)
{
    nm_terminate_threads();
    nm_process_kill_all_and_free(nm->script);
    nm_process_kill_all_and_free(nm->monitoring);
    MUTEX_DESTROY(&nm->run_mutex);
    
    socku_close(nm->ctl_fd, nm->ctl_sock_path);
    socku_close(nm->priv_fd, nm->priv_sock_path);
    
    if (nm->pid_file[0] != 0) {
	(void) unlink(nm->pid_file);
    }

    api_rest_free(nm->api);
    db_free(NULL);
    log_free();
    xfree(nm);
}

void
nm_sig_interrupt_handler(int signum ATTR_UNUSED)
{
    DEBUG("SIGINT catched, set run to false.\n");
    MUTEX_LOCK(&nm->run_mutex);
    nm->run = 0;
    MUTEX_UNLOCK(&nm->run_mutex);
}

ATTR_NORETURN void *
nm_ctl_thread(void *arg ATTR_UNUSED)
{
    DEBUG("Main loop started...\n");
    
    while (1) {
	nm_client();
	nm_process_script();
	nm_process_suspend();
    }
    pthread_exit(NULL);
}

int
nm_main_loop(void)
{
    int cont;
    
    nm->run = 1;
    do {
	MUTEX_LOCK(&nm->run_mutex);
	cont = nm->run;
	MUTEX_UNLOCK(&nm->run_mutex);
	sleep(1);
    } while (cont);
    return 0;
}

int
nm_process_run_all(struct nm_process *process, int (*func_ptr)(void*))
{
    struct nm_process *ptr = NULL;
    
    LIST_FOREACH(process, ptr) {
	if (nm_process_run(ptr, func_ptr) < 0) {
	    return -1;
	}
    }
    return 0;
}

int
nm_process_run(struct nm_process *process, int (*func_ptr)(void*))
{
    int ret;
    
    process->pid = fork();
    if (process->pid == -1) {
	err("fork: %s\n", STRERRNO);
	process->state = NM_PROCESS_KILL;
	return -1;
    } else if (process->pid == 0) {
	ret = func_ptr(process->data);
	exit(ret);
    }
    process->state = NM_PROCESS_RUN;
    return 0;
}

static int
nm_process_kill_all_and_free(struct nm_process *root)
{
    struct nm_process *process = NULL;
    struct nm_process *nextptr = NULL;

    process = root;
    while (process) {
	nextptr = process->next;
	if (process->state != NM_PROCESS_KILL) {
	    if (nm_process_kill_and_wait(process) < 0) {
		return -1;
	    }
	}
	DLIST_UNLINK(root, process);
	nm_process_free(process);
	process = nextptr;
    }
    return 0;
}

int
nm_process_kill_all(struct nm_process *process)
{
    int ret;

    ret = 0;
    while (process != NULL) {
	if (process->data != NULL) {
	    process->free_data(process->data);
	}
	if (process->state != NM_PROCESS_KILL) {
	    if (nm_process_kill_and_wait(process) < 0) {
		ret = -1;
	    }
	}
	process = process->next;
    }
    return ret;
}

int
nm_process_kill_and_wait(struct nm_process *process)
{
    if (process->pid == 0 || process->state == NM_PROCESS_KILL) {
	return 0;
    }
    if (nm_process_kill(process->pid) < 0) {
	return -1;
    }
    if (nm_process_wait(process, 0) < 0) {
	return -1;
    }
    return 0;
}

int
nm_process_send_sig(pid_t pid, int signum)
{
    if (pid == 0) {
	return 0;
    }
    if (kill(pid, signum) < 0) {
	err("kill <%d> pid %d: %s\n", pid, signum, STRERRNO);
	return -1;
    }
    DEBUG("Send signal <%d> to pocess %d.\n", signum, pid);
    return 0;
}

int
nm_process_kill(pid_t pid)
{
    return nm_process_send_sig(pid, SIGKILL);
}

int
nm_process_wait(struct nm_process *process, int options)
{
    int ret;
    int status;
    
    ret = waitpid(process->pid, &status, options);
    if (ret < 0) {
	err("wait pid %d: %s\n", process->pid, STRERRNO);
	if (ret == ECHILD) {
	    /* To remove it from the process list*/
	    ret = process->pid;
	    process->pid = 0;
	    process->state = NM_PROCESS_KILL;
	}
	return ret;
    }
    if (ret == 0) {
	return 0;
    }
    if (WIFEXITED(status)) {
	info("PID: %d terminated with code: %d\n", ret, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
	info("PID: %d terminated by signal number %d\n", ret, WTERMSIG(status));
    } else {
	info("PID: %d terminated.\n", ret);
    }
    
    process->pid = 0;
    process->state = NM_PROCESS_KILL;
    return ret;
}

void
nm_process_suspend_init(struct nm_process_suspend **suspend, int duration)
{
    if (*suspend == NULL) {
	*suspend = xmalloc(sizeof(struct nm_process_suspend));
    }
    memset(*suspend, 0, sizeof(struct nm_process_suspend));
    (*suspend)->start = (unsigned long) time(NULL);
    if (duration > 0) {
	(*suspend)->duration = (unsigned long) duration;
    }
}

void
nm_process_suspend_free(struct nm_process_suspend **suspend)
{
    if (*suspend == NULL) {
	return;
    }
    xfree(*suspend);
    *suspend = NULL;
}

int
nm_process_change_state(int new_state,
			unsigned int options,
			struct nm_process *process)
{
    int signum;
    struct nm_process *ptr = NULL;

    switch (new_state) {
    case NM_PROCESS_SUSPEND:
	signum = SIGSTOP;
	break;
    case NM_PROCESS_RESUME:
	signum = SIGCONT;
	break;
    case NM_PROCESS_KILL:
	signum = SIGKILL;
	break;
    default:
	return 0;
    }
    
    if ((options & NM_PROCESS_OPT_ONE)) {
	if (nm_process_send_sig(process->pid, signum) < 0) {
	    return -1;
	}
    } else {
	LIST_FOREACH(process, ptr) {
	    if (nm_process_send_sig(ptr->pid, signum) < 0) {
		return -1;
	    }
	}
    }
    return 0;
}

void
nm_process_free(struct nm_process *process)
{
    if (process->free_data != NULL) {
	process->free_data(process->data);
	process->free_data = NULL;
    }
    xfree(process->suspend);
    xfree(process);
}

static void
nm_client(void)
{
    int ret;
    int fd;
    int cli_fd;
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(nm->ctl_fd, &fds);
    FD_SET(nm->priv_fd, &fds);
    if (nm->api != NULL) {
	FD_SET(nm->api->srv_fd, &fds);
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    fd = nm->ctl_fd;
    if (nm->priv_fd > fd) {
	fd = nm->priv_fd;
    }
    if (nm->api != NULL) {
	if (nm->api->srv_fd > fd) {
	    fd = nm->api->srv_fd;
	}
    }

    ret = select(fd+1, &fds, NULL, NULL, &tv);
    if (ret < 1) {
	if (ret < 0) {
	    err("select: %s\n", STRERRNO);
	}
	DEBUG("select return: %d\n", ret);
	return;
    }

    cli_fd = -1;
    if (FD_ISSET(nm->ctl_fd, &fds)) {
	cli_fd = nm_accept_client(nm->ctl_fd, SOCK_TYPE_UNIX);
	if (cli_fd != -1) {
	    nm_socku_cmd(cli_fd);
	}
    } else if (FD_ISSET(nm->priv_fd, &fds)) {
	cli_fd = nm_accept_client(nm->priv_fd, SOCK_TYPE_UNIX);
	if (cli_fd != -1) {
	   nm_update_host_state(cli_fd);
	}
    } else {
	/* cli_fd not used with api rest */
	cli_fd = -1;
	if (nm->api != NULL) {
	    if (FD_ISSET(nm->api->srv_fd, &fds)) {
	        (void) api_rest_client_handler(nm->api);
	    }
	}
    }

    (void) xclose(cli_fd);
}

static int
nm_accept_client(int fd, int sock_type)
{
    int fdcli;
    socklen_t len;
    void *client;
    struct sockaddr_un ucli;
    struct sockaddr_storage scli; 

    if (sock_type == SOCK_TYPE_UNIX) {
	client = &ucli;
	len = sizeof(struct sockaddr_un);	
    } else {
	client = &scli;
	len = sizeof(struct sockaddr_storage);	
    }

    fdcli = accept(fd, (struct sockaddr *)client, &len);
    if (fdcli < 0) {
	err("accept socket type %s: %s\n",
	    (sock_type == SOCK_TYPE_UNIX) ? "unix" : "tcp",
	    STRERRNO);
	return -1;
    }
    
    return fdcli;
}

static void
nm_socku_cmd(int cli_fd)
{
    ssize_t ret;
    char buffer[CMD_SIZE];
    struct cmd cmd;

    cmd_init(&cmd);
    memset(buffer, 0, CMD_SIZE);
    ret = sock_read_fd(cli_fd, buffer, CMD_SIZE, 2);
    if (ret == SOCK_RET_TIMEOUT) {
        cmd.error = dump_err(NM_ERR_TIMEOUT);
    }
    
    if (cmd.error != NULL) {
	cmd_free_all_data(&cmd);
	return;
    }
    
    (void) cmd_handler(buffer, &cmd);
    if (sbuf_len(&cmd.reply) > 0) {
	DEBUG("Send: %s\n", cmd.reply.buf);
	(void) sock_write_fd(cli_fd, cmd.reply.buf, sbuf_len(&cmd.reply));
    }
    
    cmd_free_after_exec(&cmd);
    return;
}

static void
nm_process_script(void)
{
    pid_t pid;
    struct nm_process *script = NULL;
    struct nm_process *nextptr = NULL;

    if (nm->script_path[0] == 0 || nm->script == NULL) {
	return;
    }

    for (script = nm->script; script; script = nextptr) {
	pid = script->pid;
	nextptr = script->next;
	if (nm_process_wait(script, NM_PROCESS_WAIT_NONBLOCK) == pid) {
	    DLIST_UNLINK(nm->script, script);
	    nm_process_free(script);
	}
    }
}

static void
nm_process_suspend(void)
{
    struct nm_process *process = NULL;
    
    if (nm->suspend != NULL) {
	if (nm_process_suspend_check_duration(nm->monitoring,
					      &nm->suspend,
					      NM_PROCESS_OPT_ALL) < 0) {
	}
    } else {
	LIST_FOREACH(nm->monitoring, process) {
	    if (process->suspend == NULL || process->suspend->duration == 0) {
		continue;
	    }
	    if (nm_process_suspend_check_duration(process,
						  &process->suspend,
						  NM_PROCESS_OPT_ONE) < 0) {
	    }
	}
    }
}

static int
nm_process_suspend_check_duration(struct nm_process *process,
				  struct nm_process_suspend **suspend,
				  unsigned int options)
{
    unsigned long suspend_time;
    struct nm_process_suspend *suspendptr = NULL;

    suspendptr = *suspend;
    suspend_time = (unsigned long) time(NULL) - suspendptr->start;
    
    if (suspendptr->duration > 0 &&
	suspend_time >= suspendptr->duration) {
	if (nm_process_change_state(NM_PROCESS_RESUME, options, process) < 0) {
	    return -1;
	}
	nm_process_suspend_free(&nm->suspend);
    }
    return 0;
}

static void
nm_update_host_state(int fdcli)
{
    ssize_t ret;
    struct nm_script_arg arg;
    struct nm_process *process = NULL;
    
    ret = sock_read_fd(fdcli, &arg.msg, sizeof(arg.msg), 2);
    if (ret < 0) {
	return;
    }
    arg.host = host_get_by_uuid(arg.msg.uuid);
    if (arg.host == NULL) {
	return;
    }
    arg.host->state = arg.msg.state;

    if (nm->script_path[0] == 0) {
	return;
    }
    snprintf(arg.str_time, sizeof(arg.str_time)-1, "%lu", arg.msg.timestamp);
    arg.str_state = nm_get_state_str(arg.msg.state);

    (void) db_host_state_change(&arg.msg);

    process = xcalloc(sizeof(struct nm_process));
    process->state = NM_PROCESS_KILL;
    process->data = &arg;
    if (nm_process_run(process, &nm_script_exec) == 0) {
	DLIST_LINK(nm->script, process);
    } else {
	err("Exec script for host <%s> with state <%s> error\n",
	    arg.host->sock.straddr, arg.str_state);
	nm_process_free(process);
    }
}

static int
nm_script_exec(void *arg)
{
    struct nm_script_arg *script_arg = arg;
    
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
    char *const argv[] = {
	nm->script_path,
	script_arg->host->sock.straddr,
	script_arg->host->uuid,
	script_arg->str_time,
        script_arg->str_state,
	NULL,
    };
#pragma GCC diagnostic pop

    if (execve(nm->script_path, argv, environ) < 0) {
	return -1;
    }
    return 0;
}

static void
nm_terminate_threads(void)
{
    pthread_cancel(nm->ctl_th);
    pthread_join(nm->ctl_th, NULL);
}

int
nm_host_monitoring(void *arg)
{
    int wait_time;
    int last_state;
    unsigned long timestamp;
    struct sock *sock = NULL;
    struct host *host = NULL;

    host = arg;
    host_free_unused(host->uuid);
    last_state = host->state;
    wait_time = host->frequency;

    sock = &host->sock;
    sock->connect = &sock_connect;
    sock->read = &sock_read;
    sock->write = &sock_write;
    sock->close = &sock_close;
    
    if ((host->monit_type == MONIT_HTTP ||
	 host->monit_type == MONIT_PORT) &&
	(host->options & MONIT_OPT_SSL)) {
	if (nm_ssl_init(sock) < 0) {
	    fatal("Monitoring %s host %s aborted, SSL init error\n",
		  nm_get_monit_type_str(host->monit_type, host->options),
		  host->sock.straddr);
	}
    }

    if (host->monit_type == MONIT_HTTP) {
	/* Not use hostname because hostname is not verified.
	 * possibility to set 127.0.0.1 with host name perdu.com.
	 */
	http_make_header(host->http, host->hostname, sock->straddr);
	DEBUG("%s HTTP header:\n%s\n---End header---\n",
	      sock->straddr, host->http->header.buf);
    }
    
    while (1) {
	timestamp = (unsigned long) time(NULL);
	switch (host->monit_type) {
	case MONIT_PING:
	    host->state = nm_monit_ping(host);
	    break;
	case MONIT_PORT:
	    host->state = nm_monit_port(host);
	    break;
	case MONIT_HTTP:
	    host->state = nm_monit_http(host);
	    break;
	default:
	    sock->close(sock);
	    return -1;
	    break;
	}

	sock->close(sock);
	nm_eval_monitoring_res(host, &last_state, &wait_time, timestamp);
	sleep((unsigned int) wait_time);
    }
    return 0;
}

#ifdef HAVE_SSL
static int
nm_ssl_init(struct sock *sock)
{

    if (ssl_init(sock) < 0) {
	return -1;
    }
    sock->connect = ssl_connect;
    sock->read = ssl_read;
    sock->write = ssl_write;
    sock->close = ssl_close;
    return 0;
}
#else
static int
nm_ssl_init(struct sock *sock ATTR_UNUSED)
{
    return 0;
}
#endif /* HAVE_SSL */

static void
nm_eval_monitoring_res(struct host *host, int *last_state,
		       int *wait_time,
		       unsigned long timestamp)
{
    int fd;
    char date[DATE_SIZE];
    struct nm_priv_msg msg;
    
    if (host->state == SOCK_RET_SUCCESS) {
	host->state = HOST_STATE_UP;
    } else {
	host->state = HOST_STATE_DOWN;
    }
    
    if (host->state == *last_state) {
	return;
    }
    
    if (host->state == HOST_STATE_DOWN) {
	host->state = HOST_STATE_DOWN;
	*wait_time = 10;
    } else {
	host->state = HOST_STATE_UP;
	*wait_time = host->frequency;
    }

    info("%s - Host: %s (%s)\n\tMonitoring: %s\n\tnew state: %s\n",
	 get_date(timestamp, date), host->sock.straddr,
	 (host->hostname[0] == 0) ? "" : host->hostname,
	 nm_get_monit_type_str(host->monit_type, host->options),
	 nm_get_state_str(host->state));
    
    msg.state = host->state;
    msg.timestamp = timestamp;
    strncpy(msg.uuid, host->uuid, UUID_SIZE);
    *last_state = host->state;
    
    fd = socku_client_create(nm->priv_sock_path);
    if (fd == -1) {
	return;
    }
    (void) sock_write_fd(fd, &msg, sizeof(msg));
    (void) xclose(fd);
}

static int
nm_monit_ping(struct host *host)
{
    ssize_t ret;
    char buf[PKT_MAX_SIZE];
    time_t start_time;
    struct sock_recvfrom r;
    struct icmphdr ic;

    host->sock.fd = socket(host->sock.family,
			   host->sock.type,
			   host->sock.proto);
    if (host->sock.fd < 0) {
        err("socket: %s\n", STRERRNO);
        return SOCK_RET_ERR;
    }
    
    icmp_make_hdr(&ic, host->sock.family);
    ret = sendto(host->sock.fd, &ic,
                 sizeof(struct icmphdr), 0,
                 (struct sockaddr *)&host->sock.addr,
                 host->sock.addrlen);
    DEBUG("icmp <%s> send %ld bytes\n", host->sock.straddr, ret);
    if (ret < 0) {
        err("sendto: %s: %s\n", host->sock.straddr, STRERRNO);
        return SOCK_RET_ERR;
    }

    r.timeout = host->timeout;
    r.buf = buf;
    r.bufsize = PKT_MAX_SIZE;
    memset(&r.addr, 0, sizeof(struct sockaddr_storage));
    start_time = time(NULL);
    
    do {
	ret = sock_recvfrom(&host->sock, &r);
	if (ret < 1) {
	    return (int) ret;
	}
	if (icmp_is_echo_reply(r.buf,(size_t) ret,
			       ic.sequence,
			       host->sock.family) == 0) {
	    break;
	}
	r.timeout = (int)(time(NULL) - start_time);
	if (r.timeout == 0) {
	    r.timeout = host->timeout;
	}
	DEBUG("Next timeout = %d\n", r.timeout);
    } while (r.timeout >= host->timeout);
    
    return SOCK_RET_SUCCESS;
}

static int
nm_monit_port(struct host *host)
{
    return host->sock.connect(&host->sock, host->timeout);
}

static int
nm_monit_http(struct host *host)
{
    int ret;
    char buf[512];
    
    ret = host->sock.connect(&host->sock, host->timeout);
    if (ret != SOCK_RET_SUCCESS) {
	return ret;
    }

    if (host->sock.write(&host->sock,
			 host->http->header.buf,
			 sbuf_len(&host->http->header)) < 0) {
	return SOCK_RET_ERR;
    }
    ret = host->sock.read(&host->sock,
			  buf, sizeof(buf)-1,
			  host->timeout);
    if (ret < 1) {
	return (int) ret;
    }
    buf[ret] = 0;
    
    DEBUG("host:%s HTTP received %d bytes: \n%s---End---\n",
	  host->sock.straddr, ret, buf);

    ret = http_get_status_code(buf);
    if (ret < 200 || ret > 299) {
	DEBUG("HTTP <%s> fail status code: %d\n", host->sock.straddr, ret);
	return SOCK_RET_HTTP_ERROR;
    }
    return SOCK_RET_SUCCESS;
}

const char *
nm_get_state_str(int state)
{
    const char * buf = NULL;
    
    switch (state) {
    case HOST_STATE_DOWN:
	buf = "down";
	break;
    case HOST_STATE_UP:
	buf = "up";
	break;
    default:
	buf = "unknown";
	break;
    }

    return buf;
}

const char *
nm_get_monit_type_str(int type, int options)
{
    const char * buf = NULL;
    
    switch (type) {
    case MONIT_PING:
	buf = "ping";
	break;
    case MONIT_HTTP:
	if (options & MONIT_OPT_SSL) {
	    buf = "https";
	} else {
	    buf = "http";
	}
	break;
    case MONIT_PORT:
	if (options & MONIT_OPT_SSL) {
	    buf ="tcp_ssl_port";
	} else {
	    buf = "tcp_port";
	}
	break;
    default:
	buf = "unknown";
	break;
    }

    return buf;
}

int
nm_reload_hosts(const char *path)
{
    if (nm_process_kill_all_and_free(nm->monitoring) < 0) {
	return -1;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
    if (db_host_load(path) < 0) {
	return -1;
    }
#pragma GCC diagnostic pop

    return nm_process_run_all(nm->monitoring, &nm_host_monitoring);
}

int
nm_add_host_by_json(cJSON *json)
{
    struct cmd cmd;

    memset(&cmd, 0, sizeof(struct cmd));
    cmd.host = host_init_ptr();
    if (host_parse_json(cmd.host, json) < 0) {
	host_free(cmd.host);
	return -1;
    }

    cmd.type_init = 1;
    cmd.type = CMD_ADD;
    sbuf_init(&cmd.reply);
    if (cmd_check_host_fields(&cmd) < 0) {
	err("parse host: %s", cmd.error);
	cmd_free_all_data(&cmd);
	return -1;
    }
    
    (void) host_link(cmd.host);
    cmd_free_after_exec(&cmd);
    return 0;
}
