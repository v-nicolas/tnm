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

#include <signal.h>
#include <stdlib.h>

#include "nm.h"
#include "db.h"
#include "nm_prepare.h"
#include "http_routes.h"

#include "../lib/log.h"
#include "../lib/sock.h"

static void nm_prepare_signal(void (*sig_handler)(int));
static void nm_prepare_sockets(void);
static int nm_prepare_api_rest_routes(void);
static void nm_prepare_database(void);
static void nm_prepare_script(void);
static void nm_prepare_monitoring_process(void);
static void nm_prepare_threads(void);

void
nm_prepare(void)
{
    nm_prepare_signal(&nm_sig_interrupt_handler);
    nm_prepare_sockets();
    nm_prepare_database();
    nm_prepare_script();
    nm_prepare_monitoring_process();
    nm_prepare_threads();
}

static void
nm_prepare_signal(void (*sig_handler)(int))
{
    struct sigaction act;

    act.sa_handler = sig_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    
    if (sigaction (SIGINT, &act, NULL) < 0) {
        fatal("sigaction: %s\n", STRERRNO);
    }

    act.sa_handler = SIG_IGN;
    if (sigaction (SIGPIPE, &act, NULL) < 0) {
        fatal("sigaction: %s\n", STRERRNO);
    }
}

static void
nm_prepare_sockets(void)
{
    nm->ctl_fd = socku_server_create(nm->ctl_sock_path);
    if (nm->ctl_fd < 0) {
	fatal("Fail to create control socket server.\n");
    }
    
    nm->priv_fd = socku_server_create(nm->priv_sock_path);
    if (nm->priv_fd < 0) {
	fatal("Fail to create priv socket server.\n");
    }

    if ((nm->options & OPT_DISABLE_API_REST)) {
	api_rest_free(nm->api);
	nm->api = NULL;
    } else {
	if (api_rest_create_server(nm->api) < 0) {
	    fatal("Fail to create HTTP server.\n");
	}
	if (nm_prepare_api_rest_routes() < 0) {
	    fatal("Fail to set API rest routes.\n");
	}
    }
}

static int
nm_prepare_api_rest_routes(void)
{
    api_rest_set_route_protected(nm->api, API_REST_ENBALE_PROTECTED_ROUTE);
    if (api_rest_add_route_post(nm->api, "/",
				http_route_host_manage, NULL) < 0) {
	return -1;
    }
    if (api_rest_add_route_delete(nm->api, "/",
				  http_route_host_manage, NULL) < 0) {
	return -1;
    }
    if (api_rest_add_route_get(nm->api, "/",
			       http_route_host_manage, NULL) < 0) {
	return -1;
    }
    return 0;
}

static void
nm_prepare_database(void)
{
    if ((nm->options & OPT_NO_DB)) {
	db_disable();
	return;
    }
    
    db_init(nm->db_type);
    if (db_test_connection(nm->hosts_path) < 0) {
	fatal("Cannot access to database.\n");
    }

    if (nm->hosts_path[0] != 0) {
	if (db_host_load(nm->hosts_path) < 0) {
	    fatal("Fail to load host.\n");
	    exit(-1);
	}
    }
}

static void
nm_prepare_script(void)
{
    if (nm->script_path[0] != 0) {
	if (access(nm->script_path, X_OK) < 0) {
	    fatal("Script <%s> error: %s\n", nm->script_path, STRERRNO);
	}
    }
}

static void
nm_prepare_monitoring_process(void)
{
    if (nm_process_run_all(nm->monitoring, &nm_host_monitoring) < 0) {
	nm_process_kill_all(nm->monitoring);
	exit(-1);
    }
}

static void
nm_prepare_threads(void)
{
    if (THREAD_START(&nm->ctl_th, &nm_ctl_thread, nm) < 0) {
	fatal("Start control thread fail.\n");
    }
}
