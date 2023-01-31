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

#ifndef NM_HOST_H
#define NM_HOST_H

#include <time.h>

#include "nm.h"

#include "../lib/sock.h"
#include "../lib/uuid.h"
#include "../lib/sbuf.h"
#include "../lib/http.h"
#include "../lib/file_utils.h"
#include "../lib/cJSON.h"

#define HOSTNAME_LEN 255

enum host_state {
    HOST_STATE_UNKNOWN = -1,
    HOST_STATE_DOWN    = 0,
    HOST_STATE_UP      = 1,
};

struct host_stats {
    time_t total_downtime;
    time_t last_downtime;
    time_t last_downtime_test;
    time_t downtime_start;
    time_t downtime_end;
    unsigned long long ntest;
    unsigned long long ntest_fail;
};

struct host {
    int state;
    int frequency;
    int options;
    int monit_type;
    int timeout;
    time_t last_test;
    struct http_header *http;
    char uuid[UUID_SIZE];
    char hostname[HOSTNAME_LEN];
    struct sock sock;
    struct host_stats stats;
};

struct host * host_init_ptr(void);
void host_init(struct host *host);
void host_free(void *arg);
void host_delete_by_process(struct nm_process *process);
int host_set_uuid(struct host *new_host, char **err);
int host_get_unused_uuid(char *uuid);
struct nm_process * host_add(struct host *host, char **err ATTR_UNUSED);
struct nm_process * host_link(struct host *host);
struct nm_process * host_get_process_by_uuid(const char *uuid);
struct host * host_get_by_uuid(const char *uuid);
void host_free_unused(const char *uuid);
int host_parse_json(struct host *host, cJSON *json_host);

#endif /* !NM_HOST_H */
