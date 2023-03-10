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

#ifndef NM_H
#define NM_H

#include <netinet/in.h>

#include "../lib/attr.h"
#include "../lib/uuid.h"
#include "../lib/thread.h"
#include "../lib/cJSON.h"
#include "../lib/file_utils.h"
#include "../lib/api_rest.h"

#define PKT_MAX_SIZE 0xffff

enum program_options {
    OPT_NO_DB		 = (1 << 0),
    OPT_RUN_BG		 = (1 << 1),
    OPT_DISABLE_API_REST = (1 << 2),
};

enum nm_process_state {
    NM_PROCESS_RUN,
    NM_PROCESS_KILL,
    NM_PROCESS_SUSPEND,
    NM_PROCESS_RESUME,
};

enum nm_process_options {
    NM_PROCESS_OPT_ALL  = (1 << 0),
    NM_PROCESS_OPT_ONE  = (1 << 1),
};

struct nm_priv_msg {
    int state;
    unsigned long timestamp;
    char uuid[UUID_SIZE];
} ATTR_PACKED;

struct nm_process_suspend {
    unsigned long start;
    unsigned long duration; /* 0 is unlimited duration */
};

struct nm_process {
    pid_t pid;
    int state;
    void *data;
    void (*free_data)(void *);
    struct nm_process *next;
    struct nm_process *prev;
    struct nm_process_suspend *suspend;
};

struct nm {
    int run;
    int ctl_fd;
    int priv_fd;
    int db_type;
    int suspend_time;
    unsigned int options;
    thread_t ctl_th;
    thread_mutex_t run_mutex;
    char *ctl_sock_path;
    char *priv_sock_path;
    struct api_rest *api;
    struct nm_process *monitoring;
    struct nm_process *script;
    struct nm_process_suspend *suspend;
    char pid_file[PATH_SIZE];
    char conf_file[PATH_SIZE];
    char hosts_path[PATH_SIZE];
    char script_path[PATH_SIZE];
};

void nm_init(const char *pname);
void nm_prepare(void);
int nm_run(void);
void nm_free(void);
int nm_process_run(struct nm_process *process, int (*func_ptr)(void*));
int nm_process_kill_and_wait(struct nm_process *process);
int nm_process_send_sig(pid_t pid, int signum);
int nm_process_kill(pid_t pid);
int nm_process_wait(struct nm_process *process, int options);
void nm_process_free(struct nm_process *process);
void nm_process_suspend_init(struct nm_process_suspend **suspend, int duration);
void nm_process_suspend_free(struct nm_process_suspend **suspend);
int nm_process_change_state(int new_state,
			    unsigned int options,
			    struct nm_process *process);
int nm_host_monitoring(void *arg);
const char * nm_get_state_str(int state);
const char * nm_get_monit_type_str(int type, int options);
int nm_reload_hosts(const char *path);
int nm_add_host_by_json(cJSON *json);

extern struct nm *nm;

#endif /* !NM_H */
