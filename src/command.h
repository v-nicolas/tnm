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

#ifndef NM_COMMAND_H
#define NM_COMMAND_H

#include "../lib/sbuf.h"
#include "../lib/cJSON.h"

#ifndef CMD_SIZE
# define CMD_SIZE 2048
#endif /* !CMD_SIZE */

struct cmd {
    int type;
    int type_ctrl;
    int type_init;
    char *error;
    cJSON *monitor;
    struct host *host;
    struct sbuf reply;
};

void cmd_init(struct cmd *cmd);
void cmd_free_after_exec(struct cmd *cmd);
void cmd_free_all_data(struct cmd *cmd);
int cmd_handler(const char *json, struct cmd *cmd);
int cmd_add_host(struct cmd *cmd);
int cmd_host_list(struct cmd *cmd);
void cmd_host_to_json(struct cmd *cmd, struct host *host);
int cmd_check_host_fields(struct cmd *cmd);

#endif /* !NM_COMMAND_H */
