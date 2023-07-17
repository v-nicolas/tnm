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

#include "db_file.h"
#include "db.h"
#include "nm.h"
#include "command.h"
#include "host.h"

#include "../lib/attr.h"
#include "../lib/log.h"
#include "../lib/mem.h"
#include "../lib/sbuf.h"
#include "../lib/json_utils.h"

int
db_file_test_open(void *data ATTR_UNUSED)
{
    FILE *file = NULL;
    
    if (files_access(nm->hosts_path, NULL, R_OK | W_OK) == NULL) {
	/* Try to create file */
	file = fopen(nm->hosts_path, "w+");
	if (file == NULL) {
	    err("Fail to create file database <%s> error: %s\n",
		nm->hosts_path, STRERRNO);
	    return -1;
	}
    }
    return 0;
}

int
db_file_host_update(void *data ATTR_UNUSED)
{
    struct cmd cmd;
    FILE *file = NULL;

    if ((nm->options & OPT_NO_DB) || nm->hosts_path[0] == 0) {
	return 0;
    }
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.host = xcalloc(sizeof(struct host));
    cmd.type_init = 1;
    
    sbuf_init(&cmd.reply);
    sbuf_add(&cmd.reply, JSON_OPEN);
    if (cmd_host_list(&cmd) < 0) {
	err("Fail to update host file: %s.\n", cmd.error);
	cmd_free_all_data(&cmd);
	return -1;
    }
    json_close(&cmd.reply, JSON_CLOSE);

    if (sbuf_len(&cmd.reply) > 0) {
	file = fopen(nm->hosts_path, "w+");
	if (file == NULL) {
	    err("Open <%s>: %s\n", nm->hosts_path, STRERRNO);
	    cmd_free_all_data(&cmd);
	    return -1;
	}
	fprintf(file, "%s", cmd.reply.buf);
	fclose(file);
    }
    
    cmd_free_all_data(&cmd);
    return 0;
}

int
db_file_host_load(void *data)
{
    int error;
    cJSON *monitor = NULL;
    cJSON *json_host = NULL;
    const cJSON *json_hosts = NULL;
    const char *path = data;

    if (path == NULL || path[0] == 0) {
	warn("Hosts file path is empty.\n");
	return -1;
    }

    monitor = json_parse_file(path, &error);
    if (monitor == NULL) {
	return (error == JSON_RDFILE_ERROR) ? -1 : 0;
    }

    json_hosts = cJSON_GetObjectItemCaseSensitive(monitor, "hosts");
    if (json_hosts == NULL) {
	err("Parse hosts: %s\n", cJSON_GetErrorPtr2());
	cJSON_Delete(monitor);	
	return -1;
    }

    cJSON_ArrayForEach(json_host, json_hosts) {
	if (nm_add_host_by_json(json_host) < 0) {
	    cJSON_Delete(monitor);
	    return -1;
	}
    }
    cJSON_Delete(monitor);
    return 0;
}

int
db_file_uuid_exists(void *data)
{
    return (host_get_by_uuid((const char *)data) != NULL);
}
