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

#ifndef NM_DB_H
#define NM_DB_H

enum db_types {
    DB_TYPE_ERR   = 0,
    DB_TYPE_FILE  = 1,
    DB_TYPE_MONGO = 2,
};

struct database {
    int (*test_connection)(void *);
    int (*host_add)(void *);
    int (*host_del)(void *);
    int (*host_load)(void *);
    int (*host_state_change)(void *);
    int (*uuid_exists)(void *data);
    int (*close)(void *);
    int (*free)(void *);
};

void db_disable(void);
void db_init(int db_type);
int db_test_connection(void *arg);
int db_host_add(void *arg);
int db_host_del(void *arg);
int db_host_load(void *arg);
int db_uuid_exists(void *arg);
int db_host_state_change(void *arg);
int db_close(void *arg);
int db_free(void *arg);

#endif /* !NM_DB_H */
