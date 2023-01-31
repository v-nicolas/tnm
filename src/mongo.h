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

#ifndef NM_MONGO_H
#define NM_MONGO_H

/* bson.h warning */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <mongoc/mongoc.h>
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop

#include "host.h"

int foodb(void);
int mongo_test_connection(void *arg);
mongoc_client_t * mongo_connect(const char *dburi);
int mongo_host_add(void *arg);
int mongo_host_del(void *arg);
int mongo_host_load(void *data);
int mongo_uuid_exists(void *data);
int mongo_update_host_state(void *data);
int mongo_delete_all(const char *coll_name);
void mongo_close(mongoc_client_t *client);
int mongo_free(void *data);

#endif /* !NM_MONGO_H */
