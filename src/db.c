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

#include "../lib/log.h"

#include "db.h"
#include "db_file.h"
#include "mongo.h"

static struct database db;

void
db_init(int db_type)
{
    if (db_type == DB_TYPE_FILE) {
	db.test_connection = &db_file_test_open;
	db.host_add = &db_file_host_update;
	db.host_del = &db_file_host_update;
	db.host_load = &db_file_host_load;
	db.uuid_exists = &db_file_uuid_exists;
    } else if (db_type == DB_TYPE_MONGO) {
	db.test_connection = &mongo_test_connection;
	db.host_add = &mongo_host_add;
	db.host_del = &mongo_host_del;
	db.host_load = &mongo_host_load;
	db.uuid_exists = &mongo_uuid_exists;
	db.free = &mongo_free;
	db.host_state_change = &mongo_update_host_state;
    } else {
	fatal("Database type not set.\n");
    }
}

int
db_test_connection(void *arg)
{
    if (db.test_connection == NULL) {
	return 0;
    }
    return db.test_connection(arg);
}

int
db_host_add(void *arg)
{
    if (db.host_add == NULL) {
	return 0;
    }
    return db.host_add(arg);
}

int
db_host_del(void *arg)
{
    if (db.host_del == NULL) {
	return 0;
    }
    return db.host_del(arg);
}

int
db_host_load(void *arg)
{
    if (db.host_load == NULL) {
	return 0;
    }
    return db.host_load(arg);
}

int
db_uuid_exists(void *arg)
{
    if (db.uuid_exists == NULL) {
	return 0;
    }
    return db.uuid_exists(arg);
}

int
db_host_state_change(void *arg)
{
    if (db.host_state_change == NULL) {
	return 0;
    }
    return db.host_state_change(arg);
}

int
db_close(void *arg)
{
    if (db.close == NULL) {
	return 0;
    }
    return db.close(arg);
}
    
int
db_free(void *arg)
{
    if (db.free == NULL) {
	return 0;
    }
    return db.free(arg);
}
