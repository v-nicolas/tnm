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

#include "mongo.h"
#include "nm.h"
#include "host.h"
#include "command.h"

#include "../lib/log.h"
#include "../lib/json_utils.h"

#ifndef NDEBUG
# define DEFAULT_URI "mongodb://localhost:27017"
#endif /* !NDEBUG */

#define MGO_APP_NAME "nm"
#define MGO_DB_NAME  "nm"
#define MGO_COLL_HOST_NAME  "host"
#define MGO_COLL_STATE_NAME "state"

#define MGO_INIT {NULL, NULL, NULL, NULL}
#define MGO_AUTOFREE __attribute__((cleanup(mgo_free)))

struct mgo {
    bson_t *bson;
    bson_t *filter;
    mongoc_client_t *client;
    mongoc_collection_t *collection;
};

static int mongo_parse_host_collection(mongoc_collection_t *collection,
				       bson_t *filter);
static int mongo_insert_with_connection(const char *collection_name,
					const char *json);
static int mongo_insert(struct mgo *mgo, const char *json);
static int mongo_connect_to_collection(mongoc_client_t **client,
				       mongoc_collection_t **collection,
				       const char *coll_name);
static int mongo_add_new_state(struct mgo *mgo, struct nm_priv_msg *msg);
static int mongo_update_host(struct mgo *mgo, struct nm_priv_msg *msg);
static int xmongoc_get_collection(mongoc_client_t *client,
				  mongoc_collection_t **collection,
				  const char *coll_name);
static void mgo_free(struct mgo *m);
static void mgo_free_bson(struct mgo *m);

static int once_init = 0;
static mongoc_uri_t *uri = NULL;

int
mongo_test_connection(void *arg ATTR_UNUSED)
{
    mongoc_client_t *client = NULL;
    bson_t ping;
    bson_error_t error;

    client = mongo_connect(nm->hosts_path);
    if (client == NULL) {
	return -1;
    }
    
    bson_init(&ping);
    bson_append_int32(&ping, "ping", 4, 1);
    if (mongoc_client_command_simple(client, "nm", &ping,
				     NULL, NULL, &error) == 0) {
	err("Ping command fail: %s\n", error.message);
	bson_destroy(&ping);
	mongoc_client_destroy(client);
	return -1;
    }
 
    bson_destroy(&ping);
    mongoc_client_destroy(client);
    return 0;
}

mongoc_client_t *
mongo_connect(const char *dburi)
{
    mongoc_client_t *client = NULL;
    bson_error_t error;

    if (once_init == 0) {
	mongoc_init();
	once_init = 1;
    }

    if (uri == NULL) {
	uri = mongoc_uri_new_with_error(dburi, &error);
	if (uri == NULL) {
	    err("mongo URI <%s> error: %s\n", dburi, error.message);
	    return NULL;
	}
    }

    client = mongoc_client_new_from_uri(uri);
    if (!client) {
	err("Fail connect to mongo URI <%s>\n", error.message);
	return NULL;
    }
    
    mongoc_client_set_appname(client, MGO_APP_NAME);
    return client;
}

int
mongo_host_add(void *arg)
{
    struct host *host = arg;
    struct cmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.type_init = 1;
    cmd.host = host;
    cmd_host_to_json(&cmd, host);
    mongo_insert_with_connection(MGO_COLL_HOST_NAME, cmd.reply.buf);
    sbuf_free(&cmd.reply);
    return 0;
}

static int
mongo_insert_with_connection(const char *collection_name, const char *json)
{
    int ret;
    MGO_AUTOFREE struct mgo mgo = MGO_INIT;

    if (mongo_connect_to_collection(&mgo.client,
				    &mgo.collection,
				    collection_name) < 0) {
        return -1;
    }
    ret = mongo_insert(&mgo, json);
    return ret;
}

static int
mongo_insert(struct mgo *mgo, const char *json)
{
    bson_error_t error;

    DEBUG("MONGO JSON INSERT:\n%s\n\n", json);
    mgo->bson = bson_new_from_json((const uint8_t *)json, -1, &error);
    if (mgo->bson == NULL) {
	err("Fail to create bson document: %s\n", error.message);
	return -1;
    }
    if (mongoc_collection_insert(mgo->collection,
				 MONGOC_INSERT_NONE,
				 mgo->bson, NULL, &error) == 0) {
	err("mongoc insert: %s\n", error.message);
	return -1;
    }
    return 0;
}

int
mongo_host_del(void *arg)
{
    bson_error_t error;
    MGO_AUTOFREE struct mgo mgo = MGO_INIT;

    if (mongo_connect_to_collection(&mgo.client,
				    &mgo.collection,
				    MGO_COLL_HOST_NAME) < 0) {
        return -1;
    }

    mgo.filter = BCON_NEW("uuid", BCON_UTF8((const char *)arg));
    if (mongoc_collection_remove(mgo.collection,
				 MONGOC_REMOVE_SINGLE_REMOVE,
				 mgo.filter, NULL, &error) == 0) {
	err("Ping command fail: %s\n", error.message);
	return -1;
    }

    return 0;
}

int
mongo_host_load(void *data ATTR_UNUSED)
{
    MGO_AUTOFREE struct mgo mgo = MGO_INIT;

    if (mongo_connect_to_collection(&mgo.client,
				    &mgo.collection,
				    MGO_COLL_HOST_NAME) < 0) {
        return -1;
    }
    
    mgo.filter = bson_new();
    if (mongo_parse_host_collection(mgo.collection, mgo.filter) < 0) {
	return -1;
    }

    return 0;
}

static int
mongo_parse_host_collection(mongoc_collection_t *collection, bson_t *filter)
{
    int ret;
    mongoc_cursor_t *cursor = NULL;
    const bson_t *doc = NULL;
    cJSON *monitor = NULL;
    char *json = NULL;

    cursor = mongoc_collection_find_with_opts(collection, filter, NULL, NULL);
    if (cursor == NULL) {
	return -1;
    }
    
    while (mongoc_cursor_next(cursor, &doc)) {
        json = bson_as_json(doc, NULL);
	
	monitor = cJSON_Parse(json);
	if (monitor == NULL) {
	    err("mongo parse host: %s", cJSON_GetErrorPtr2());
	    bson_free(json);
	    mongoc_cursor_destroy(cursor);
	    return -1;
	}

	ret = nm_add_host_by_json(monitor);
        bson_free(json);
	cJSON_Delete(monitor);
	if (ret < 0) {
	    mongoc_cursor_destroy(cursor);
	    return -1;
	}
    }

    mongoc_cursor_destroy(cursor);
    return  0;
}

int
mongo_update_host_state(void *data)
{
    struct nm_priv_msg *msg = data;
    MGO_AUTOFREE struct mgo mgo = MGO_INIT;

    if (mongo_connect_to_collection(&mgo.client,
				    &mgo.collection,
				    MGO_COLL_STATE_NAME) < 0) {
        return -1;
    }

    if (mongo_add_new_state(&mgo, msg) < 0) {
	warn("Fail to add a new state.\n");
    }

    mgo_free_bson(&mgo);
    mongoc_collection_destroy(mgo.collection);
    if (xmongoc_get_collection(mgo.client,
			       &mgo.collection,
			       MGO_COLL_HOST_NAME) < 0) {
	return -1;
    }

    (void) mongo_update_host(&mgo, msg);
    return 0;
}

static int
mongo_add_new_state(struct mgo *mgo, struct nm_priv_msg *msg)
{
    int ret;
    struct sbuf str = SBUF_INIT;
    
    sbuf_add(&str, JSON_OPEN);
    sbuf_vadd(&str, JSON_SET_STR("uuid", msg->uuid));
    sbuf_vadd(&str, JSON_SET_INT("state", msg->state));
    sbuf_vadd(&str, JSON_SET_ULONG("timestamp", msg->timestamp));
    sbuf_vadd(&str, JSON_SET_STR("str_state", nm_get_state_str(msg->state)));
    json_close(&str, JSON_CLOSE);
    ret = mongo_insert(mgo, str.buf);
    sbuf_free(&str);
    return ret;
}

static int
mongo_update_host(struct mgo *mgo, struct nm_priv_msg *msg)
{
    bson_error_t error;

    mgo->bson = BCON_NEW("$set",
			 JSON_OPEN,
			 "state", BCON_INT32(msg->state),
			 "str_state", BCON_UTF8(nm_get_state_str(msg->state)),
			 JSON_CLOSE);
    mgo->filter = BCON_NEW("uuid", BCON_UTF8(msg->uuid));    
    if (mongoc_collection_update(mgo->collection,
				 MONGOC_UPDATE_NONE,
				 mgo->filter, mgo->bson,
				 NULL, &error) == 0) {
	return -1;
    }
    return 0;
}

static int
mongo_connect_to_collection(mongoc_client_t **client,
			    mongoc_collection_t **collection,
			    const char *coll_name)
{
    *collection = NULL;
    
    *client = mongo_connect(nm->hosts_path);
    if (*client == NULL) {
	return -1;
    }
    if (xmongoc_get_collection(*client, collection, coll_name) < 0) {
	mongoc_client_destroy(*client);
	*client = NULL;
	return -1;
    }
    return 0;
}

int
mongo_uuid_exists(void *arg)
{
    int64_t count;
    MGO_AUTOFREE struct mgo mgo = MGO_INIT;
    bson_error_t error;
    
    if (mongo_connect_to_collection(&mgo.client,
				    &mgo.collection,
				    MGO_COLL_HOST_NAME) < 0) {
        return -1;
    }

    mgo.bson = BCON_NEW("limit", BCON_INT64(1));
    mgo.filter = BCON_NEW("uuid", BCON_UTF8((const char *)arg));
    count = mongoc_collection_count_documents(mgo.collection,
					      mgo.filter, mgo.bson,
					      NULL, NULL, &error);
    if (count < 0) {
	err("Mongo collection %s count error: %s\n",
	    MGO_COLL_HOST_NAME, error.message);
	count = -1;
    }

    return (int)count;
}

static int
xmongoc_get_collection(mongoc_client_t *client,
		       mongoc_collection_t **collection,
		       const char *coll_name)
{
    *collection = mongoc_client_get_collection(client,
					       MGO_DB_NAME,
					       coll_name);
    if (*collection == NULL) {
	err("Fail ton connect collection `%s' database `%s'.\n",
	    coll_name, MGO_DB_NAME);
	return -1;
    }
    return 0;
}

static void
mgo_free(struct mgo *m)
{
    mgo_free_bson(m);
    if (m->collection != NULL) {
	mongoc_collection_destroy(m->collection);
	m->collection = NULL;
    }
    if (m->client != NULL) {
	mongoc_client_destroy(m->client);
	m->client = NULL;
    }
}

#define BSON_DESTROY(bson)			\
    do {					\
	if (bson != NULL) {			\
	    bson_destroy(bson);			\
	    bson = NULL;			\
	}					\
    } while (0)

static void
mgo_free_bson(struct mgo *m)
{
    BSON_DESTROY(m->bson);
    BSON_DESTROY(m->filter);
}

int
mongo_delete_all(const char *coll_name)
{
    int ret;
    struct mgo mgo = MGO_INIT;
    bson_error_t error;
    
    /* clear all host */
    if (mongo_connect_to_collection(&mgo.client,
				    &mgo.collection,
				    coll_name) < 0) {
	return -1;
    }

    ret = 0;
    mgo.filter = bson_new();
    if (!mongoc_collection_remove (mgo.collection, 0,
				   mgo.filter,
				   NULL, &error)) {
	err("Delete all document in collection %s error: %s\n",
	    coll_name, error.message);
	ret = -1;
    }
    mgo_free(&mgo);
    return ret;
}

void
mongo_close(mongoc_client_t *client)
{
    mongoc_client_destroy(client);
    client = NULL;
}

int
mongo_free(void *data ATTR_UNUSED)
{
    if (uri != NULL) {
	mongoc_uri_destroy(uri);
	uri = NULL;
    }
    if (once_init) {
	mongoc_cleanup();
	once_init = 0;
    }
    return 0;
}
