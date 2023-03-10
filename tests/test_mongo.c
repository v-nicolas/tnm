
#include <assert.h>

#include "../src/nm.h"
#include "../lib/mem.h"
#include "../lib/log.h"

#include "../src/mongo.c"
#include "../src/mongo.h"

static void test_mongo(void);
static void test_delete_all(void);
static void test_insert_with_connection(void);
static void test_update_host(void);
static void test_update_host_state(void);
static void test_host_load(void);
static void test_uuid_exists(void);

const char *progname;

int
main(int argc, char **argv)
{
    nm_init(argv[0]);
    test_mongo();
    nm_free();
    return 0;
}

static void
test_mongo(void)
{   
    strcpy(nm->hosts_path, DEFAULT_URI);

    assert(mongo_test_connection(nm->hosts_path) == 0);
    test_delete_all();
    test_insert_with_connection();
    test_update_host();
    test_update_host_state();
    test_host_load();
    test_uuid_exists();

    mongo_free(NULL);
}

static void
test_insert_with_connection(void)
{
    test_delete_all();
    assert(mongo_insert_with_connection(MGO_COLL_HOST_NAME,
					"{"
					"\"uuid\": \"111\","
					"\"frequency\": 15,"
					"\"timeout\": 5,"
					"\"monitoring_type\": 1,"
					"\"ip\": \"127.0.1.1\","
					"\"state\":\"down\""
					"}") == 0);
}

static void
test_update_host(void)
{
    struct nm_priv_msg msg;
    struct mgo m = MGO_INIT;

    memset(&msg, 0, sizeof(struct nm_priv_msg));
    msg.state = HOST_STATE_UNKNOWN;
    msg.timestamp = time(NULL);
    strcpy(msg.uuid, "111");

    test_delete_all();
    assert(mongo_connect_to_collection(&m.client,
				       &m.collection,
				       MGO_COLL_HOST_NAME) == 0);
    assert(mongo_update_host(&m, &msg) == 0);
    mgo_free(&m);
}
 
static void
test_update_host_state(void)
{
    struct nm_priv_msg msg;

    test_delete_all();
    assert(mongo_insert_with_connection(MGO_COLL_HOST_NAME,
		     "{"
		     "\"uuid\": \"222\","
		     "\"host\": \"127.0.1.1\","
		     "\"state\":\"Unknow\""
					"}") == 0);

    memset(&msg, 0, sizeof(struct nm_priv_msg));
    msg.state = HOST_STATE_UP;
    msg.timestamp = time(NULL);
    strcpy(msg.uuid, "222");
    assert(mongo_update_host_state(&msg) == 0);
}

static void
test_host_load(void)
{
    test_delete_all();
    assert(mongo_insert_with_connection(MGO_COLL_HOST_NAME,
					"{"
					"\"uuid\": \"111\","
					"\"frequency\": 15,"
					"\"timeout\": 5,"
					"\"monitoring_type\": 1,"
					"\"ip\": \"127.0.1.1\","
					"\"state\":\"down\""
					"}") == 0);
    assert(mongo_insert_with_connection(MGO_COLL_HOST_NAME,
					"{"
					"\"uuid\": \"333\","
					"\"frequency\": 15,"
					"\"timeout\": 5,"
					"\"port\": 10,"
					"\"monitoring_type\": 3,"
					"\"ip\": \"127.0.1.1\","
					"\"state\":\"down\""
					"}") == 0);
    assert(mongo_host_load(NULL) == 0);
}

static void
test_uuid_exists(void)
{
    test_delete_all();
    assert(mongo_uuid_exists("111") == 0);
    assert(mongo_insert_with_connection(MGO_COLL_HOST_NAME,
					"{"
					"\"uuid\": \"111\","
					"\"frequency\": 15,"
					"\"timeout\": 5,"
					"\"monitoring_type\": 1,"
					"\"ip\": \"127.0.1.1\","
					"\"state\":\"down\""
					"}") == 0);
    assert(mongo_uuid_exists("111") == 1);
}


static void
test_delete_all(void)
{
    assert(mongo_delete_all(MGO_COLL_HOST_NAME) == 0);
}
