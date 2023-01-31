
#include <assert.h>

#include "../lib/mem.h"
#include "../lib/log.h"

#include "../src/command.c"

const char *progname;

static void test_command(void);
static void test_cmd_check_host_fields(void);

#define CMD_RESET_ERROR(c)			\
    do {					\
	xfree(c.error);				\
	c.error = NULL;				\
    } while (0)

int
main(int argc, char **argv)
{
    nm_init(argv[0]);
    test_command();
    nm_free();
    return 0;
}

static void
test_command(void)
{
    struct host *h = NULL;

    
    test_cmd_check_host_fields();
}

static void
test_cmd_check_host_fields(void)
{
    struct cmd c;
 
    memset(&c, 0, sizeof(c));
    c.host = xcalloc(sizeof(struct host));
    c.host->timeout = 10;
    c.host->monit_type = 1;
    c.host->sock.family = AF_INET;
    c.host->sock.proto = 0;
    c.host->sock.type = SOCK_STREAM;
    assert(sock_resolv_addr("localhost", &c.host->sock) == 0);
    
    /* frequency min */
    c.host->frequency = NM_FREQ_MIN-1;
    assert(cmd_check_host_fields(&c) == -1);
    assert(STREQ(c.error, NM_ERR_FREQ_INVALID));
    CMD_RESET_ERROR(c);
    
    /* frequency man */
    c.host->frequency = NM_FREQ_MAX+1;
    assert(cmd_check_host_fields(&c) == -1);
    assert(STREQ(c.error, NM_ERR_FREQ_INVALID));
    CMD_RESET_ERROR(c);
    c.host->frequency = NM_FREQ_MIN;
    
    /* timeout min */
    c.host->timeout = NM_TIMEOUT_MIN-1;
    assert(cmd_check_host_fields(&c) == -1);
    printf("%s\n", c.error);
    assert(STREQ(c.error, NM_ERR_TIMEOUT_INVALID));
    CMD_RESET_ERROR(c);

    /* timeout max */
    c.host->timeout = NM_TIMEOUT_MAX+1;
    assert(cmd_check_host_fields(&c) == -1);
    assert(STREQ(c.error, NM_ERR_TIMEOUT_INVALID));
    CMD_RESET_ERROR(c);

    /* no hostname and ip */
    c.host->timeout = NM_TIMEOUT_MAX;
    c.host->sock.family = NM_IPv4;
    c.host->hostname[0] = 0;
    c.host->sock.straddr[0] = 0;
    assert(cmd_check_host_fields(&c) == -1);
    assert(STREQ(c.error, NM_ERR_ADDR_MISSING));
    CMD_RESET_ERROR(c);
    
    /* no monitoring type */
    strcpy(c.host->sock.straddr, "127.0.0.1");
    c.host->monit_type = MONIT_ERR;
    assert(cmd_check_host_fields(&c) == -1);
    assert(STREQ(c.error, NM_ERR_MONIT_TYPE_INVALID));
    CMD_RESET_ERROR(c);
    
    /* invalid ipv */
    c.host->sock.family = -1;
    c.host->monit_type = MONIT_PING;
    assert(cmd_check_host_fields(&c) == -1);
    assert(STREQ(c.error, NM_ERR_IP_VERSION_INVALID));
    CMD_RESET_ERROR(c);

    cmd_free_data(&c);
}
