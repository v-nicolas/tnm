
#include <assert.h>

#include "../lib/http.c"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

struct test_http_parse_first_line_data {
    int ret;
    char *line;
    char *method;
    char *path;
    char *param;
    char *version;
};

void test_http_get_status_code(void);
void test_http_get_content_type(void);
void test_http_get_auth(void);
void test_http_get_payload(void);
void test_http_parse_first_line(void);
void test_one_http_first_line(struct test_http_parse_first_line_data *test);

const char *progname;

int
main(int argc, char **argv)
{
    progname = argv[0];
    test_http_get_status_code();
    test_http_get_content_type();
    test_http_get_auth();
    test_http_get_payload();
    test_http_parse_first_line();
    return 0;
}

void
test_http_get_status_code(void)
{
    assert(http_get_status_code("XXXX 1 XX") == 1);
    assert(http_get_status_code("XXXX 200 XX") == 200);
    assert(http_get_status_code("XXXX\t3") == 3);
    assert(http_get_status_code("XXXX X 3") == -1);
    assert(http_get_status_code("XXXX -13") == -1);
}

void
test_http_get_content_type(void)
{
    int i;
    char *buf1 = NULL;
    char buf2[1024];
    char str[HTTP_CONTENT_TYPE_SIZE];

    assert(http_get_content_type("", str) == -1);
    assert(str[0] == 0);
    assert(http_get_content_type("Content-Type: test\r", str) == 0);
    assert(strcmp(str, "test") == 0);
    assert(http_get_content_type("Content-Type: test", str) == 0);
    assert(strcmp(str, "test") == 0);
    assert(http_get_content_type("Content-Type: test", str) == 0);
    assert(strcmp(str, "test") == 0);
    assert(http_get_content_type("Content-Type:   test  ", str) == 0);
    assert(strcmp(str, "test  ") == 0);
    assert(http_get_content_type("Content-Type:   test\ttest", str) == 0);
    assert(strcmp(str, "test\ttest") == 0);
    assert(http_get_content_type("Content:   test\ttest", str) == -1);

    buf1 = xcalloc((HTTP_CONTENT_TYPE_SIZE+1) * sizeof(char));
    for (i = 0; i < HTTP_CONTENT_TYPE_SIZE; i++) {
	buf1[i] = 'a';
    }
    snprintf(buf2, sizeof(buf2)-1, "Content-Type:%s", buf1);
    assert(http_get_content_type(buf2, str) == -1);

    buf1[HTTP_CONTENT_TYPE_SIZE-1] = 0;
    snprintf(buf2, sizeof(buf2)-1, "Content-Type:%s", buf1);
    assert(http_get_content_type(buf2, str) == 0);
    assert(strcmp(str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    xfree(buf1);
}

void
test_http_get_auth(void)
{
    char *value = NULL;
    char type[HTTP_AUTHORIZATION_SIZE];

    assert(http_get_authorization("", type, &value) == -1);
    assert(type[0] == 0 && value == NULL);
    assert(http_get_authorization("Authorization: Bearer 1", type, &value) == 0);
    assert(!strcmp(type, "Bearer"));
    assert(value != NULL);
    assert(!strcmp(value, "1"));
    xfree(value);

    assert(http_get_authorization("Authorization: Bearer  \r test",
				  type, &value) == 0);
    assert(!strcmp(type, "Bearer"));
    assert(value == NULL);
}

void
test_http_get_payload(void)
{
    char *v = NULL;

    assert(http_get_payload("") == NULL);
    assert(http_get_payload("a\r\nz\r\ne") == NULL);
    assert(http_get_payload("a\r\nz\r\n\r\n") == NULL);
    v = http_get_payload("a\r\nz\r\n\r\nr");
    assert(v != NULL && !strcmp(v, "r"));
    xfree(v);
    v = http_get_payload("a\r\nz\r\n\r\nrty");
    assert(v != NULL && !strcmp(v, "rty"));
    xfree(v);
}

void
test_http_copy_next_word(void)
{
    char buf[10];

    assert(http_copy_next_part("", buf, 9, 0) == 0 && buf[0] == 0);
    assert(http_copy_next_part(" ", buf, 9, 0) == 0 && buf[0] == 0);
    assert(http_copy_next_part("\t", buf, 9, 0) == 0 && buf[0] == 0);
    assert(http_copy_next_part("\tt", buf, 9, 0) == 0);
    assert(!strcmp(buf, "t"));
    assert(http_copy_next_part("\ttest", buf, 9, 0) == 0);
    assert(!strcmp(buf, "test"));
    assert(http_copy_next_part("\ttest test", buf, 9, HTTP_STR_OPT_BLANK) == 0);
    assert(!strcmp(buf, "test"));
}

void
test_http_get_next_word_size(void)
{
    assert(http_get_next_part_size("", 0, 0) == 0);
    assert(http_get_next_part_size("t", 0, 0) == -1);
    assert(http_get_next_part_size(" t", 0, 0) == 0);
    assert(http_get_next_part_size(" t", 0, HTTP_STR_OPT_BLANK) == 0);
    assert(http_get_next_part_size("t t", 10, HTTP_STR_OPT_BLANK) == 1);
    assert(http_get_next_part_size("t t", 10, 0) == 3);
    assert(http_get_next_part_size("t t", 3, 0) == -1);
}

void
test_http_parse_first_line(void)
{
    unsigned long i;
    struct test_http_parse_first_line_data tests[] = {
	{0, "GET / HTTP/1.0\r\n", HTTP_GET, "/", NULL, HTTP_VERSION_1},
        {0, "POST / HTTP/1.1\r\n", HTTP_POST, "/", NULL, HTTP_VERSION_1_1},
	{0, "PUT / HTTP/2.0\r\n", HTTP_PUT, "/", NULL, HTTP_VERSION_2},
	{0, "DELETE / HTTP/3.0\r\n", HTTP_DELETE, "/", NULL, HTTP_VERSION_3},
	{-1, "NOP / HTTP/1.1\r\n", NULL, NULL, NULL, NULL},
	{-1, "GET / HTTP/1.1\r", NULL, NULL, NULL, NULL},
	{-1, "GET / HTTP/1.1", NULL, NULL, NULL, NULL},
	{-1, "GET /HTTP/1.1\r\n", NULL, NULL, NULL, NULL},
	{-1, "GET/ HTTP/1.1\r\n", NULL, NULL, NULL, NULL},
	{0, "GET /test HTTP/1.0\r\n", HTTP_GET, "/test", NULL, HTTP_VERSION_1},
	{0, "GET /test? HTTP/1.0\r\n", HTTP_GET, "/test", NULL, HTTP_VERSION_1},
	{0, "GET /test?a=z&e=r HTTP/1.0\r\n", HTTP_GET, "/test", "a=z&e=r", HTTP_VERSION_1},
    };

    for (i = 0; i < ARRAY_SIZE(tests); i++) {
	test_one_http_first_line(&tests[i]);
    }
}

void
test_one_http_first_line(struct test_http_parse_first_line_data *test)
{
    struct http_header http;
    
    memset(&http, 0, sizeof(http));
    sbuf_init(&http.header);
    sbuf_add(&http.header, test->line);
    assert(http_parse_first_line(&http) == test->ret);
    if (test->ret == 0) {
	if (test->path != NULL) {
	    assert(!strcmp(http.path, test->path));
	}
	if (test->method != NULL) {
	    assert(!strcmp(http.method, test->method));
	}
	if (test->version != NULL) {
	    assert(!strcmp(http.version, test->version));
	}
	if (test->param != NULL) {
	    assert(!strcmp(http.param, test->param));
	}
    }
    http_header_free_data(&http);
}
