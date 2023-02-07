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

#ifndef LIB_JSON_UTILS_H
#define LIB_JSON_UTILS_H

#include "cJSON.h"
#include "sbuf.h"

#define JSON_OPEN "{"
#define JSON_CLOSE "}"

#define JSON_ARRAY_OPEN "["
#define JSON_ARRAY_CLOSE "]"

#define JSON_MAKE(json, size, fmt, ...) snprintf(json, size, fmt, __VA_ARGS__)
#define JSON_SET_INT(x, y)    #x": %d,", y
#define JSON_SET_ULONG(x, y) #x": %lu,", y
#define JSON_SET_ULLONG(x, y) #x": %llu,", y
#define JSON_SET_LONG(x, y)   #x": %ld,", y
#define JSON_SET_STR(x, y)    #x": \"%s\",", y

enum json_read_file_status {
    JSON_RDFILE_SUCCESS,
    JSON_RDFILE_ERROR,
    JSON_RDFILE_IS_EMPTY,
};

enum json_options {
    JSON_OPT_OMITEMPTY = (1 << 0),
};

#define JSON_VAR_ERR_SIZE 124

#define JSON_INIT_STR(x, y, z)			\
    {						\
        .type = cJSON_String,			\
        .str_size = x,				\
        .name = y,				\
        .sval = z,				\
	.err = {0},		         	\
    }

#define JSON_INIT_STRPTR(y, z)			\
    {						\
        .type = cJSON_String,			\
        .str_size = 0,				\
        .name = y,				\
        .svalptr = z,				\
	.err = {0},		         	\
    }

#define JSON_INIT_NBR(x, y)			\
    {						\
        .type = cJSON_Number,			\
        .name = x,				\
        .ivalptr = y,				\
	.err = {0},			        \
    }

#define JSON_INIT_LAST				\
    {						\
        .type = 0,				\
	.str_size = 0,				\
	.name = NULL,			        \
	.sval = NULL,			        \
        .err = {0},				\
    }

struct json_var {
    int type;
    size_t str_size;
    const char *name;
    union {
	char *sval;
	char **svalptr;
	int *ivalptr;
    };
    char err[JSON_VAR_ERR_SIZE];
};

static inline void json_close(struct sbuf *str, const char *close_ch) {
    sbuf_trim_char(str, ',');
    sbuf_add(str, close_ch);
}

int json_get_var(cJSON *monitor, struct json_var *var);
int json_get_var_opts(cJSON *monitor, struct json_var *var, unsigned int options);
cJSON * json_parse_file(const char *path, int *error);

#endif /* not have LIB_JSON_UTILS_H */
