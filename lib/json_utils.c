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

#include <stdio.h>
#include <string.h>

#include "log.h"
#include "sbuf.h"
#include "json_utils.h"

#define JSON_RDFILE_SET_ERR(e, status)	\
    do {					\
	if (e != NULL) {			\
	    *e = -status;			\
	}					\
    } while (0)

int
json_get_var(cJSON *monitor, struct json_var *var)
{
    return json_get_var_opts(monitor, var, 0);
}

int
json_get_var_opts(cJSON *monitor, struct json_var *var, unsigned int options)
{
    cJSON *item = NULL;
    
    item = cJSON_GetObjectItem(monitor, var->name);
    if (item == NULL) {
	if ((options & JSON_OPT_OMITEMPTY)) {
	    return 0;
	}
	snprintf(var->err, JSON_VAR_ERR_SIZE,
		 "JSON <%s> missing.\n", var->name);
	return -1;
    }

    if (var->type == cJSON_Number) {	
	if (!cJSON_IsNumber(item)) {
	    	snprintf(var->err, JSON_VAR_ERR_SIZE,
			 "JSON <%s> invalid type.\n", var->name);
	    return -1;
	}
	*(var->ivalptr) = item->valueint;
    } else {
	if (!cJSON_IsString(item)) {
	    snprintf(var->err, JSON_VAR_ERR_SIZE,
		     "JSON <%s> invalid type.\n", var->name);
	    return -1;
	}

	if (var->str_size > 0) {
	    if (strlen(item->valuestring) == 0) {
		var->sval[0] = 0;
	    } else {
		memset(var->sval, 0, var->str_size);
		strncpy(var->sval, item->valuestring, var->str_size-1);
	    }
	} else {
	    if (strlen(item->valuestring) == 0) {
		*var->svalptr = strdup("");
	    } else {
		*var->svalptr = strdup(item->valuestring);
	    }

	    if (*var->svalptr == NULL) {
		snprintf(var->err, JSON_VAR_ERR_SIZE,
			 "JSON <%s> memory exhausted.\n", var->name);
		return -1;
	    }
	}
    }
    
    return 0;
}

cJSON *
json_parse_file(const char *path, int *error)
{
    int ret;
    cJSON *monitor = NULL;
    struct sbuf str = SBUF_INIT;

    JSON_RDFILE_SET_ERR(error, JSON_RDFILE_SUCCESS);
    ret = sbuf_read_file(&str, path);
    if (ret < 0) {
	err("read file <%s> %s: %s\n", path,
	    sbuf_rdfile_get_func_fail(ret), STRERRNO);
	sbuf_free(&str);
	JSON_RDFILE_SET_ERR(error, JSON_RDFILE_ERROR);
	return NULL;
    }

    if (sbuf_len(&str) == 0) {
	JSON_RDFILE_SET_ERR(error, JSON_RDFILE_IS_EMPTY);
	warn("json file <%s> is empty\n", path);
	sbuf_free(&str);
	return 0;
    }
    
    monitor = cJSON_Parse(str.buf);
    sbuf_free(&str);
    if (monitor == NULL) {
	err("JSON parse file <%s>: %s\n", path, cJSON_GetErrorPtr2());
        JSON_RDFILE_SET_ERR(error, JSON_RDFILE_ERROR);
	return NULL;
    }

    return monitor;
}
