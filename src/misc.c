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

#include <time.h>
#include <string.h>

#include "misc.h"

const char *
get_date(unsigned long timestamp, char *date)
{
    struct tm *tm = NULL;

    memset(date, 0, DATE_SIZE);
    tm = localtime((time_t *) &timestamp);
    if (tm != NULL) {
	(void) strftime(date, DATE_SIZE, "%d/%m/%Y %H:%M:%S", tm);
    }
    if (date[0] == 0) {
        strncpy(date, "[get_date_error]", DATE_SIZE);
    }
    return date;
}
