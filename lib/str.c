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

#include "str.h"

int
xstrtol(const char *str, int *v, int base)
{
    char *err = NULL;

    *v = (int) strtol(str, &err, base);
    if (err != NULL && *err != 0) {
        return -1;
    }

    return 0;
}

int
xstrtoul(const char *str, unsigned long int *v, int base)
{
    char *err = NULL;

    *v = strtoul(str, &err, base);
    if (err != NULL && *err != 0) {
        return -1;
    }

    return 0;
}
