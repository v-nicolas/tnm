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

#ifndef NM_HTTP_ROUTES_H
#define NM_HTTP_ROUTES_H

#include "../lib/api_rest.h"

/* To easely change the prototype of handlers */
#define DECLARE_HTTP_ROUTE(name) \
    int http_route_##name(struct api_rest_ctx *s, void *arg)

DECLARE_HTTP_ROUTE(host_manage);

#endif /* !NM_HTTP_ROUTES_H */
