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

#include "http_routes.h"
#include "command.h"

#include "../lib/attr.h"
#include "../lib/api_rest.h"
#include "../lib/sock.h"
#include "../lib/http.h"

int
http_route_host_manage(struct api_rest_req_ctx *ctx, void *arg ATTR_UNUSED)
{
    int ret;
    struct cmd cmd;

    cmd_init(&cmd);
    ret = cmd_handler(ctx->in.payload, &cmd);
    if (ret != -1) {
	api_rest_ret(ctx, HTTP_STATUS_OK, cmd.reply.buf);
	cmd_free_after_exec(&cmd);
    } else {
	api_rest_ret(ctx, HTTP_STATUS_INTERNAL_ERROR, cmd.reply.buf);
	cmd_free_all_data(&cmd);
    }

    return 0;
}
