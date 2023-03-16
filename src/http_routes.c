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

int
http_route_host_manage(struct api_rest_ctx *ctx, void *arg ATTR_UNUSED)
{
    int ret;
    struct cmd cmd;

    cmd_init(&cmd);
    ret = cmd_handler(ctx->in.payload, &cmd);
    sbuf_add(&ctx->out, cmd.reply.buf);
    if (ret == -1) {
	cmd_free_all_data(&cmd);
    } else {
	cmd_free_after_exec(&cmd);
    }
    return 0;
}
