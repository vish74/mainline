/* Copyright (C) 2006-2007 Hendrik Sattler <post@hendrik-sattler.de>
 *       
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.		       
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *	       
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include "obexpushd.h"
#include "net.h"
#include "core.h"
#include "compiler.h"

static void disconnect_reqhint(file_data_t *data, obex_object_t *obj)
{
	/* A new request is coming in */
	obex_send_response(data, obj, OBEX_RSP_CONTINUE);
}

static void disconnect_request(file_data_t *data, obex_object_t __unused *obj)
{
	data->target = OBEX_TARGET_NONE;
	if (data->transfer.path) {
		free(data->transfer.path);
		data->transfer.path = NULL;
	}
}

static void disconnect_done(file_data_t *data, obex_object_t __unused *obj)
{
	net_disconnect(data->net_data);
}

void obex_action_disconnect (file_data_t* data, obex_object_t* obj, int event)
{
	switch (event) {
	case OBEX_EV_REQHINT:
		disconnect_reqhint(data, obj);
		break;

	case OBEX_EV_REQ:
		disconnect_request(data, obj);
		break;

	case OBEX_EV_REQDONE:
		disconnect_done(data, obj);
		break;
	}
}
