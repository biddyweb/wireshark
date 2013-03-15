/* packet-t2sam.h
 * Definitions for TinyOs2 Serial Active Message
 * Copyright 2007, Philipp Huppertz <huppertz@tkn.tu-berlin.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.*/

#ifndef PACKET_TOSAM_H
#define PACKET_TOSAM_H

#define TOSAM_IEEE_HEADER_LEN 9
#define TOSAM_HEADER_ID_LEN 1
#define TOSAM_HEADER_TYPE_LEN 1
#define TOSAM_HEADER_LEN (TOSAM_IEEE_HEADER_LEN+TOSAM_HEADER_ID_LEN+TOSAM_HEADER_TYPE_LEN)

#define TOSAM_HEADER_ID_OFFSET TOSAM_IEEE_HEADER_LEN
#define TOSAM_HEADER_TYPE_OFFSET (TOSAM_HEADER_ID_OFFSET + TOSAM_HEADER_ID_LEN)
#define TOSAM_DATA_OFFSET (TOSAM_HEADER_TYPE_OFFSET + TOSAM_HEADER_TYPE_LEN)

static void dissect_tosam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#endif
