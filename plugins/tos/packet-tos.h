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

#ifndef PACKET_TOS_H
#define PACKET_TOS_H

#define TOS_IEEE_HEADER_LEN 0
#define TOS_HEADER_ID_LEN 1
#define TOS_HEADER_TYPE_LEN 1
#define TOS_HEADER_LEN (TOS_IEEE_HEADER_LEN+TOS_HEADER_ID_LEN+TOS_HEADER_TYPE_LEN)

#endif
