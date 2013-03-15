/* Wireshark - Network traffic analyzer
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

#ifndef PACKET_TOSCTP_H
#define PACKET_TOSCTP_H

#define TOS_CTP_P_OFFSET 0
#define TOS_CTP_C_OFFSET 0
#define TOS_CTP_P_LEN 1
#define TOS_CTP_C_LEN 1
#define TOS_CTP_PARENT_LEN 2
#define TOS_CTP_ETX_LEN 2
#define TOS_CTP_THL_LEN 1
#define TOS_CTP_ORIGIN_LEN 2
#define TOS_CTP_SEQNO_LEN 1
#define TOS_CTP_COLLECT_ID_LEN 1


#define TOS_CTP_PULL_FLAG 0x80
#define TOS_CTP_CONGESTION_FLAG 0x40

#define TOS_CTP_ROUTING_PARENT_OFFSET (TOS_CTP_C_OFFSET+TOS_CTP_C_LEN)
#define TOS_CTP_ROUTING_ETX_OFFSET (TOS_CTP_ROUTING_PARENT_OFFSET+TOS_CTP_PARENT_LEN)
#define TOS_CTP_ROUTING_HEADER_LEN (TOS_CTP_ROUTING_ETX_OFFSET+TOS_CTP_ETX_LEN)

#define TOS_CTP_THL_OFFSET (TOS_CTP_C_OFFSET+TOS_CTP_C_LEN)
#define TOS_CTP_DATA_ETX_OFFSET (TOS_CTP_THL_OFFSET+TOS_CTP_THL_LEN)
#define TOS_CTP_DATA_ORIGIN_OFFSET (TOS_CTP_DATA_ETX_OFFSET+TOS_CTP_ETX_LEN)
#define TOS_CTP_DATA_SEQNO_OFFSET (TOS_CTP_DATA_ORIGIN_OFFSET+TOS_CTP_ORIGIN_LEN)
#define TOS_CTP_DATA_COLLECT_ID_OFFSET (TOS_CTP_DATA_SEQNO_OFFSET+TOS_CTP_SEQNO_LEN)
#define TOS_CTP_DATA_HEADER_LEN (TOS_CTP_DATA_COLLECT_ID_OFFSET+TOS_CTP_COLLECT_ID_LEN)


static void dissect_ctp_routing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_ctp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#endif
