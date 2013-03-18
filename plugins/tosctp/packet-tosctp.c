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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tosctp.h"
#include <epan/dissectors/packet-ieee802154.h>
#include <epan/crc16-tvb.h>
#include <epan/expert.h>

/* Forward declaration we need below */
void
proto_reg_handoff_tosctp(void);

/* for subdissectors */
static dissector_handle_t data_handle;
static dissector_table_t tosam_type_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_tosctp = -1;
static int hf_tosctp_pull = -1;
static int hf_tosctp_con = -1;
static int hf_tosctp_thl = -1;
static int hf_tosctp_etx = -1;
static int hf_tosctp_origin = -1;
static int hf_tosctp_seqno = -1;
static int hf_tosctp_collect_id = -1;
static int hf_tosctp_parent = -1;

/* Initialize the subtree pointers */
static gint ett_tosctp = -1;

static void
dissect_ctp_routing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *tosctp_tree;

  if (tvb_length(tvb) < TOS_CTP_ROUTING_HEADER_LEN)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  if (tree)
  {
    guint offset;
    offset = 0;
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_tosctp, tvb, 0, -1, FALSE);
    proto_item_append_text(ti, " (Routing)");
    tosctp_tree = proto_item_add_subtree(ti, ett_tosctp);
    proto_tree_add_item(tosctp_tree, hf_tosctp_pull, tvb, offset, TOS_CTP_P_LEN, FALSE);
    proto_tree_add_item(tosctp_tree, hf_tosctp_con, tvb, offset, TOS_CTP_C_LEN, FALSE);
    offset += TOS_CTP_C_LEN;
    proto_tree_add_item(tosctp_tree, hf_tosctp_parent, tvb, offset, TOS_CTP_PARENT_LEN, FALSE);
    offset += TOS_CTP_PARENT_LEN;
    proto_tree_add_item(tosctp_tree, hf_tosctp_etx, tvb, offset, TOS_CTP_ETX_LEN, FALSE);
    offset += TOS_CTP_ETX_LEN;
  }

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOS CTP Routing");

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, TOS_CTP_ROUTING_HEADER_LEN,
      tvb_length(tvb) - TOS_CTP_ROUTING_HEADER_LEN, tvb_length(tvb) - TOS_CTP_ROUTING_HEADER_LEN);

  /* call the next dissector */
  call_dissector(data_handle, next_tvb, pinfo, tree);
  return;
}

static void
dissect_ctp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;
  guint8 am_type;
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *tosctp_tree;

  if (tvb_length(tvb) < TOS_CTP_DATA_HEADER_LEN)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  am_type = tvb_get_guint8(tvb, TOS_CTP_DATA_COLLECT_ID_OFFSET);

  if (tree)
  {
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_tosctp, tvb, 0, -1, FALSE);
    proto_item_append_text(ti, " (Data)");
    tosctp_tree = proto_item_add_subtree(ti, ett_tosctp);
    proto_tree_add_item(tosctp_tree, hf_tosctp_pull, tvb, TOS_CTP_P_OFFSET, TOS_CTP_P_LEN, FALSE);
    proto_tree_add_item(tosctp_tree, hf_tosctp_con, tvb, TOS_CTP_C_OFFSET, TOS_CTP_C_LEN, FALSE);
    proto_tree_add_item(tosctp_tree, hf_tosctp_thl, tvb, TOS_CTP_THL_OFFSET, TOS_CTP_THL_LEN, FALSE);
    proto_tree_add_item(tosctp_tree, hf_tosctp_etx, tvb, TOS_CTP_DATA_ETX_OFFSET, TOS_CTP_ETX_LEN, FALSE);
    proto_tree_add_item(tosctp_tree, hf_tosctp_origin, tvb, TOS_CTP_DATA_ORIGIN_OFFSET, TOS_CTP_ORIGIN_LEN, FALSE);
    proto_tree_add_item(tosctp_tree, hf_tosctp_seqno, tvb, TOS_CTP_DATA_SEQNO_OFFSET, TOS_CTP_SEQNO_LEN, FALSE);
    proto_tree_add_item(tosctp_tree, hf_tosctp_collect_id, tvb, TOS_CTP_DATA_COLLECT_ID_OFFSET, TOS_CTP_COLLECT_ID_LEN, FALSE);
  }

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOS CTP Data");

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, TOS_CTP_DATA_HEADER_LEN,
      tvb_length(tvb) - TOS_CTP_DATA_HEADER_LEN, tvb_length(tvb) - TOS_CTP_DATA_HEADER_LEN);

  if (dissector_try_uint(tosam_type_dissector_table, am_type, next_tvb, pinfo, tree)) {
    return;
  }

  /* call the next dissector */
  call_dissector(data_handle, next_tvb, pinfo, tree);
  return;
}

/* Register the protocol with Wireshark */
void
proto_register_tosctp(void)
{
  /* TinyOS CTP Header */
  static hf_register_info hf[] =
  {
  { &hf_tosctp_pull,
  { "P", "tosctp.pull", FT_BOOLEAN, 8, NULL, TOS_CTP_PULL_FLAG, "Routing Pull", HFILL } },
  { &hf_tosctp_con,
  { "C", "tosctp.con", FT_BOOLEAN, 8, NULL, TOS_CTP_CONGESTION_FLAG, "Congestion Notification", HFILL } },
  { &hf_tosctp_thl,
  { "THL", "tosctp.thl", FT_UINT8, BASE_DEC, NULL, 0x0, "Time Has Lived", HFILL } },
  { &hf_tosctp_etx,
  { "ETX", "tosctp.etx", FT_UINT16, BASE_DEC, NULL, 0x0, "Expected Transmission", HFILL } },
  { &hf_tosctp_origin,
  { "Origin", "tosctp.origin", FT_UINT16, BASE_HEX, NULL, 0x0, "Origin", HFILL } },
  { &hf_tosctp_seqno,
  { "Seqno", "tosctp.seqno", FT_UINT8, BASE_DEC, NULL, 0x0, "Seqno", HFILL } },
  { &hf_tosctp_collect_id,
  { "Collect Id", "tosctp.collect_id", FT_UINT8, BASE_HEX, NULL, 0x0, "Collect Id (AM Type)", HFILL } },
  { &hf_tosctp_parent,
  { "Parent", "tosctp.parent", FT_UINT16, BASE_HEX, NULL, 0x0, "Current Parent", HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_tosctp };

  /* Register the protocol name and description */
  proto_tosctp = proto_register_protocol("TinyOS Collection Tree Protocol", "TOS CTP", "tosctp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_tosctp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  tosam_type_dissector_table = find_dissector_table("tosam.type");
}

/* If this dissector uses sub-dissector registration add a registration routine.
 This exact format is required because a script is used to find these routines
 and create the code that calls these routines.

 This function is also called by preferences whenever "Apply" is pressed
 (see prefs_register_protocol above) so it should accommodate being called
 more than once.
 */
void
proto_reg_handoff_tosctp(void)
{
  static dissector_handle_t tosctp_routing_handle;
  static dissector_handle_t tosctp_data_handle;
  static gboolean inited = FALSE;

  if (!inited)
  {
    tosctp_routing_handle = create_dissector_handle(dissect_ctp_routing, proto_tosctp);
    tosctp_data_handle = create_dissector_handle(dissect_ctp_data, proto_tosctp);
    data_handle = find_dissector("data");
    inited = TRUE;
  }
  else
  {
    dissector_delete_uint("tosam.type", 0x70, tosctp_routing_handle);
    dissector_delete_uint("tosam.type", 0x71, tosctp_data_handle);
  }

  dissector_add_uint("tosam.type", 0x70, tosctp_routing_handle);
  dissector_add_uint("tosam.type", 0x71, tosctp_data_handle);
}
