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
#include "packet-ctp.h"
#include <epan/dissectors/packet-ieee802154.h>
#include <epan/crc16-tvb.h>
#include <epan/expert.h>

/* Forward declaration we need below */
void
proto_reg_handoff_ctp(void);

/* for subdissectors */
static dissector_handle_t data_handle;
static dissector_table_t tos_type_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_ctp = -1;
static int hf_ctp_pull = -1;
static int hf_ctp_con = -1;
static int hf_ctp_thl = -1;
static int hf_ctp_etx = -1;
static int hf_ctp_origin = -1;
static int hf_ctp_seqno = -1;
static int hf_ctp_collect_id = -1;
static int hf_ctp_parent = -1;

/* Initialize the subtree pointers */
static gint ett_ctp = -1;

static void
dissect_ctp_routing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *ctp_tree;

  if (tvb_length(tvb) < CTP_ROUTING_HEADER_LEN)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  if (tree)
  {
    guint offset;
    offset = 0;
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_ctp, tvb, 0, -1, FALSE);
    proto_item_append_text(ti, " (Routing)");
    ctp_tree = proto_item_add_subtree(ti, ett_ctp);
    proto_tree_add_item(ctp_tree, hf_ctp_pull, tvb, offset, CTP_P_LEN, FALSE);
    proto_tree_add_item(ctp_tree, hf_ctp_con, tvb, offset, CTP_C_LEN, FALSE);
    offset += CTP_C_LEN;
    proto_tree_add_item(ctp_tree, hf_ctp_parent, tvb, offset, CTP_PARENT_LEN, FALSE);
    offset += CTP_PARENT_LEN;
    proto_tree_add_item(ctp_tree, hf_ctp_etx, tvb, offset, CTP_ETX_LEN, FALSE);
    offset += CTP_ETX_LEN;
  }

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTP Routing");

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, CTP_ROUTING_HEADER_LEN,
      tvb_length(tvb) - CTP_ROUTING_HEADER_LEN, tvb_length(tvb) - CTP_ROUTING_HEADER_LEN);

  /* call the next dissector */
  call_dissector(data_handle, next_tvb, pinfo, tree);
  return;
}

static void
dissect_ctp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;
  guint8 collectid;
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *ctp_tree;

  if (tvb_length(tvb) < CTP_DATA_HEADER_LEN)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  collectid = tvb_get_guint8(tvb, CTP_DATA_COLLECT_ID_OFFSET);

  if (tree)
  {
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_ctp, tvb, 0, -1, FALSE);
    proto_item_append_text(ti, " (Data)");
    ctp_tree = proto_item_add_subtree(ti, ett_ctp);
    proto_tree_add_item(ctp_tree, hf_ctp_pull, tvb, CTP_P_OFFSET, CTP_P_LEN, FALSE);
    proto_tree_add_item(ctp_tree, hf_ctp_con, tvb, CTP_C_OFFSET, CTP_C_LEN, FALSE);
    proto_tree_add_item(ctp_tree, hf_ctp_thl, tvb, CTP_THL_OFFSET, CTP_THL_LEN, FALSE);
    proto_tree_add_item(ctp_tree, hf_ctp_etx, tvb, CTP_DATA_ETX_OFFSET, CTP_ETX_LEN, FALSE);
    proto_tree_add_item(ctp_tree, hf_ctp_origin, tvb, CTP_DATA_ORIGIN_OFFSET, CTP_ORIGIN_LEN, FALSE);
    proto_tree_add_item(ctp_tree, hf_ctp_seqno, tvb, CTP_DATA_SEQNO_OFFSET, CTP_SEQNO_LEN, FALSE);
    proto_tree_add_item(ctp_tree, hf_ctp_collect_id, tvb, CTP_DATA_COLLECT_ID_OFFSET, CTP_COLLECT_ID_LEN, FALSE);
  }

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTP Data");

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, CTP_DATA_HEADER_LEN,
      tvb_length(tvb) - CTP_DATA_HEADER_LEN, tvb_length(tvb) - CTP_DATA_HEADER_LEN);

  if (tos_type_dissector_table == NULL) {
    tos_type_dissector_table = find_dissector_table("tos.amid");
  }

  if (tos_type_dissector_table != NULL &&
      dissector_try_uint(tos_type_dissector_table, collectid, next_tvb, pinfo, tree)) {
    return;
  }

  /* call the next dissector */
  call_dissector(data_handle, next_tvb, pinfo, tree);
  return;
}

/* Register the protocol with Wireshark */
void
proto_register_ctp(void)
{
  /* CTP Header */
  static hf_register_info hf[] =
  {
  { &hf_ctp_pull,
  { "P", "ctp.pull", FT_BOOLEAN, 8, NULL, CTP_PULL_FLAG, "Routing Pull", HFILL } },
  { &hf_ctp_con,
  { "C", "ctp.con", FT_BOOLEAN, 8, NULL, CTP_CONGESTION_FLAG, "Congestion Notification", HFILL } },
  { &hf_ctp_thl,
  { "THL", "ctp.thl", FT_UINT8, BASE_DEC, NULL, 0x0, "Time Has Lived", HFILL } },
  { &hf_ctp_etx,
  { "ETX", "ctp.etx", FT_UINT16, BASE_DEC, NULL, 0x0, "Expected Transmission", HFILL } },
  { &hf_ctp_origin,
  { "Origin", "ctp.origin", FT_UINT16, BASE_HEX, NULL, 0x0, "Origin", HFILL } },
  { &hf_ctp_seqno,
  { "Seqno", "ctp.seqno", FT_UINT8, BASE_DEC, NULL, 0x0, "Seqno", HFILL } },
  { &hf_ctp_collect_id,
  { "Collect Id", "ctp.collect_id", FT_UINT8, BASE_HEX, NULL, 0x0, "Collect Id (AM Type)", HFILL } },
  { &hf_ctp_parent,
  { "Parent", "ctp.parent", FT_UINT16, BASE_HEX, NULL, 0x0, "Current Parent", HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_ctp };

  /* Register the protocol name and description */
  proto_ctp = proto_register_protocol("Collection Tree Protocol", "CTP", "ctp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_ctp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/* If this dissector uses sub-dissector registration add a registration routine.
 This exact format is required because a script is used to find these routines
 and create the code that calls these routines.

 This function is also called by preferences whenever "Apply" is pressed
 (see prefs_register_protocol above) so it should accommodate being called
 more than once.
 */
void
proto_reg_handoff_ctp(void)
{
  static dissector_handle_t ctp_routing_handle;
  static dissector_handle_t ctp_data_handle;
  static gboolean inited = FALSE;

  if (!inited)
  {
    ctp_routing_handle = create_dissector_handle(dissect_ctp_routing, proto_ctp);
    ctp_data_handle = create_dissector_handle(dissect_ctp_data, proto_ctp);
    data_handle = find_dissector("data");
    inited = TRUE;
  }
  else
  {
    dissector_delete_uint("tos.amid", 0x70, ctp_routing_handle);
    dissector_delete_uint("tos.amid", 0x71, ctp_data_handle);
  }

  dissector_add_uint("tos.amid", 0x70, ctp_routing_handle);
  dissector_add_uint("tos.amid", 0x71, ctp_data_handle);
  dissector_add_uint("tos.amid", 0x7A, ctp_data_handle);
}
