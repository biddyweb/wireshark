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
static int hf_tosctp_id = -1;
static int hf_tosctp_type = -1;
static int hf_ieee802154_rssi = -1;
static int hf_ieee802154_fcs_ok = -1;
static int hf_ieee802154_correlation = -1;
static int hf_ieee802154_fcs = -1;

/* Initialize the subtree pointers */
static gint ett_tosctp = -1;

/* Code to actually dissect the packets */
static void
dissect_tosctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;
  guint8 am_type;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *tosctp_tree;

  /* check if this is really a complete AM. If not call sub dissector. */
//  if (tvb_length(tvb) < TOS_HEADER_LEN)
//  {
//    call_dissector(data_handle, tvb, pinfo, tree);
//    return;
//  }
//
//  am_type = tvb_get_guint8(tvb, tosctp_HEADER_TYPE_OFFSET);


  if (tree)
  {
//    guint offset;
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_tosctp, tvb, 0, -1, FALSE);
    tosctp_tree = proto_item_add_subtree(ti, ett_tosctp);

  }
  /* If the CRC is invalid, make a note of it in the info column. */

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOS AM");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "AM: 0x%2x, ", am_type);

  /* Calculate the available data in the packet,
   set this to -1 to use all the data in the tv_buffer */
//  next_tvb = tvb_new_subset(tvb, tosctp_HEADER_LEN, , -1);

  /* call the next dissector */

  if (dissector_try_uint(tosam_type_dissector_table, am_type, next_tvb, pinfo, tree)) {
    return;
  }
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
  { &hf_tosctp_id,
  { "Id", "tosctp.id", FT_UINT8, BASE_HEX, NULL, 0x0, "Unique Dispatch Id", HFILL } },
  { &hf_tosctp_type,
  { "Type", "tosctp.type", FT_UINT8, BASE_HEX, NULL, 0x0, "Active Message Type", HFILL } },
  { &hf_ieee802154_fcs,
  { "FCS", "tosctp.fcs", FT_UINT16, BASE_HEX, NULL, 0x0, "Frame Check Sequence", HFILL } },
  { &hf_ieee802154_rssi,
  { "RSSI", "tosctp.rssi", FT_INT8, BASE_DEC, NULL, 0x0, "Received Signal Strength", HFILL } },
  { &hf_ieee802154_fcs_ok,
  { "FCS Valid", "tosctp.fcs_ok", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
  { &hf_ieee802154_correlation,
  { "LQI Correlation Value", "tosctp.correlation", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_tosctp };

  /* Register the protocol name and description */
  proto_tosctp = proto_register_protocol("TinyOS Active Message", "TOS AM", "tosctp");

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
  static dissector_handle_t tosctp_handle;
  static gboolean inited = FALSE;

  if (!inited)
  {
    tosctp_handle = create_dissector_handle(dissect_tosctp, proto_tosctp);
    dissector_add_uint("tosam.type", 0x70, tosctp_handle);
    dissector_add_uint("tosam.type", 0x71, tosctp_handle);
    dissector_add_uint("tosam.type", 0x72, tosctp_handle);
    inited = TRUE;
  }
  else
  {
    dissector_delete_uint("tosam.type", 0x70, tosctp_handle);
    dissector_delete_uint("tosam.type", 0x71, tosctp_handle);
    dissector_delete_uint("tosam.type", 0x72, tosctp_handle);
  }

  dissector_add_uint("tosam.type", 0x70, tosctp_handle);
  dissector_add_uint("tosam.type", 0x71, tosctp_handle);
  dissector_add_uint("tosam.type", 0x72, tosctp_handle);
  data_handle = find_dissector("data");
}
