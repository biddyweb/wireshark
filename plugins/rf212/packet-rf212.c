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
#include "packet-rf212.h"
#include <epan/dissectors/packet-ieee802154.h>

#define RX_STATUS_VALID_FLAG 0x80

/* Forward declaration we need below */
void
proto_reg_handoff_rf212(void);

/* for subdissectors */
static dissector_handle_t data_handle;
static dissector_handle_t ieee802154_handle;
static heur_dissector_list_t heur_subdissector_list;

/* Initialize the protocol and registered fields */
static int proto_rf212 = -1;
static int hf_rf212_phy = -1;
static int hf_rf212_phr = -1;
static int hf_rf212_lqi = -1;
static int hf_rf212_ed = -1;
static int hf_rf212_rx_status_valid = -1;
static int hf_rf212_trac_status = -1;

/* Initialize the subtree pointers */
static gint ett_rf212 = -1;

/* Code to actually dissect the packets */
static void
dissect_rf212(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb = tvb;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *rf212_tree;

  guint8 len;

  if (tvb_length(tvb) < RF212_MIN_LEN)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  len = tvb_get_guint8(tvb, 1);

  if (tree)
  {
    guint offset;
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_rf212, tvb, 0, -1, FALSE);
    rf212_tree = proto_item_add_subtree(ti, ett_rf212);
    offset = 0;
    proto_tree_add_item(rf212_tree, hf_rf212_phy, tvb, offset, 1, FALSE);
    offset += 1;
    proto_tree_add_item(rf212_tree, hf_rf212_phr, tvb, offset, 1, FALSE);
    offset += 1 + len;
    proto_tree_add_item(rf212_tree, hf_rf212_lqi, tvb, offset, 1, FALSE);
    offset += 1;
    proto_tree_add_item(rf212_tree, hf_rf212_ed, tvb, offset, 1, FALSE);
    offset += 1;
    proto_tree_add_item(rf212_tree, hf_rf212_rx_status_valid, tvb, offset, 1, FALSE);
    proto_tree_add_item(rf212_tree, hf_rf212_trac_status, tvb, offset, 1, FALSE);
  }

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RF212 Frame");

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, 2, tvb_length(tvb) - 5, len);

  if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, NULL)) {
    return;
  }

  if (call_dissector_only(ieee802154_handle, next_tvb, pinfo, tree, NULL)) {
    return;
  }

  call_dissector(data_handle, next_tvb, pinfo, tree);
  return;
}

/* Register the protocol with Wireshark */
void
proto_register_rf212(void)
{
  /* TinyOS2 Active Message Header */
  static hf_register_info hf[] =
  {
  { &hf_rf212_phy,
  { "PHY", "rf212.phy", FT_UINT8, BASE_HEX, NULL, 0x0, "PHY_STATUS value", HFILL } },
  { &hf_rf212_phr,
  { "PHR", "rf212.len", FT_UINT8, BASE_DEC, NULL, 0x0, "Payload length", HFILL } },
  { &hf_rf212_lqi,
  { "LQI", "rf212.lqi", FT_UINT8, BASE_DEC, NULL, 0x0, "Link Quality Indication", HFILL } },
  { &hf_rf212_ed,
  { "ED", "rf212.ed", FT_UINT8, BASE_DEC, NULL, 0x0, "Energy Detection", HFILL } },
  { &hf_rf212_rx_status_valid,
  { "RX_STATUS_VALID", "rf212.crc_valid", FT_BOOLEAN, 8, NULL, RX_STATUS_VALID_FLAG, "RX_CRC_VALID bit of PHY_RSSI register", HFILL } },
  { &hf_rf212_trac_status,
  { "TRAC_STATUS", "rf212.trac_status", FT_BOOLEAN, 8, NULL, 0x70, "TRAC_STATUS value of TRX_STATUS register", HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_rf212 };

  /* Register the protocol name and description */
  proto_rf212 = proto_register_protocol("RF212 Frame", "RF212 physical layer frame", "rf212");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_rf212, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_heur_dissector_list("rf212", &heur_subdissector_list);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 This exact format is required because a script is used to find these routines
 and create the code that calls these routines.

 This function is also called by preferences whenever "Apply" is pressed
 (see prefs_register_protocol above) so it should accommodate being called
 more than once.
 */
void
proto_reg_handoff_rf212(void)
{
  static dissector_handle_t rf212_handle;
  static gboolean inited = FALSE;

  if (!inited)
  {
    rf212_handle = create_dissector_handle(dissect_rf212, proto_rf212);
    ieee802154_handle = find_dissector(IEEE802154_PROTOABBREV_WPAN);
    data_handle = find_dissector("data");
    inited = TRUE;
  }
  else
  {
    dissector_delete_uint("ip.proto", 0xfe, rf212_handle);
  }

  dissector_add_uint("ip.proto", 0xfe, rf212_handle);
}
