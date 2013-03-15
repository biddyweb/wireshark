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
#include "packet-tosdis.h"

/* Forward declaration we need below */
void
proto_reg_handoff_tosdis(void);

/* for subdissectors */
static dissector_handle_t data_handle;
static dissector_table_t tosam_type_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_tosdis = -1;
static int hf_tosdis_id = -1;
static int hf_tosdis_type = -1;
static int hf_ieee802154_rssi = -1;
static int hf_ieee802154_fcs_ok = -1;
static int hf_ieee802154_correlation = -1;
static int hf_ieee802154_fcs = -1;

/* Initialize the subtree pointers */
static gint ett_tosdis = -1;
static gint ett_ieee802154_fcs = -1;

/* Code to actually dissect the packets */
static void
dissect_tosdis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb = tvb;
//  int available_length;
//  guint8 am_type;

  /* Set up structures needed to add the protocol subtree and manage it */
//  proto_item *ti;
//  proto_tree *tosdis_tree;

  /* check if this is really a complete AM. If not call sub dissector. */
//  if (tvb_length(tvb) < TOSAM_HEADER_LEN)
//  {
//    call_dissector(data_handle, tvb, pinfo, tree);
//    return;
//  }

//  am_type = tvb_get_guint8(tvb, TOSAM_HEADER_TYPE_OFFSET);



  if (tree)
  {
//    guint offset;
//    /* create display subtree for the protocol */
//    ti = proto_tree_add_item(tree, proto_tosdis, tvb, 0, -1, FALSE);
//    tosdis_tree = proto_item_add_subtree(ti, ett_tosdis);

    /* add items to the subtree */

  }
  /* If the CRC is invalid, make a note of it in the info column. */

  call_dissector(data_handle, next_tvb, pinfo, tree);
  return;
}

/* Register the protocol with Wireshark */
void
proto_register_tosdis(void)
{
  /* TinyOS2 Active Message Header */
  static hf_register_info hf[] =
  {
  { &hf_tosdis_id,
  { "Id", "tosdis.id", FT_UINT8, BASE_HEX, NULL, 0x0, "Unique Dispatch Id", HFILL } },
  { &hf_tosdis_type,
  { "Type", "tosdis.type", FT_UINT8, BASE_HEX, NULL, 0x0, "Active Message Type", HFILL } },
  { &hf_ieee802154_fcs,
  { "FCS", "tosdis.fcs", FT_UINT16, BASE_HEX, NULL, 0x0, "Frame Check Sequence", HFILL } },
  { &hf_ieee802154_rssi,
  { "RSSI", "tosdis.rssi", FT_INT8, BASE_DEC, NULL, 0x0, "Received Signal Strength", HFILL } },
  { &hf_ieee802154_fcs_ok,
  { "FCS Valid", "tosdis.fcs_ok", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
  { &hf_ieee802154_correlation,
  { "LQI Correlation Value", "tosdis.correlation", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_tosdis, &ett_ieee802154_fcs };

  /* Register the protocol name and description */
  proto_tosdis = proto_register_protocol("TinyOS Dissemination", "TOS Dissemination", "tosdis");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_tosdis, hf, array_length(hf));
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
proto_reg_handoff_tosdis(void)
{
  static dissector_handle_t tosdis_handle;
  static gboolean inited = FALSE;

  if (!inited)
  {
    tosdis_handle = create_dissector_handle(dissect_tosdis, proto_tosdis);
    inited = TRUE;
  }
  else
  {
  }
  data_handle = find_dissector("data");
}
