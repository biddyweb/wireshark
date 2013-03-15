/* packet-gryphon.c
 * Routines for Gryphon protocol packet disassembly
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tosam.h"
#include <epan/dissectors/packet-ieee802154.h>
#include <epan/crc16-tvb.h>
#include <epan/expert.h>

/* CRC definitions. IEEE 802.15.4 CRCs vary from CCITT by using an initial value of
 * 0x0000, and no XOR out. IEEE802154_CRC_XOR is defined as 0xFFFF in order to un-XOR
 * the output from the CCITT CRC routines in Wireshark. (from packet-ieee892154.c)
 */
#define IEEE802154_CRC_SEED     0x0000
#define IEEE802154_CRC_XOROUT   0xFFFF
#define ieee802154_crc_tvb(tvb, offset)   (crc16_ccitt_tvb_seed(tvb, offset, IEEE802154_CRC_SEED) ^ IEEE802154_CRC_XOROUT)

/* Forward declaration we need below */
void
proto_reg_handoff_tosam(void);

/* for subdissectors */
static gboolean tosam_cc24xx = FALSE;
static dissector_handle_t ieee802154_handle;
static dissector_handle_t data_handle;
static dissector_table_t tosam_type_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_tosam = -1;
static int hf_tosam_id = -1;
static int hf_tosam_type = -1;
static int hf_ieee802154_rssi = -1;
static int hf_ieee802154_fcs_ok = -1;
static int hf_ieee802154_correlation = -1;
static int hf_ieee802154_fcs = -1;

/* Initialize the subtree pointers */
static gint ett_tosam = -1;
static gint ett_ieee802154_fcs = -1;

/* Code to actually dissect the packets */
static void
dissect_tosam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb, *ieee802145_tvb;
  int available_length;
  guint8 am_type;
  volatile gboolean fcs_ok = TRUE;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *tosam_tree;

  /* check if this is really a complete AM. If not call sub dissector. */
  if (tvb_length(tvb) < TOSAM_HEADER_LEN)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  am_type = tvb_get_guint8(tvb, TOSAM_HEADER_TYPE_OFFSET);


  /*=====================================================
   * VERIFY FRAME CHECK SEQUENCE (from packet-ieee802154.c)
   *=====================================================
   */
  /* Check, but don't display the FCS yet, otherwise the payload dissection
   * may be out of place in the tree. But we want to know if the FCS is OK in
   * case the CRC is bad (don't want to continue dissection to the NWK layer).
   */
  if (tvb_bytes_exist(tvb, tvb_reported_length(tvb) - IEEE802154_FCS_LEN,
      IEEE802154_FCS_LEN))
  {
    /* The FCS is in the last two bytes of the packet. */
    guint16 fcs = tvb_get_letohs(tvb,
        tvb_reported_length(tvb) - IEEE802154_FCS_LEN);
    /* Check if we are expecting a CC2420-style FCS*/
    if (tosam_cc24xx)
    {
      fcs_ok = (fcs & IEEE802154_CC24xx_CRC_OK);
    }
    else
    {
      guint16 fcs_calc =
          ieee802154_crc_tvb(tvb, tvb_reported_length(tvb)-IEEE802154_FCS_LEN);
      fcs_ok = (fcs == fcs_calc);
    }
  }

  if (tree)
  {
    guint offset;
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_tosam, tvb, 0, -1, FALSE);
    tosam_tree = proto_item_add_subtree(ti, ett_tosam);

    /* add items to the subtree */
    ieee802145_tvb = tvb_new_subset(tvb, 0, TOSAM_IEEE_HEADER_LEN, -1);

    DISSECTOR_ASSERT(ieee802154_handle);
    call_dissector(ieee802154_handle, ieee802145_tvb, pinfo, tosam_tree);
    proto_tree_add_item(tosam_tree, hf_tosam_id, tvb, TOSAM_HEADER_ID_OFFSET,
        TOSAM_HEADER_ID_LEN, FALSE);
    proto_tree_add_item(tosam_tree, hf_tosam_type, tvb,
        TOSAM_HEADER_TYPE_OFFSET, TOSAM_HEADER_TYPE_LEN, FALSE);

    offset = tvb_reported_length(tvb) - IEEE802154_FCS_LEN;

    /* The FCS should be the last bytes of the reported packet. */
    /* Dissect the FCS only if it exists (captures which don't or can't get the
     * FCS will simply truncate the packet to omit it, but should still set the
     * reported length to cover the original packet length), so if the snapshot
     * is too short for an FCS don't make a fuss.
     */
    if (tvb_bytes_exist(tvb, offset, IEEE802154_FCS_LEN) && (tree))
    {
      proto_tree *field_tree;
      guint16 fcs = tvb_get_letohs(tvb, offset);

      /* Display the FCS depending on expected FCS format */
      if (tosam_cc24xx)
      {
        /* Create a subtree for the FCS. */
        ti = proto_tree_add_text(tosam_tree, tvb, offset, 2,
            "Frame Check Sequence (TI CC24xx format): FCS %s",
            (fcs_ok) ? "OK" : "Bad");
        field_tree = proto_item_add_subtree(ti, ett_ieee802154_fcs);
        /* Display FCS contents.  */
        ti = proto_tree_add_int(field_tree, hf_ieee802154_rssi, tvb, offset++,
            1, (gint8)(fcs & IEEE802154_CC24xx_RSSI));
        proto_item_append_text(ti, " dBm"); /*  Displaying Units */
        proto_tree_add_boolean(field_tree, hf_ieee802154_fcs_ok, tvb, offset, 1,
            (gboolean) (fcs & IEEE802154_CC24xx_CRC_OK));
        proto_tree_add_uint(field_tree, hf_ieee802154_correlation, tvb, offset,
            1, (guint8)((fcs & IEEE802154_CC24xx_CORRELATION) >> 8));
      }
      else
      {
        ti = proto_tree_add_uint(tosam_tree, hf_ieee802154_fcs, tvb, offset, 2,
            fcs);
        if (fcs_ok)
        {
          proto_item_append_text(ti, " (Correct)");
        }
        else
        {
          proto_item_append_text(ti, " (Incorrect, expected FCS=0x%04x",
              ieee802154_crc_tvb(tvb, offset));
        }
        /* To Help with filtering, add the fcs_ok field to the tree.  */
        ti = proto_tree_add_boolean(tosam_tree, hf_ieee802154_fcs_ok, tvb,
            offset, 2, fcs_ok);
        PROTO_ITEM_SET_HIDDEN(ti);
      }
    }
    else
    {
      /* Even if the FCS isn't present, add the fcs_ok field to the tree to
       * help with filter. Be sure not to make it visible though.
       */
      ti = proto_tree_add_boolean(tosam_tree, hf_ieee802154_fcs_ok, tvb, offset,
          2, fcs_ok);
      PROTO_ITEM_SET_HIDDEN(ti);
    }
  }
  /* If the CRC is invalid, make a note of it in the info column. */
  if (!fcs_ok)
  {
    col_append_str(pinfo->cinfo, COL_INFO, ", Bad FCS");
    if (tree)
      proto_item_append_text(tosam_tree, ", Bad FCS");

    /* Flag packet as having a bad crc. */
    expert_add_info_format(pinfo, tosam_tree, PI_CHECKSUM, PI_WARN,
        "Bad FCS");
  }

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOS AM");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "AM: 0x%02x, ", am_type);

  /* Calculate the available data in the packet,
   set this to -1 to use all the data in the tv_buffer */
  available_length = tvb_length(tvb) - TOSAM_HEADER_LEN - IEEE802154_FCS_LEN;

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, TOSAM_HEADER_LEN, available_length, -1);

  /* call the next dissector */

  if (dissector_try_uint(tosam_type_dissector_table, am_type, next_tvb, pinfo, tree)) {
    return;
  }
  call_dissector(data_handle, next_tvb, pinfo, tree);
  return;
}

/* Register the protocol with Wireshark */
void
proto_register_tosam(void)
{
  /* TinyOS2 Active Message Header */
  static hf_register_info hf[] =
  {
  { &hf_tosam_id,
  { "Id", "tosam.id", FT_UINT8, BASE_HEX, NULL, 0x0, "Unique Dispatch Id", HFILL } },
  { &hf_tosam_type,
  { "Type", "tosam.type", FT_UINT8, BASE_HEX, NULL, 0x0, "Active Message Type", HFILL } },
  { &hf_ieee802154_fcs,
  { "FCS", "tosam.fcs", FT_UINT16, BASE_HEX, NULL, 0x0, "Frame Check Sequence", HFILL } },
  { &hf_ieee802154_rssi,
  { "RSSI", "tosam.rssi", FT_INT8, BASE_DEC, NULL, 0x0, "Received Signal Strength", HFILL } },
  { &hf_ieee802154_fcs_ok,
  { "FCS Valid", "tosam.fcs_ok", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
  { &hf_ieee802154_correlation,
  { "LQI Correlation Value", "tosam.correlation", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_tosam, &ett_ieee802154_fcs };

  /* Preferences. */
  module_t *tosam_module;

  /* Register the protocol name and description */
  proto_tosam = proto_register_protocol("TinyOS AM Frame", "TOS AM", "tosam");

  tosam_module = prefs_register_protocol(proto_tosam, proto_reg_handoff_tosam);

  prefs_register_bool_preference(tosam_module, "802154_cc24xx",
      "TI CC24xx FCS format", "Set if the FCS field is in TI CC24xx format.",
      &tosam_cc24xx);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_tosam, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  tosam_type_dissector_table = register_dissector_table("tosam.type",
      "TOS AM type", FT_UINT8, BASE_HEX);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 This exact format is required because a script is used to find these routines
 and create the code that calls these routines.

 This function is also called by preferences whenever "Apply" is pressed
 (see prefs_register_protocol above) so it should accommodate being called
 more than once.
 */
void
proto_reg_handoff_tosam(void)
{
  static dissector_handle_t tosam_handle;
  static gboolean inited = FALSE;

  if (!inited)
  {
    tosam_handle = create_dissector_handle(dissect_tosam, proto_tosam);
    dissector_add_uint("udp.port", 54321, tosam_handle);
    inited = TRUE;
  }
  else
  {
    dissector_delete_uint("udp.port", 54321, tosam_handle);
  }

  dissector_add_uint("udp.port", 54321, tosam_handle);
  ieee802154_handle = find_dissector("wpan");
  data_handle = find_dissector("data");
}
