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
#include "packet-tos.h"
#include <epan/dissectors/packet-ieee802154.h>
#include <epan/crc16-tvb.h>
#include <epan/expert.h>
#include <epan/conversation.h>

#define TOS_DISPATCH_ID 0x3f

/* Forward declaration we need below */
void
proto_reg_handoff_tos(void);

/* for subdissectors */
static dissector_table_t tos_amid_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_tos = -1;
static int hf_tos_id = -1;
static int hf_tos_type = -1;

/* Initialize the subtree pointers */
static gint ett_tos = -1;

static gboolean
dissect_tos_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

  tvbuff_t *next_tvb;
  guint8 am_id, d_id;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *tos_tree;

  /* check if this is big enough to be AM. */
  if (tvb_length(tvb) < TOS_HEADER_LEN)
  {
    return FALSE;
  }

  /* check the dispatch id */
  d_id = tvb_get_guint8(tvb, 0);
  if (d_id != TOS_DISPATCH_ID)
  {
    return FALSE;
  }

  am_id = tvb_get_guint8(tvb, 1);
  if (tree)
  {
    guint offset;
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_tos, tvb, 0, -1, FALSE);
    tos_tree = proto_item_add_subtree(ti, ett_tos);

    /* add items to the subtree */
    offset = 0;
    proto_tree_add_item(tos_tree, hf_tos_id, tvb, offset,
        TOS_HEADER_ID_LEN, FALSE);
    offset += TOS_HEADER_ID_LEN;
    proto_tree_add_item(tos_tree, hf_tos_type, tvb,
        offset, TOS_HEADER_TYPE_LEN, FALSE);
    offset += 1;
  }

/* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOS AM");
  col_prepend_fstr(pinfo->cinfo, COL_INFO, "AMId: 0x%02x, ", am_id);

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, TOS_HEADER_LEN, -1, -1);

  /* call the next dissector, if no subdissector found just ignore it*/
  if (dissector_try_uint(tos_amid_dissector_table, am_id, next_tvb, pinfo, tree)) {
    return TRUE;
  }

  return FALSE;
}

/* Register the protocol with Wireshark */
void
proto_register_tos(void)
{
  /* TinyOS2 Active Message Header */
  static hf_register_info hf[] =
  {
  { &hf_tos_id,
  { "Udid", "tos.udid", FT_UINT8, BASE_HEX, NULL, 0x0, "Unique Dispatch Id", HFILL } },
  { &hf_tos_type,
  { "Type", "tos.amid", FT_UINT8, BASE_HEX, NULL, 0x0, "Active Message Type", HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_tos };

  /* Register the protocol name and description */
  proto_tos = proto_register_protocol("TinyOS AM Frame", "TOS AM", "tos");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_tos, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  tos_amid_dissector_table = register_dissector_table("tos.amid",
      "TOS AM ID", FT_UINT8, BASE_HEX);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 This exact format is required because a script is used to find these routines
 and create the code that calls these routines.

 This function is also called by preferences whenever "Apply" is pressed
 (see prefs_register_protocol above) so it should accommodate being called
 more than once.
 */
void
proto_reg_handoff_tos(void)
{
  static gboolean inited = FALSE;

  if (!inited)
  {
    inited = TRUE;
  }
  else
  {
    heur_dissector_delete(IEEE802154_PROTOABBREV_WPAN, dissect_tos_heur, proto_tos);
  }

  heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_tos_heur, proto_tos);
}
