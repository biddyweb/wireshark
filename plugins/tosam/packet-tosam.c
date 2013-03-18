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
#include <epan/conversation.h>

/* Forward declaration we need below */
void
proto_reg_handoff_tosam(void);

/* for subdissectors */
static dissector_handle_t data_handle;
static dissector_handle_t tosam_handle;
static dissector_table_t tosam_type_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_tosam = -1;
static int hf_tosam_id = -1;
static int hf_tosam_type = -1;

/* Initialize the subtree pointers */
static gint ett_tosam = -1;

static gboolean
dissect_tosam_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  conversation_t *conversation;

  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector(conversation, tosam_handle);

  /*   and do the dissection */
  dissect_tosam(tvb, pinfo, tree);

  data = data;
  return TRUE;
}

/* Code to actually dissect the packets */
static void
dissect_tosam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;
  guint8 am_type;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *tosam_tree;

  /* check if this is really a complete AM. If not call sub dissector. */
  if (tvb_length(tvb) < TOSAM_HEADER_LEN)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  am_type = tvb_get_guint8(tvb, 1);

  if (tree)
  {
    guint offset;
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_tosam, tvb, 0, -1, FALSE);
    tosam_tree = proto_item_add_subtree(ti, ett_tosam);

    /* add items to the subtree */
    offset = 0;
    proto_tree_add_item(tosam_tree, hf_tosam_id, tvb, offset,
        TOSAM_HEADER_ID_LEN, FALSE);
    offset += TOSAM_HEADER_ID_LEN;
    proto_tree_add_item(tosam_tree, hf_tosam_type, tvb,
        offset, TOSAM_HEADER_TYPE_LEN, FALSE);
    offset += 1;
  }

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOS AM");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "AM: 0x%02x, ", am_type);

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, TOSAM_HEADER_LEN, -1, -1);

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
  { "Type", "tosam.type", FT_UINT8, BASE_HEX, NULL, 0x0, "Active Message Type", HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_tosam };

  /* Register the protocol name and description */
  proto_tosam = proto_register_protocol("TinyOS AM Frame", "TOS AM", "tosam");

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
  static gboolean inited = FALSE;

  if (!inited)
  {
    tosam_handle = create_dissector_handle(dissect_tosam, proto_tosam);
    data_handle = find_dissector("data");
    inited = TRUE;
  }
  else
  {
    heur_dissector_delete(IEEE802154_PROTOABBREV_WPAN, dissect_tosam_heur, proto_tosam);
  }

  heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_tosam_heur, proto_tosam);
}
