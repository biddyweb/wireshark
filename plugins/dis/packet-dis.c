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
#include "packet-dis.h"

/* Forward declaration we need below */
void
proto_reg_handoff_dis(void);

/* for subdissectors */
static dissector_handle_t data_handle;
static dissector_table_t tosam_type_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_dis = -1;
static int hf_dis_key = -1;
static int hf_dis_seqno = -1;

/* Initialize the subtree pointers */
static gint ett_dis = -1;

/* Code to actually dissect the packets */
static void
dissect_dis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb = tvb;
  guint16 am_type;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *dis_tree;

  /* check if this is really a complete AM. If not call sub dissector. */
  if (tvb_length(tvb) < TOS_DIS_HEADER_LEN)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  am_type = tvb_get_guint8(tvb, DIS_KEY_OFFSET);

  if (tree)
  {
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dis, tvb, 0, -1, FALSE);
    proto_item_append_text(ti, " (Data)");
    dis_tree = proto_item_add_subtree(ti, ett_dis);
    proto_tree_add_item(dis_tree, hf_dis_key, tvb, DIS_KEY_OFFSET, DIS_KEY_LEN, FALSE);
    proto_tree_add_item(dis_tree, hf_dis_seqno, tvb, DIS_SEQNO_OFFSET, DIS_SEQNO_LEN, FALSE);
  }

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOS Dissemination Data");

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, TOS_DIS_HEADER_LEN,
      tvb_length(tvb) - TOS_DIS_HEADER_LEN, tvb_length(tvb) - TOS_DIS_HEADER_LEN);

  if (dissector_try_uint(tosam_type_dissector_table, am_type, next_tvb, pinfo, tree)) {
    return;
  }

  call_dissector(data_handle, next_tvb, pinfo, tree);
  return;
}

/* Register the protocol with Wireshark */
void
proto_register_dis(void)
{
  /* TinyOS2 Active Message Header */
  static hf_register_info hf[] =
  {
  { &hf_dis_key,
  { "Key", "dis.key", FT_UINT16, BASE_HEX, NULL, 0x0, "Dispatch Key (AM Type)", HFILL } },
  { &hf_dis_seqno,
  { "Seqno", "dis.seqno", FT_UINT32, BASE_DEC, NULL, 0x0, "Seqno", HFILL } }};

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_dis };

  /* Register the protocol name and description */
  proto_dis = proto_register_protocol("TinyOS Dissemination", "Dissemination", "dissem");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_dis, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  tosam_type_dissector_table = find_dissector_table("tos.amid");
}

/* If this dissector uses sub-dissector registration add a registration routine.
 This exact format is required because a script is used to find these routines
 and create the code that calls these routines.

 This function is also called by preferences whenever "Apply" is pressed
 (see prefs_register_protocol above) so it should accommodate being called
 more than once.
 */
void
proto_reg_handoff_dis(void)
{
  static dissector_handle_t dis_handle;
  static gboolean inited = FALSE;

  if (!inited)
  {
    dis_handle = create_dissector_handle(dissect_dis, proto_dis);
    data_handle = find_dissector("data");
    inited = TRUE;
  }
  else
  {
    dissector_delete_uint("tos.amid", 0x60, dis_handle);
  }
  dissector_add_uint("tos.amid", 0x60, dis_handle);
}
