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
static int hf_ctp_options = -1;
static int hf_ctp_options_pull = -1;
static int hf_ctp_options_con = -1;
static int hf_ctp_options_stats = -1;
static int hf_ctp_thl = -1;
static int hf_ctp_etx = -1;
static int hf_ctp_origin = -1;
static int hf_ctp_seqno = -1;
static int hf_ctp_collect_id = -1;
static int hf_ctp_parent = -1;
static int hf_ctp_stats = -1;

static int hf_ctp_stats_size = -1;
static int hf_ctp_stats_num = -1;
static int hf_ctp_stats_node_id = -1;
static int hf_ctp_stats_tx_power = -1;
static int hf_ctp_stats_tx_retry = -1;
static int hf_ctp_stats_tx_busy_channel = -1;
static int hf_ctp_stats_rx_ed = -1;
static int hf_ctp_stats_rx_lqi = -1;
static int hf_ctp_stats_reserved = -1;

/* Initialize the subtree pointers */
static gint ett_ctp = -1;
static gint ett_ctp_options = -1;
static gint ett_ctp_stats = -1;
static gint ett_ctp_stats_nodes = -1;

static guint
dissect_ctp_options(tvbuff_t *tvb, guint offset, proto_tree *tree, gboolean include_stats)
{
  proto_tree *field_tree = NULL;
  guint8 options;
  proto_item *tf;

  options = tvb_get_guint8(tvb, offset);
  tf = proto_tree_add_uint(tree, hf_ctp_options, tvb, offset, CTP_OPTIONS_LEN, options);
  field_tree = proto_item_add_subtree(tf, ett_ctp_options);

  proto_tree_add_bits_item(field_tree, hf_ctp_options_pull, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(field_tree, hf_ctp_options_con, tvb, 1, 1, ENC_BIG_ENDIAN);
  if (include_stats)
    proto_tree_add_bits_item(field_tree, hf_ctp_options_stats, tvb, 7, 1, ENC_BIG_ENDIAN);
  return CTP_OPTIONS_LEN;
}

static int
dissect_ctp_stats(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *stats_tree;
  guint8 size, num;
  static int *node_field_info[] = {
    &hf_ctp_stats_tx_power,
    &hf_ctp_stats_tx_retry,
    &hf_ctp_stats_tx_busy_channel,
    &hf_ctp_stats_rx_ed,
    &hf_ctp_stats_rx_lqi,
    &hf_ctp_stats_reserved,
  };

  size = tvb_get_guint8(tvb, offset);
  ti = proto_tree_add_item(tree, hf_ctp_stats, tvb, offset, size, ENC_BIG_ENDIAN);
  stats_tree = proto_item_add_subtree(ti, ett_ctp_stats);
  proto_tree_add_item(stats_tree, hf_ctp_stats_size, tvb, offset, CTP_STATS_SIZE_LEN, ENC_BIG_ENDIAN);
  offset += CTP_STATS_SIZE_LEN;

  num = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(stats_tree, hf_ctp_stats_num, tvb, offset, CTP_STATS_NUM_LEN, ENC_BIG_ENDIAN);
  offset += CTP_STATS_NUM_LEN;

  for (int i = 0; i <= num; i++)
  {
    proto_item *_ti = proto_tree_add_item(stats_tree, hf_ctp_stats_node_id, tvb, offset, CTP_STATS_NODE_FIELD_LEN, ENC_BIG_ENDIAN);
    offset += CTP_STATS_NODE_FIELD_LEN;
    proto_tree *node_tree = proto_item_add_subtree(_ti, ett_ctp_stats_nodes);
    for (int j = 0; j < (int)G_N_ELEMENTS(node_field_info); j++)
    {
      proto_tree_add_item(node_tree, *(node_field_info[j]), tvb, offset, CTP_STATS_NODE_FIELD_LEN, ENC_BIG_ENDIAN);
      offset += CTP_STATS_NODE_FIELD_LEN;
    }
  }
  return size;
}

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
    offset += dissect_ctp_options(tvb, offset, ctp_tree, FALSE);
    offset += CTP_OPTIONS_LEN;
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
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *ctp_tree;
  guint offset = 0;

  if (tvb_length(tvb) < CTP_DATA_STATS_OFFSET)
  {
    call_dissector(data_handle, tvb, pinfo, tree);
    return;
  }

  if (tree)
  {
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_ctp, tvb, 0, -1, FALSE);
    proto_item_append_text(ti, " (Data)");
    ctp_tree = proto_item_add_subtree(ti, ett_ctp);
    offset += dissect_ctp_options(tvb, offset, ctp_tree, TRUE);
    proto_tree_add_item(ctp_tree, hf_ctp_thl, tvb, offset, CTP_THL_LEN, FALSE);
    offset += CTP_THL_LEN;
    proto_tree_add_item(ctp_tree, hf_ctp_etx, tvb, offset, CTP_ETX_LEN, FALSE);
    offset += CTP_ETX_LEN;
    proto_tree_add_item(ctp_tree, hf_ctp_origin, tvb, offset, CTP_ORIGIN_LEN, FALSE);
    offset += CTP_ORIGIN_LEN;
    proto_tree_add_item(ctp_tree, hf_ctp_seqno, tvb, offset, CTP_SEQNO_LEN, FALSE);
    offset += CTP_SEQNO_LEN;
    proto_tree_add_item(ctp_tree, hf_ctp_collect_id, tvb, offset, CTP_COLLECT_ID_LEN, FALSE);
    offset += CTP_COLLECT_ID_LEN;
    if (CTP_STATS_FLAG & tvb_get_guint8(tvb, CTP_OPTIONS_OFFSET))
    {
      offset += dissect_ctp_stats(tvb, offset, ctp_tree);
    }
  }

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTP Data");

  /* Create the tvbuffer for the next dissector */
  next_tvb = tvb_new_subset(tvb, offset,
                            tvb_length(tvb) - offset, tvb_length(tvb) - offset);

  if (tos_type_dissector_table &&
      dissector_try_uint(tos_type_dissector_table,
                         tvb_get_guint8(tvb, CTP_DATA_COLLECT_ID_OFFSET),
                         next_tvb, pinfo, tree)) {
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
    { &hf_ctp_options,
      { "Ctp Options", "ctp.options", FT_UINT8, BASE_HEX,
        NULL, 0, "Ctp Options", HFILL }
    },
    { &hf_ctp_options_pull,
      { "Routing Pull", "ctp.options.pull", FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0, NULL, HFILL }
    },
    { &hf_ctp_options_con,
      { "Congestion Notification", "ctp.options.con", FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0, NULL, HFILL }
    },
    { &hf_ctp_options_stats,
      { "Path Information", "ctp.options.stats", FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0, NULL, HFILL }
    },
    { &hf_ctp_thl,
      { "THL", "ctp.thl", FT_UINT8, BASE_DEC, NULL, 0x0, "Time Has Lived", HFILL }
    },
    { &hf_ctp_etx,
      { "ETX", "ctp.etx", FT_UINT16, BASE_DEC, NULL, 0x0, "Expected Transmission", HFILL }
    },
    { &hf_ctp_origin,
      { "Origin", "ctp.origin", FT_UINT16, BASE_HEX, NULL, 0x0, "Origin", HFILL }
    },
    { &hf_ctp_seqno,
      { "Seqno", "ctp.seqno", FT_UINT8, BASE_DEC, NULL, 0x0, "Seqno", HFILL }
    },
    { &hf_ctp_collect_id,
      { "Collect Id", "ctp.collect_id", FT_UINT8, BASE_HEX, NULL, 0x0, "Collect Id (AM Type)", HFILL }
    },
    { &hf_ctp_parent,
      { "Parent", "ctp.parent", FT_UINT16, BASE_HEX, NULL, 0x0, "Current Parent", HFILL }
    },
    { &hf_ctp_stats,
      { "Path Info", "ctp.stats", FT_PROTOCOL, BASE_NONE, NULL, 0x0, "Packet Path Information", HFILL }
    },

    { &hf_ctp_stats_size,
      { "Size", "ctp.stats.size", FT_UINT8, BASE_DEC, NULL, 0x0, "Total Size", HFILL }
    },
    { &hf_ctp_stats_num,
      { "Current Index", "ctp.stats.num", FT_UINT8, BASE_DEC, NULL, 0x0, "Current Index", HFILL }
    },
    { &hf_ctp_stats_node_id,
      { "Node Id", "ctp.stats.node.id", FT_UINT8, BASE_DEC, NULL, 0x0, "Node Id", HFILL }
    },
    { &hf_ctp_stats_tx_retry,
      { "Tx Retry", "ctp.stats.tx.retry", FT_UINT8, BASE_DEC, NULL, 0x0, "Number of Tx Retries", HFILL }
    },
    { &hf_ctp_stats_tx_power,
      { "Tx Power", "ctp.stats.tx.power", FT_UINT8, BASE_HEX, NULL, 0x0, "Tx Power", HFILL }
    },
    { &hf_ctp_stats_tx_busy_channel,
      { "Tx Busy Channel", "ctp.stats.tx.busy_channel", FT_UINT8, BASE_DEC, NULL, 0x0, "Number of Tx Busy Channels", HFILL }
    },
    { &hf_ctp_stats_rx_lqi,
      { "Rx LQI", "ctp.stats.rx.lqi", FT_UINT8, BASE_HEX, NULL, 0x0, "Link Quality Indicator", HFILL }
    },
    { &hf_ctp_stats_rx_ed,
      { "Rx ED", "ctp.stats.rx.ed", FT_UINT8, BASE_HEX, NULL, 0x0, "Rx Power", HFILL }
    },
    { &hf_ctp_stats_reserved,
      { "Reserved", "ctp.stats.reserved", FT_NONE, BASE_NONE, NULL, 0x0, "Reserved", HFILL }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_ctp, &ett_ctp_options, &ett_ctp_stats, &ett_ctp_stats_nodes };

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
    inited = TRUE;
  }
  else
  {
    dissector_delete_uint("tos.amid", 0x70, ctp_routing_handle);
    dissector_delete_uint("tos.amid", 0x71, ctp_data_handle);
  }

  data_handle = find_dissector("data");
  tos_type_dissector_table = find_dissector_table("tos.amid");

  dissector_add_uint("tos.amid", 0x70, ctp_routing_handle);
  dissector_add_uint("tos.amid", 0x71, ctp_data_handle);
}
