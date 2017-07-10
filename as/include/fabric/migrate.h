/*
 * migrate.h
 *
 * Copyright (C) 2008-2014 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

#pragma once

//==========================================================
// Includes.
//

#include <stdbool.h>
#include <stdint.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_queue.h"
#include "citrusleaf/cf_rchash.h"

#include "msg.h"
#include "node.h"
#include "shash.h"

#include "fabric/hb.h"
#include "fabric/partition.h"


//==========================================================
// Forward declarations.
//

struct as_index_ref_s;
struct as_namespace_s;


//==========================================================
// Typedefs & constants.
//

// For receiver-side migration flow-control.
// TODO - move to namespace? Go even lower than 4?
#define AS_MIGRATE_DEFAULT_MAX_NUM_INCOMING 4
#define AS_MIGRATE_LIMIT_MAX_NUM_INCOMING 64

// Maximum permissible number of migrate xmit threads.
#define MAX_NUM_MIGRATE_XMIT_THREADS 100

typedef enum {
	EMIG_TYPE_TRANSFER,
	EMIG_TYPE_SIGNAL_ALL_DONE
} emig_type;

#define TX_FLAGS_NONE           ((uint32_t) 0x0)
#define TX_FLAGS_ACTING_MASTER  ((uint32_t) 0x1)

// A data structure for temporarily en-queuing partition migrations.
typedef struct partition_migrate_record_s {
	cf_node dest;
	struct as_namespace_s *ns;
	uint32_t pid;
	uint64_t cluster_key;
	emig_type type;
	uint32_t tx_flags;
} partition_migrate_record;


//==========================================================
// Public API.
//

void as_migrate_init();
void as_migrate_emigrate(const partition_migrate_record *pmr);
void as_migrate_set_num_xmit_threads(uint32_t n_threads);
void as_migrate_dump(bool verbose);


//==========================================================
// Private API - for enterprise separation only.
//

typedef enum {
	// These values go on the wire, so mind backward compatibility if changing.
	MIG_FIELD_OP,
	MIG_FIELD_UNUSED_1,
	MIG_FIELD_EMIG_ID,
	MIG_FIELD_NAMESPACE,
	MIG_FIELD_PARTITION,
	MIG_FIELD_DIGEST,
	MIG_FIELD_GENERATION,
	MIG_FIELD_RECORD,
	MIG_FIELD_CLUSTER_KEY,
	MIG_FIELD_UNUSED_9,
	MIG_FIELD_VOID_TIME,
	MIG_FIELD_UNUSED_11,
	MIG_FIELD_UNUSED_12,
	MIG_FIELD_INFO,
	MIG_FIELD_UNUSED_14,
	MIG_FIELD_UNUSED_15,
	MIG_FIELD_UNUSED_16,
	MIG_FIELD_UNUSED_17,
	MIG_FIELD_UNUSED_18,
	MIG_FIELD_LAST_UPDATE_TIME,
	MIG_FIELD_FEATURES,
	MIG_FIELD_UNUSED_21,
	MIG_FIELD_META_RECORDS,
	MIG_FIELD_META_SEQUENCE,
	MIG_FIELD_META_SEQUENCE_FINAL,
	MIG_FIELD_PARTITION_SIZE,
	MIG_FIELD_SET_NAME,
	MIG_FIELD_KEY,
	MIG_FIELD_UNUSED_28,
	MIG_FIELD_EMIG_INSERT_ID,

	NUM_MIG_FIELDS
} migrate_msg_fields;

#define OPERATION_UNDEF 0
#define OPERATION_INSERT 1
#define OPERATION_INSERT_ACK 2
#define OPERATION_START 3
#define OPERATION_START_ACK_OK 4
#define OPERATION_START_ACK_EAGAIN 5
#define OPERATION_START_ACK_FAIL 6
#define OPERATION_UNUSED_7 7 // deprecated
#define OPERATION_DONE 8
#define OPERATION_DONE_ACK 9
#define OPERATION_UNUSED_10 10 // deprecated
#define OPERATION_MERGE_META 11
#define OPERATION_MERGE_META_ACK 12
#define OPERATION_ALL_DONE 13
#define OPERATION_ALL_DONE_ACK 14

#define MIG_INFO_UNUSED_1   0x0001
#define MIG_INFO_UNUSED_2   0x0002
#define MIG_INFO_UNUSED_4   0x0004
#define MIG_INFO_TOMBSTONE  0x0008 // enterprise only

#define MIG_FEATURE_MERGE 0x00000001U
#define MIG_FEATURES_SEEN 0x80000000U // needed for backward compatibility
extern const uint32_t MY_MIG_FEATURES;

typedef struct meta_record_s {
	cf_digest keyd;
	uint16_t generation;
	uint64_t last_update_time: 40;
} __attribute__ ((__packed__)) meta_record;

typedef struct meta_batch_s {
	bool is_final;
	uint32_t n_records;
	meta_record *records;
} meta_batch;

typedef struct emig_meta_q_s {
	uint32_t current_rec_i;
	meta_batch current_batch;
	cf_queue *batch_q;
	cf_atomic32 last_acked;
	bool is_done;
} emig_meta_q;

typedef struct emigration_s {
	cf_node     dest;
	uint64_t    cluster_key;
	uint32_t    id;
	emig_type	type;
	uint32_t    tx_flags;
	cf_atomic32 state;
	bool        aborted;

	cf_atomic32 bytes_emigrating;
	cf_shash    *reinsert_hash;
	uint64_t    insert_id;
	cf_queue    *ctrl_q;
	emig_meta_q *meta_q;

	as_partition_reservation rsv;
} emigration;

typedef struct immig_meta_q_s {
	meta_batch current_batch;
	cf_queue *batch_q;
	uint32_t sequence;
	cf_atomic32 last_acked;
} immig_meta_q;

typedef struct immigration_s {
	cf_node          src;
	uint64_t         cluster_key;
	uint32_t         pid;

	cf_atomic32      done_recv;      // flag - 0 if not yet received, atomic counter for receives
	uint64_t         start_recv_ms;  // time the first START event was received
	uint64_t         done_recv_ms;   // time the first DONE event was received

	uint32_t         emig_id;
	immig_meta_q     meta_q;

	as_migrate_result start_result;
	uint32_t        features;
	struct as_namespace_s *ns; // for statistics only

	as_partition_reservation rsv;
} immigration;

typedef struct immigration_hkey_s {
	cf_node src;
	uint32_t emig_id;
} __attribute__((__packed__)) immigration_hkey;


// Globals.
extern cf_rchash *g_emigration_hash;
extern cf_rchash *g_immigration_hash;


// Emigration, immigration, & pickled record destructors.
void emigration_release(emigration *emig);
void immigration_release(immigration *immig);

// Emigration.
bool should_emigrate_record(emigration *emig, struct as_index_ref_s *r_ref);
void emigration_flag_pickle(const uint8_t *buf, uint32_t *info);

// Emigration meta queue.
emig_meta_q *emig_meta_q_create();
void emig_meta_q_destroy(emig_meta_q *emq);

// Migrate fabric message handling.
void emigration_handle_meta_batch_request(cf_node src, msg *m);
bool immigration_ignore_pickle(const uint8_t *buf, const msg *m);
void immigration_handle_meta_batch_ack(cf_node src, msg *m);

// Meta sender.
bool immigration_start_meta_sender(immigration *immig, uint32_t emig_features, uint64_t emig_n_recs);

// Immigration meta queue.
void immig_meta_q_init(immig_meta_q *imq);
void immig_meta_q_destroy(immig_meta_q *imq);
