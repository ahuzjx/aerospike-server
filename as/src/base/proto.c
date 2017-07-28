/*
 * proto.c
 *
 * Copyright (C) 2008-2015 Aerospike, Inc.
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

//==========================================================
// Includes.
//

#include "base/proto.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "aerospike/as_val.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_byte_order.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_vector.h"

#include "dynbuf.h"
#include "fault.h"
#include "socket.h"

#include "base/as_stap.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "base/thr_tsvc.h"
#include "base/transaction.h"
#include "storage/storage.h"


//==========================================================
// Typedefs & constants.
//

#define MSG_STACK_BUFFER_SZ (1024 * 16)
#define NETIO_MAX_IO_RETRY 5


//==========================================================
// Globals.
//

static cf_queue g_netio_queue;
static cf_queue g_netio_slow_queue;


//==========================================================
// Forward declarations.
//

static int send_reply_buf(as_file_handle *fd_h, uint8_t *msgp, size_t msg_sz);
void *run_netio(void *q_to_wait_on);
int netio_send_packet(as_file_handle *fd_h, cf_buf_builder *bb_r, uint32_t *offset, bool blocking);


//==========================================================
// Public API - byte swapping.
//

void
as_proto_swap(as_proto *p)
{
	uint8_t version = p->version;
	uint8_t type = p->type;

	p->version = p->type = 0;
	p->sz = cf_swap_from_be64(*(uint64_t *)p);
	p->version = version;
	p->type = type;
}


void
as_msg_swap_header(as_msg *m)
{
	m->generation = cf_swap_from_be32(m->generation);
	m->record_ttl = cf_swap_from_be32(m->record_ttl);
	m->transaction_ttl = cf_swap_from_be32(m->transaction_ttl);
	m->n_fields = cf_swap_from_be16(m->n_fields);
	m->n_ops = cf_swap_from_be16(m->n_ops);
}


void
as_msg_swap_field(as_msg_field *mf)
{
	mf->field_sz = cf_swap_from_be32(mf->field_sz);
}


void
as_msg_swap_op(as_msg_op *op)
{
	op->op_sz = cf_swap_from_be32(op->op_sz);
}


//==========================================================
// Public API - generating internal transactions.
//

// This writes an host-ordered header, which is what we want.
uint8_t *
as_msg_write_header(uint8_t *buf, size_t msg_sz, uint8_t info1, uint8_t info2,
		uint8_t info3, uint32_t generation, uint32_t record_ttl,
		uint32_t transaction_ttl, uint32_t n_fields, uint32_t n_ops)
{
	cl_msg *msg = (cl_msg *)buf;

	msg->proto.version = PROTO_VERSION;
	msg->proto.type = PROTO_TYPE_AS_MSG;
	msg->proto.sz = msg_sz - sizeof(as_proto);
	msg->msg.header_sz = sizeof(as_msg);
	msg->msg.info1 = info1;
	msg->msg.info2 = info2;
	msg->msg.info3 = info3;
	msg->msg.unused = 0;
	msg->msg.result_code = 0;
	msg->msg.generation = generation;
	msg->msg.record_ttl = record_ttl;
	msg->msg.transaction_ttl = transaction_ttl;
	msg->msg.n_fields = n_fields;
	msg->msg.n_ops = n_ops;

	return buf + sizeof(cl_msg);
}


// This writes host-ordered fields, which is what we want.
uint8_t *
as_msg_write_fields(uint8_t *buf, const char *ns_name, size_t ns_name_len,
		const char *set_name, size_t set_name_len, const cf_digest *d,
		uint64_t trid)
{
	as_msg_field *mf = (as_msg_field *)buf;

	if (ns_name) {
		mf->type = AS_MSG_FIELD_TYPE_NAMESPACE;
		mf->field_sz = (uint32_t)ns_name_len + 1;
		memcpy(mf->data, ns_name, ns_name_len);
		mf = as_msg_field_get_next(mf);
	}

	// Not currently used, but it's plausible we'll do so in future.
	if (set_name && set_name_len != 0) {
		mf->type = AS_MSG_FIELD_TYPE_SET;
		mf->field_sz = (uint32_t)set_name_len + 1;
		memcpy(mf->data, set_name, set_name_len);
		mf = as_msg_field_get_next(mf);
	}

	// Not currently used, but it's plausible we'll do so in future.
	if (trid) {
		mf->type = AS_MSG_FIELD_TYPE_TRID;
		mf->field_sz = sizeof(trid) + 1;
		memcpy(mf->data, &trid, sizeof(trid));
		mf = as_msg_field_get_next(mf);
	}

	if (d) {
		mf->type = AS_MSG_FIELD_TYPE_DIGEST_RIPE;
		mf->field_sz = sizeof(cf_digest) + 1;
		memcpy(mf->data, d, sizeof(cf_digest));
		mf = as_msg_field_get_next(mf);
	}

	return (uint8_t *)mf;
}


//==========================================================
// Public API - packing responses.
//

// Allocates cl_msg returned - caller must free it.
cl_msg *
as_msg_make_response_msg(uint32_t result_code, uint32_t generation,
		uint32_t void_time, as_msg_op **ops, as_bin **bins, uint16_t bin_count,
		as_namespace *ns, cl_msg *msgp_in, size_t *msg_sz_in, uint64_t trid,
		const char *set_name)
{
	size_t msg_sz = sizeof(cl_msg);

	msg_sz += sizeof(as_msg_op) * bin_count;

	for (uint16_t i = 0; i < bin_count; i++) {
		if (ops) {
			msg_sz += ops[i]->name_sz;
		}
		else if (bins[i]) {
			msg_sz += ns->single_bin ?
					0 : strlen(as_bin_get_name_from_id(ns, bins[i]->id));
		}
		else {
			cf_crash(AS_PROTO, "making response message with null bin and op");
		}

		if (bins[i]) {
			msg_sz += as_bin_particle_client_value_size(bins[i]);
		}
	}

	if (trid != 0) {
		msg_sz += sizeof(as_msg_field) + sizeof(trid);
	}

	uint32_t set_name_len = 0;

	if (set_name) {
		set_name_len = strlen(set_name);
		msg_sz += sizeof(as_msg_field) + set_name_len;
	}

	uint8_t *buf;

	if (! msgp_in || *msg_sz_in < msg_sz) {
		buf = cf_malloc(msg_sz);
		cf_assert(buf, AS_PROTO, "alloc failed");
	}
	else {
		buf = (uint8_t *)msgp_in;
	}

	*msg_sz_in = msg_sz;

	cl_msg *msgp = (cl_msg *)buf;

	msgp->proto.version = PROTO_VERSION;
	msgp->proto.type = PROTO_TYPE_AS_MSG;
	msgp->proto.sz = msg_sz - sizeof(as_proto);
	as_proto_swap(&msgp->proto);

	as_msg *m = &msgp->msg;

	m->header_sz = sizeof(as_msg);
	m->info1 = 0;
	m->info2 = 0;
	m->info3 = 0;
	m->unused = 0;
	m->result_code = result_code;
	m->generation = generation;
	m->record_ttl = void_time;
	m->transaction_ttl = 0;
	m->n_ops = bin_count;
	m->n_fields = 0;

	buf += sizeof(cl_msg);

	if (trid != 0) {
		m->n_fields++;

		as_msg_field *trfield = (as_msg_field *)buf;

		trfield->field_sz = 1 + sizeof(uint64_t);
		trfield->type = AS_MSG_FIELD_TYPE_TRID;
		*(uint64_t *)trfield->data = cf_swap_to_be64(trid);

		buf += sizeof(as_msg_field) + sizeof(uint64_t);
		as_msg_swap_field(trfield);
	}

	if (set_name) {
		m->n_fields++;

		as_msg_field *trfield = (as_msg_field *)buf;

		trfield->field_sz = 1 + set_name_len;
		trfield->type = AS_MSG_FIELD_TYPE_SET;
		memcpy(trfield->data, set_name, set_name_len);

		buf += sizeof(as_msg_field) + set_name_len;
		as_msg_swap_field(trfield);
	}

	as_msg_swap_header(m);

	for (uint16_t i = 0; i < bin_count; i++) {
		as_msg_op *op = (as_msg_op *)buf;

		op->version = 0;

		if (ops) {
			op->op = ops[i]->op;
			memcpy(op->name, ops[i]->name, ops[i]->name_sz);
			op->name_sz = ops[i]->name_sz;
		}
		else {
			op->op = AS_MSG_OP_READ;
			op->name_sz = as_bin_memcpy_name(ns, op->name, bins[i]);
		}

		op->op_sz = 4 + op->name_sz;

		buf += sizeof(as_msg_op) + op->name_sz;
		buf += as_bin_particle_to_client(bins[i], op);

		as_msg_swap_op(op);
	}

	return msgp;
}


// FIXME - only old batch sets include_key false - remove parameter ???
// FIXME - only old batch sets skip_empty_records false - remove parameter ???
// Pass NULL bb_r for sizing only. Return value is size if >= 0, error if < 0.
int32_t
as_msg_make_response_bufbuilder(cf_buf_builder **bb_r, as_storage_rd *rd,
		bool no_bin_data, bool include_key, bool skip_empty_records,
		cf_vector *select_bins)
{
	as_namespace *ns = rd->ns;
	as_record *r = rd->r;

	size_t ns_len = strlen(ns->name);
	const char *set_name = as_index_get_set_name(r, ns);
	size_t set_name_len = set_name ? strlen(set_name) : 0;

	uint8_t* key = NULL;
	uint32_t key_size = 0;

	if (include_key && r->key_stored == 1) {
		if (! as_storage_record_get_key(rd)) {
			cf_warning(AS_PROTO, "can't get key - skipping record");
			return -1;
		}

		key = rd->key;
		key_size = rd->key_size;
	}

	uint16_t n_fields = 2; // always add digest and namespace
	size_t msg_sz = sizeof(as_msg) +
			sizeof(as_msg_field) + sizeof(cf_digest) +
			sizeof(as_msg_field) + ns_len;

	if (set_name) {
		n_fields++;
		msg_sz += sizeof(as_msg_field) + set_name_len;
	}

	if (key) {
		n_fields++;
		msg_sz += sizeof(as_msg_field) + key_size;
	}

	uint32_t n_select_bins = 0;
	uint16_t n_bins_matched = 0;
	uint16_t n_record_bins = 0;

	if (! no_bin_data) {
		if (select_bins) {
			n_select_bins = cf_vector_size(select_bins);

			for (uint32_t i = 0; i < n_select_bins; i++) {
				char bin_name[AS_ID_BIN_SZ];

				cf_vector_get(select_bins, i, (void*)&bin_name);

				as_bin *b = as_bin_get(rd, bin_name);

				if (! b) {
					continue;
				}

				msg_sz += sizeof(as_msg_op);
				msg_sz += ns->single_bin ? 0 : strlen(bin_name);
				msg_sz += as_bin_particle_client_value_size(b);

				n_bins_matched++;
			}

			// Don't return an empty record.
			if (skip_empty_records && n_bins_matched == 0) {
				return 0;
			}
		}
		else {
			n_record_bins = as_bin_inuse_count(rd);

			msg_sz += sizeof(as_msg_op) * n_record_bins;

			for (uint16_t i = 0; i < n_record_bins; i++) {
				as_bin *b = &rd->bins[i];

				msg_sz += ns->single_bin ?
						0 : strlen(as_bin_get_name_from_id(ns, b->id));
				msg_sz += (int)as_bin_particle_client_value_size(b);
			}
		}
	}

	// NULL buf-builder means just return size.
	if (! bb_r) {
		return (int32_t)msg_sz;
	}

	uint8_t *buf;

	cf_buf_builder_reserve(bb_r, (int)msg_sz, &buf);

	as_msg *msgp = (as_msg *)buf;

	msgp->header_sz = sizeof(as_msg);
	msgp->info1 = no_bin_data ? AS_MSG_INFO1_GET_NOBINDATA : 0;
	msgp->info2 = 0;
	msgp->info3 = 0;
	msgp->unused = 0;
	msgp->result_code = AS_PROTO_RESULT_OK;
	msgp->generation = r->generation;
	msgp->record_ttl = r->void_time;
	msgp->transaction_ttl = 0;
	msgp->n_fields = n_fields;

	if (no_bin_data) {
		msgp->n_ops = 0;
	}
	else {
		msgp->n_ops = select_bins ? n_bins_matched : n_record_bins;
	}

	as_msg_swap_header(msgp);

	buf += sizeof(as_msg);

	as_msg_field *mf = (as_msg_field *)buf;

	mf->field_sz = sizeof(cf_digest) + 1;
	mf->type = AS_MSG_FIELD_TYPE_DIGEST_RIPE;
	memcpy(mf->data, &r->keyd, sizeof(cf_digest));
	as_msg_swap_field(mf);
	buf += sizeof(as_msg_field) + sizeof(cf_digest);

	mf = (as_msg_field *)buf;
	mf->field_sz = ns_len + 1;
	mf->type = AS_MSG_FIELD_TYPE_NAMESPACE;
	memcpy(mf->data, ns->name, ns_len);
	as_msg_swap_field(mf);
	buf += sizeof(as_msg_field) + ns_len;

	if (set_name) {
		mf = (as_msg_field *)buf;
		mf->field_sz = set_name_len + 1;
		mf->type = AS_MSG_FIELD_TYPE_SET;
		memcpy(mf->data, set_name, set_name_len);
		as_msg_swap_field(mf);
		buf += sizeof(as_msg_field) + set_name_len;
	}

	if (key) {
		mf = (as_msg_field *)buf;
		mf->field_sz = key_size + 1;
		mf->type = AS_MSG_FIELD_TYPE_KEY;
		memcpy(mf->data, key, key_size);
		as_msg_swap_field(mf);
		buf += sizeof(as_msg_field) + key_size;
	}

	if (no_bin_data) {
		return (int32_t)msg_sz;
	}

	if (select_bins) {
		for (uint32_t i = 0; i < n_select_bins; i++) {
			char bin_name[AS_ID_BIN_SZ];

			cf_vector_get(select_bins, i, (void*)&bin_name);

			as_bin *b = as_bin_get(rd, bin_name);

			if (! b) {
				continue;
			}

			as_msg_op *op = (as_msg_op *)buf;

			op->op = AS_MSG_OP_READ;
			op->version = 0;
			op->name_sz = as_bin_memcpy_name(ns, op->name, b);
			op->op_sz = 4 + op->name_sz;

			buf += sizeof(as_msg_op) + op->name_sz;
			buf += as_bin_particle_to_client(b, op);

			as_msg_swap_op(op);
		}
	}
	else {
		for (uint16_t i = 0; i < n_record_bins; i++) {
			as_msg_op *op = (as_msg_op *)buf;

			op->op = AS_MSG_OP_READ;
			op->version = 0;
			op->name_sz = as_bin_memcpy_name(ns, op->name, &rd->bins[i]);
			op->op_sz = 4 + op->name_sz;

			buf += sizeof(as_msg_op) + op->name_sz;
			buf += as_bin_particle_to_client(&rd->bins[i], op);

			as_msg_swap_op(op);
		}
	}

	return (int32_t)msg_sz;
}


// Caller-provided val_sz must be the result of calling
// as_particle_asval_client_value_size() for same val.
void
as_msg_make_val_response_bufbuilder(const as_val *val, cf_buf_builder **bb_r,
		uint32_t val_sz, bool success)
{
	static const char SUCCESS_BIN_NAME[] = "SUCCESS";
	static const char FAILURE_BIN_NAME[] = "FAILURE";

	const char *bin_name;
	size_t bin_name_len;

	if (success) {
		bin_name = SUCCESS_BIN_NAME;
		bin_name_len = sizeof(SUCCESS_BIN_NAME) - 1;
	}
	else {
		bin_name = FAILURE_BIN_NAME;
		bin_name_len = sizeof(FAILURE_BIN_NAME) - 1;
	}

	size_t msg_sz = sizeof(as_msg) + sizeof(as_msg_op) + val_sz + bin_name_len;

	uint8_t *buf;

	cf_buf_builder_reserve(bb_r, (int)msg_sz, &buf);

	as_msg *msgp = (as_msg *)buf;

	msgp->header_sz = sizeof(as_msg);
	msgp->info1 = 0;
	msgp->info2 = 0;
	msgp->info3 = 0;
	msgp->unused = 0;
	msgp->result_code = AS_PROTO_RESULT_OK;
	msgp->generation = 0;
	msgp->record_ttl = 0;
	msgp->transaction_ttl = 0;
	msgp->n_fields = 0;
	msgp->n_ops = 1; // only the one special bin

	as_msg_swap_header(msgp);

	as_msg_op *op = (as_msg_op *)(buf + sizeof(as_msg));

	op->op = AS_MSG_OP_READ;
	op->name_sz = (uint8_t)bin_name_len;
	memcpy(op->name, bin_name, op->name_sz);
	op->op_sz = 4 + op->name_sz;
	op->version = 0;

	as_particle_asval_to_client(val, op);

	as_msg_swap_op(op);
}


//==========================================================
// Public API - sending responses to client.
//

// Make an individual transaction response and send it.
int
as_msg_send_reply(as_file_handle *fd_h, uint32_t result_code,
		uint32_t generation, uint32_t void_time, as_msg_op **ops, as_bin **bins,
		uint16_t bin_count, as_namespace *ns, uint64_t trid,
		const char *set_name)
{
	uint8_t stack_buf[MSG_STACK_BUFFER_SZ];
	size_t msg_sz = sizeof(stack_buf);
	uint8_t *msgp = (uint8_t *)as_msg_make_response_msg(result_code, generation,
			void_time, ops, bins, bin_count, ns, (cl_msg *)stack_buf, &msg_sz,
			trid, set_name);

	int rv = send_reply_buf(fd_h, msgp, msg_sz);

	if (msgp != stack_buf) {
		cf_free(msgp);
	}

	return rv;
}


// Send a pre-made response saved in a dyn-buf.
int
as_msg_send_ops_reply(as_file_handle *fd_h, cf_dyn_buf *db)
{
	return send_reply_buf(fd_h, db->buf, db->used_sz);
}


// Send a blocking "fin" message with default timeout.
bool
as_msg_send_fin(cf_socket *sock, uint32_t result_code)
{
	return as_msg_send_fin_timeout(sock, result_code, CF_SOCKET_TIMEOUT) != 0;
}


// Send a blocking "fin" message with a specified timeout.
size_t
as_msg_send_fin_timeout(cf_socket *sock, uint32_t result_code, int32_t timeout)
{
	cl_msg m;

	m.proto.version = PROTO_VERSION;
	m.proto.type = PROTO_TYPE_AS_MSG;
	m.proto.sz = sizeof(as_msg);
	as_proto_swap(&m.proto);

	m.msg.header_sz = sizeof(as_msg);
	m.msg.info1 = 0;
	m.msg.info2 = 0;
	m.msg.info3 = AS_MSG_INFO3_LAST;
	m.msg.unused = 0;
	m.msg.result_code = result_code;
	m.msg.generation = 0;
	m.msg.record_ttl = 0;
	m.msg.transaction_ttl = 0;
	m.msg.n_fields = 0;
	m.msg.n_ops = 0;
	as_msg_swap_header(&m.msg);

	if (cf_socket_send_all(sock, (uint8_t*)&m, sizeof(m), MSG_NOSIGNAL,
			timeout) < 0) {
		cf_warning(AS_PROTO, "send error - fd %d %s", CSFD(sock),
				cf_strerror(errno));
		return 0;
	}

	return sizeof(cl_msg);
}


//==========================================================
// Public API - query "net-IO" responses.
//

void 
as_netio_init()
{
	if (! cf_queue_init(&g_netio_queue, sizeof(as_netio), 64, true)) {
		cf_crash(AS_PROTO, "failed to create netio queue");
	}

	if (! cf_queue_init(&g_netio_slow_queue, sizeof(as_netio), 64, true)) {
		cf_crash(AS_PROTO, "failed to create netio queue");
	}

	pthread_t thread;
	pthread_attr_t attrs;

	pthread_attr_init(&attrs);
	pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&thread, &attrs, run_netio,
			(void *)&g_netio_queue) != 0) {
		cf_crash(AS_PROTO, "failed to create netio thread");
	}

	if (pthread_create(&thread, &attrs, run_netio,
			(void *)&g_netio_slow_queue) != 0) {
		cf_crash(AS_PROTO, "failed to create netio slow thread");
	}
}


// Based on io object, send buffer to the network, or queue for retry.
//
// start_cb: Callback to the module before the real IO is started. Returns:
//      AS_NETIO_OK: Everything ok, go ahead with IO.
//      AS_NETIO_ERR: If there was issue like abort/err/timeout etc.
//
// finish_cb: Callback to module with status code of the IO call. Returns:
//      AS_NETIO_OK: Everything ok.
//      AS_NETIO_CONTINUE: The IO was requeued.
//      AS_NETIO_ERR: IO erred out due to some issue.
//
// finish_cb should do the needful like release ref to user data etc.
//
// Returns:
// AS_NETIO_OK: Everything is fine, both start_cb & finish_cb were called.
// AS_NETIO_ERR: Something failed either calling start_cb or while doing
//      network IO, finish_cb is called.
//
// This function consumes qtr reference. It calls finish_cb which releases ref
// to qtr. In case of AS_NETIO_CONTINUE: this function also consumes bb_r and
// ref for fd_h. The background thread is responsible for freeing up bb_r and
// releasing ref to fd_h.
int
as_netio_send(as_netio *io, bool slow, bool blocking)
{
	int ret = io->start_cb(io, io->seq);

	if (ret == AS_NETIO_OK) {
		ret = io->finish_cb(io, netio_send_packet(io->fd_h, io->bb_r,
				&io->offset, blocking));
	} 
	else {
		ret = io->finish_cb(io, ret);
	}

	// If needs requeue then requeue it.
	switch (ret) {
	case AS_NETIO_CONTINUE:
		if (slow) {
			io->slow = true;
			cf_queue_push(&g_netio_slow_queue, io);
		}
		else {
			cf_queue_push(&g_netio_queue, io);
		}
		break;
	default:
		ret = AS_NETIO_OK;
		break;
	}

	return ret;
}


//==========================================================
// Local helpers.
//

static int
send_reply_buf(as_file_handle *fd_h, uint8_t *msgp, size_t msg_sz)
{
	cf_assert(cf_socket_exists(&fd_h->sock), AS_PROTO, "fd is invalid");

	if (cf_socket_send_all(&fd_h->sock, msgp, msg_sz, MSG_NOSIGNAL,
			CF_SOCKET_TIMEOUT) < 0) {
		// Common when a client aborts.
		cf_debug(AS_PROTO, "protocol write fail: fd %d sz %zu errno %d",
				CSFD(&fd_h->sock), msg_sz, errno);

		as_end_of_transaction_force_close(fd_h);
		return -1;
	}

	as_end_of_transaction_ok(fd_h);
	return 0;
}


void *
run_netio(void *q_to_wait_on)
{
	cf_queue *q = (cf_queue*)q_to_wait_on;

	while (true) {
		as_netio io;

		if (cf_queue_pop(q, &io, CF_QUEUE_FOREVER) != 0) {
			cf_crash(AS_PROTO, "Failed to pop from IO worker queue.");
		}

		if (io.slow) {
			usleep(g_config.proto_slow_netio_sleep_ms * 1000);
		}

		as_netio_send(&io, true, false);
	}

	return NULL;
}


int
netio_send_packet(as_file_handle *fd_h, cf_buf_builder *bb_r, uint32_t *offset,
		bool blocking)
{
#if defined(USE_SYSTEMTAP)
	uint64_t nodeid = g_config.self_node;
#endif

	uint32_t len = bb_r->used_sz;
	uint8_t *buf = bb_r->buf;

	as_proto proto;
	proto.version = PROTO_VERSION;
	proto.type = PROTO_TYPE_AS_MSG;
	proto.sz = len - 8;
	as_proto_swap(&proto);

	memcpy(bb_r->buf, &proto, 8);

	uint32_t pos = *offset;

	ASD_QUERY_SENDPACKET_STARTING(nodeid, pos, len);

	int retry = 0;

	cf_detail(AS_PROTO," Start At %p %d %d", buf, pos, len);

	while (pos < len) {
		int rv = cf_socket_send(&fd_h->sock, buf + pos, len - pos,
				MSG_NOSIGNAL);

		if (rv <= 0) {
			if (errno != EAGAIN) {
				cf_debug(AS_PROTO, "Packet send response error returned %d errno %d fd %d",
						rv, errno, CSFD(&fd_h->sock));
				return AS_NETIO_IO_ERR;
			}

			if (! blocking && (retry > NETIO_MAX_IO_RETRY)) {
				*offset = pos;
				cf_detail(AS_PROTO," End At %p %d %d", buf, pos, len);
				ASD_QUERY_SENDPACKET_CONTINUE(nodeid, pos);
				return AS_NETIO_CONTINUE;
			}

			retry++;
			// bigger packets so try few extra times
			usleep(100);
		}
		else {
			pos += rv;
		}
	}

	ASD_QUERY_SENDPACKET_FINISHED(nodeid);
	return AS_NETIO_OK;
}
