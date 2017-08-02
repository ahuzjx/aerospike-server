/*
 * cdt.c
 *
 * Copyright (C) 2015-2016 Aerospike, Inc.
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

#include "base/cdt.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "citrusleaf/cf_byte_order.h"

#include "dynbuf.h"
#include "fault.h"

#include "base/cfg.h"
#include "base/particle.h"


//==========================================================
// Typedefs & constants.
//

#define VA_FIRST(first, ...)	first
#define VA_REST(first, ...)		__VA_ARGS__

#define CDT_OP_ENTRY(op, type, ...) [op].args = (const as_cdt_paramtype[]){VA_REST(__VA_ARGS__, 0)}, [op].count = VA_NARGS(__VA_ARGS__) - 1, [op].opt_args = VA_FIRST(__VA_ARGS__)

const cdt_op_table_entry cdt_op_table[] = {

	//============================================
	// LIST

	//--------------------------------------------
	// Modify OPs

	// Add to list
	CDT_OP_ENTRY(AS_CDT_OP_LIST_APPEND,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_APPEND_ITEMS,	CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_INSERT,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_INSERT_ITEMS,	CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),

	// Remove from list
	CDT_OP_ENTRY(AS_CDT_OP_LIST_POP,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_POP_RANGE,		CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_COUNT),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_REMOVE,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_REMOVE_RANGE,	CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_COUNT),

	// Other list modifies
	CDT_OP_ENTRY(AS_CDT_OP_LIST_SET,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_TRIM,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_COUNT),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_CLEAR,			CDT_RW_TYPE_MODIFY, 0),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_INCREMENT,		CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),

	//--------------------------------------------
	// Read OPs

	// Read from list
	CDT_OP_ENTRY(AS_CDT_OP_LIST_SIZE,			CDT_RW_TYPE_READ, 0),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_GET,			CDT_RW_TYPE_READ, 0, AS_CDT_PARAM_INDEX),
	CDT_OP_ENTRY(AS_CDT_OP_LIST_GET_RANGE,		CDT_RW_TYPE_READ, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_COUNT),

	//============================================
	// MAP

	//--------------------------------------------
	// Create and flags

	CDT_OP_ENTRY(AS_CDT_OP_MAP_SET_TYPE,				CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_FLAGS),

	//--------------------------------------------
	// Modify OPs

	CDT_OP_ENTRY(AS_CDT_OP_MAP_ADD,						CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_FLAGS),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_ADD_ITEMS,				CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_FLAGS),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_PUT,						CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_FLAGS),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_PUT_ITEMS,				CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_FLAGS),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REPLACE,					CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REPLACE_ITEMS,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_PAYLOAD),

	CDT_OP_ENTRY(AS_CDT_OP_MAP_INCREMENT,				CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_FLAGS),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_DECREMENT,				CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_FLAGS),

	CDT_OP_ENTRY(AS_CDT_OP_MAP_CLEAR,					CDT_RW_TYPE_MODIFY, 0),

	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_KEY,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_VALUE,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_INDEX,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_INDEX),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_RANK,			CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_INDEX),

	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_KEY_LIST,		CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_ALL_BY_VALUE,		CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_VALUE_LIST,	CDT_RW_TYPE_MODIFY, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),

	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_KEY_INTERVAL,	CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_VALUE_INTERVAL,CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_INDEX_RANGE,	CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_COUNT),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_REMOVE_BY_RANK_RANGE,	CDT_RW_TYPE_MODIFY, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_COUNT),

	//--------------------------------------------
	// Read OPs

	CDT_OP_ENTRY(AS_CDT_OP_MAP_SIZE,					CDT_RW_TYPE_READ, 0),

	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_BY_KEY,				CDT_RW_TYPE_READ, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_BY_INDEX,			CDT_RW_TYPE_READ, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_INDEX),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_BY_VALUE,			CDT_RW_TYPE_READ, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_BY_RANK,				CDT_RW_TYPE_READ, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_INDEX),

	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_ALL_BY_VALUE,		CDT_RW_TYPE_READ, 0, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD),

	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_BY_KEY_INTERVAL,		CDT_RW_TYPE_READ, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_BY_INDEX_RANGE,		CDT_RW_TYPE_READ, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_COUNT),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_BY_VALUE_INTERVAL,	CDT_RW_TYPE_READ, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_PAYLOAD, AS_CDT_PARAM_PAYLOAD),
	CDT_OP_ENTRY(AS_CDT_OP_MAP_GET_BY_RANK_RANGE,		CDT_RW_TYPE_READ, 1, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_INDEX, AS_CDT_PARAM_COUNT),

};

static const size_t cdt_op_table_size = sizeof(cdt_op_table) / sizeof(cdt_op_table_entry);

extern const as_particle_vtable *particle_vtable[];

typedef struct index_pack24_s {
	uint32_t value:24;
} __attribute__ ((__packed__)) index_pack24;


//==========================================================
// CDT helpers.
//

// Calculate count given index and max_index.
// input_count == 0 implies until end of list.
// Assumes index < ele_count.
uint64_t
calc_count(uint64_t index, uint64_t input_count, uint32_t max_index)
{
	uint64_t max = (uint64_t)max_index;

	// Since we assume index < ele_count, max - index will never overflow.
	if (input_count == 0 || input_count >= max - index) {
		return max - index;
	}

	return input_count;
}

void
calc_index_count_multi(int64_t in_index, uint64_t in_count, uint32_t ele_count,
		uint32_t *out_index, uint32_t *out_count)
{
	if (in_index >= ele_count) {
		*out_index = ele_count;
		*out_count = 0;
	}
	else if ((in_index = calc_index(in_index, ele_count)) < 0) {
		if ((uint64_t)(-in_index) < in_count) {
			*out_count = in_count + in_index;

			if (*out_count > ele_count) {
				*out_count = ele_count;
			}
		}
		else {
			*out_count = 0;
		}

		*out_index = 0;
	}
	else {
		*out_index = (uint32_t)in_index;
		*out_count = calc_count((uint64_t)in_index, in_count, ele_count);
	}
}

bool
calc_index_count(int64_t in_index, uint64_t in_count, uint32_t ele_count,
		uint32_t *out_index, uint32_t *out_count, bool is_multi)
{
	if (is_multi) {
		calc_index_count_multi(in_index, in_count, ele_count, out_index,
				out_count);
		return true;
	}

	if (in_index >= ele_count ||
			(in_index = calc_index(in_index, ele_count)) < 0) {
		return false;
	}

	*out_index = (uint32_t)in_index;
	*out_count = (uint32_t)calc_count((uint64_t)in_index, in_count, ele_count);

	return true;
}


//==========================================================
// as_bin functions.
//

bool
as_bin_get_int(const as_bin *b, int64_t *value)
{
	if (as_bin_get_particle_type(b) != AS_PARTICLE_TYPE_INTEGER) {
		return false;
	}

	*value = (int64_t)b->particle;

	return true;
}

void
as_bin_set_int(as_bin *b, int64_t value)
{
	b->particle = (as_particle *)value;
	as_bin_state_set_from_type(b, AS_PARTICLE_TYPE_INTEGER);
}

void
as_bin_set_double(as_bin *b, double value)
{
	*((double *)(&b->particle)) = value;
	as_bin_state_set_from_type(b, AS_PARTICLE_TYPE_FLOAT);
}


//==========================================================
//cdt_calc_delta

bool
cdt_calc_delta_init(cdt_calc_delta *cdv, const cdt_payload *delta_value,
		bool is_decrement)
{
	if (delta_value) {
		as_unpacker pk_delta_value = {
				.buffer = delta_value->ptr,
				.offset = 0,
				.length = (int)delta_value->sz
		};

		cdv->type = as_unpack_peek_type(&pk_delta_value);

		if (cdv->type == AS_INTEGER) {
			if (as_unpack_int64(&pk_delta_value, &cdv->incr_int) != 0) {
				cf_warning(AS_PARTICLE, "cdt_delta_value_init() invalid packed delta value");
				return false;
			}
		}
		else if (cdv->type == AS_DOUBLE) {
			if (as_unpack_double(&pk_delta_value, &cdv->incr_double) != 0) {
				cf_warning(AS_PARTICLE, "cdt_delta_value_init() invalid packed delta value");
				return false;
			}
		}
		else {
			cf_warning(AS_PARTICLE, "cdt_delta_value_init() delta is not int/double");
			return false;
		}
	}
	else {
		cdv->type = AS_UNDEF;
		cdv->incr_int = 1;
		cdv->incr_double = 1;
	}

	if (is_decrement) {
		cdv->incr_int = -cdv->incr_int;
		cdv->incr_double = -cdv->incr_double;
	}

	cdv->value_int = 0;
	cdv->value_double = 0;

	return true;
}

bool
cdt_calc_delta_add(cdt_calc_delta *cdv, as_unpacker *pk_value)
{
	if (pk_value) {
		as_val_t packed_value_type = as_unpack_peek_type(pk_value);

		if (packed_value_type == AS_INTEGER) {
			if (as_unpack_int64(pk_value, &cdv->value_int) != 0) {
				cf_warning(AS_PARTICLE, "cdt_delta_value_add() invalid packed int");
				return false;
			}

			if (cdv->type == AS_DOUBLE) {
				cdv->value_int += (int64_t)cdv->incr_double;
			}
			else {
				cdv->value_int += cdv->incr_int;
			}
		}
		else if (packed_value_type == AS_DOUBLE) {
			if (as_unpack_double(pk_value, &cdv->value_double) != 0) {
				cf_warning(AS_PARTICLE, "cdt_delta_value_add() invalid packed double");
				return false;
			}

			if (cdv->type == AS_DOUBLE) {
				cdv->value_double += cdv->incr_double;
			}
			else {
				cdv->value_double += (double)cdv->incr_int;
			}
		}
		else {
			cf_warning(AS_PARTICLE, "cdt_delta_value_add() only valid for int/double");
			return false;
		}

		cdv->type = packed_value_type;
	}
	else {
		if (cdv->type == AS_DOUBLE) {
			cdv->value_double += cdv->incr_double;
		}
		else {
			cdv->value_int += cdv->incr_int;
		}
	}

	return true;
}

void
cdt_calc_delta_pack_and_result(cdt_calc_delta *cdv, cdt_payload *value,
		as_bin *result)
{
	if (cdv->type == AS_INTEGER) {
		cdt_payload_pack_int(value, cdv->value_int);
		as_bin_set_int(result, cdv->value_int);
	}
	else {
		cdt_payload_pack_double(value, cdv->value_double);
		as_bin_set_double(result, cdv->value_double);
	}
}


//==========================================================
// cdt_payload functions.
//

bool
cdt_payload_is_int(const cdt_payload *payload)
{
	return as_unpack_buf_peek_type(payload->ptr, payload->sz) == AS_INTEGER;
}

int64_t
cdt_payload_get_int64(const cdt_payload *payload)
{
	int64_t ret = 0;
	as_unpacker pk = {
			.buffer = payload->ptr,
			.offset = 0,
			.length = payload->sz
	};

	as_unpack_int64(&pk, &ret);

	return ret;
}

inline static void
cdt_payload_pack_val(cdt_payload *value, const as_val *val)
{
	as_serializer ser;
	as_msgpack_init(&ser);

	value->sz = as_serializer_serialize_presized(&ser, val,
			(uint8_t *)value->ptr);

	as_serializer_destroy(&ser);
}

void
cdt_payload_pack_int(cdt_payload *packed, int64_t value)
{
	as_integer val;
	as_integer_init(&val, value);

	cdt_payload_pack_val(packed, (as_val *)&val);
}

void
cdt_payload_pack_double(cdt_payload *packed, double value)
{
	as_double val;
	as_double_init(&val, value);

	return cdt_payload_pack_val(packed, (as_val *)&val);
}


//==========================================================
// cdt_container_builder functions.
//

void
cdt_container_builder_add(cdt_container_builder *builder, const uint8_t *buf,
		uint32_t sz)
{
	memcpy(builder->write_ptr, buf, sz);
	builder->write_ptr += sz;
	*builder->sz += sz;
	builder->ele_count++;
}

void
cdt_container_builder_add_int64(cdt_container_builder *builder, int64_t value)
{
	as_integer val64;

	as_packer pk = {
			.buffer = builder->write_ptr,
			.capacity = INT_MAX
	};

	as_integer_init(&val64, value);
	as_pack_val(&pk, (const as_val *)&val64);
	builder->write_ptr += pk.offset;
	*builder->sz += (uint32_t)pk.offset;
	builder->ele_count++;
}


//==========================================================
// cdt_process_state functions.
//

bool
cdt_process_state_init(cdt_process_state *cdt_state, const as_msg_op *op)
{
	const uint8_t *data = op->name + op->name_sz;
	uint32_t sz = op->op_sz - 4 - op->name_sz;

	if (sz < sizeof(uint16_t)) {
		cf_warning(AS_PARTICLE, "cdt_parse_state_init() as_msg_op data too small to be valid: size=%u", sz);
		return false;
	}

	const uint16_t *type_ptr = (const uint16_t *)data;

	cdt_state->type = cf_swap_from_be16(*type_ptr);
	cdt_state->pk.buffer = data + sizeof(uint16_t);
	cdt_state->pk.length = sz - sizeof(uint16_t);
	cdt_state->pk.offset = 0;

	int64_t ele_count = (cdt_state->pk.length == 0) ?
			0 : as_unpack_list_header_element_count(&cdt_state->pk);

	if (ele_count < 0) {
		cf_warning(AS_PARTICLE, "cdt_parse_state_init() unpack list header failed: size=%u type=%u", sz, cdt_state->type);
		return false;
	}

	cdt_state->ele_count = (uint32_t)ele_count;

	return true;
}

bool
cdt_process_state_get_params(cdt_process_state *state, size_t n, ...)
{
	as_cdt_optype op = state->type;

	if (op >= cdt_op_table_size) {
		return false;
	}

	const cdt_op_table_entry *entry = &cdt_op_table[op];
	int required_count = entry->count - entry->opt_args;

	if (n < (size_t)required_count) {
		cf_crash(AS_PARTICLE, "cdt_process_state_get_params() called with %zu params, require at least %d - %d = %d params", n, entry->count, entry->opt_args, required_count);
	}

	if (n == 0 || entry->args[0] == 0) {
		return true;
	}

	if (state->ele_count < (uint32_t)required_count) {
		cf_warning(AS_PARTICLE, "cdt_process_state_get_params() count mismatch: got %u from client < expected %d", state->ele_count, required_count);
		return false;
	}

	if (state->ele_count > (uint32_t)entry->count) {
		cf_warning(AS_PARTICLE, "cdt_process_state_get_params() count mismatch: got %u from client > expected %u", state->ele_count, entry->count);
		return false;
	}

	va_list vl;
	va_start(vl, n);

	for (size_t i = 0; i < state->ele_count; i++) {
		switch (entry->args[i]) {
		case AS_CDT_PARAM_PAYLOAD: {
			cdt_payload *arg = va_arg(vl, cdt_payload *);

			arg->ptr = state->pk.buffer + state->pk.offset;

			int sz = as_unpack_size(&state->pk);

			if (sz < 0) {
				va_end(vl);
				return false;
			}

			arg->sz = sz;

			break;
		}
		case AS_CDT_PARAM_FLAGS:
		case AS_CDT_PARAM_COUNT: {
			uint64_t *arg = va_arg(vl, uint64_t *);

			if (as_unpack_uint64(&state->pk, arg) != 0) {
				va_end(vl);
				return false;
			}

			break;
		}
		case AS_CDT_PARAM_INDEX: {
			int64_t *arg = va_arg(vl, int64_t *);

			if (as_unpack_int64(&state->pk, arg) != 0) {
				va_end(vl);
				return false;
			}

			break;
		}
		default:
			va_end(vl);
			return false;
		}
	}

	va_end(vl);

	return true;
}

size_t
cdt_process_state_op_param_count(as_cdt_optype op)
{
	if (op >= cdt_op_table_size) {
		return 0;
	}

	const cdt_op_table_entry *entry = &cdt_op_table[op];

	if (entry->args[0] == 0) {
		return 0;
	}

	return entry->count;
}


//==========================================================
// rollback_alloc functions.
//

void
rollback_alloc_push(rollback_alloc *packed_alloc, void *ptr)
{
	if (packed_alloc->malloc_list_sz >= packed_alloc->malloc_list_cap) {
		cf_crash(AS_PARTICLE, "rollback_alloc_push() need to make rollback list larger: cap=%zu", packed_alloc->malloc_list_cap);
	}

	packed_alloc->malloc_list[packed_alloc->malloc_list_sz++] = ptr;
}

uint8_t *
rollback_alloc_reserve(rollback_alloc *alloc_buf, size_t size)
{
	if (! alloc_buf) {
		return NULL;
	}

	uint8_t *ptr;

	if (alloc_buf->ll_buf) {
		ptr = NULL;
		cf_ll_buf_reserve(alloc_buf->ll_buf, size, &ptr);
	}
	else {
		ptr = alloc_buf->malloc_ns ? cf_malloc_ns(size) : cf_malloc(size);
		rollback_alloc_push(alloc_buf, ptr);
	}

	return ptr;
}

void
rollback_alloc_rollback(rollback_alloc *alloc_buf)
{
	if (alloc_buf->ll_buf) {
		return;
	}

	for (size_t i = 0; i < alloc_buf->malloc_list_sz; i++) {
		cf_free(alloc_buf->malloc_list[i]);
	}

	alloc_buf->malloc_list_sz = 0;
}

bool
rollback_alloc_from_msgpack(rollback_alloc *alloc_buf, as_bin *b,
		const cdt_payload *seg)
{
	// We assume the bin is empty.

	as_particle_type type = as_particle_type_from_msgpack(seg->ptr, seg->sz);

	if (type == AS_PARTICLE_TYPE_BAD) {
		return false;
	}

	if (type == AS_PARTICLE_TYPE_NULL) {
		return true;
	}

	uint32_t sz =
			particle_vtable[type]->size_from_msgpack_fn(seg->ptr, seg->sz);

	if (sz != 0) {
		b->particle = (as_particle *)rollback_alloc_reserve(alloc_buf, sz);

		if (! b->particle) {
			return false;
		}
	}

	particle_vtable[type]->from_msgpack_fn(seg->ptr, seg->sz, &b->particle);

	// Set the bin's iparticle metadata.
	as_bin_state_set_from_type(b, type);

	return true;
}


//==========================================================
// as_bin_cdt_packed functions.
//

int
as_bin_cdt_packed_modify(as_bin *b, as_msg_op *op, as_bin *result,
		cf_ll_buf *particles_llb)
{
	cdt_process_state state;

	if (! cdt_process_state_init(&state, op)) {
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	cdt_modify_data udata = {
		.b = b,
		.result = result,
		.alloc_buf = particles_llb,
		.ret_code = AS_PROTO_RESULT_OK,
	};

	bool success;

	if ((int)state.type <= (int)AS_CDT_OP_LIST_LAST) {
		success = cdt_process_state_packed_list_modify_optype(&state, &udata);
	}
	else {
		success = cdt_process_state_packed_map_modify_optype(&state, &udata);
	}

	if (! success) {
		as_bin_set_empty(b);
	}

	return udata.ret_code;
}

int
as_bin_cdt_packed_read(const as_bin *b, as_msg_op *op, as_bin *result)
{
	cdt_process_state state;

	if (! cdt_process_state_init(&state, op)) {
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	cdt_read_data udata = {
		.b = b,
		.result = result,
		.ret_code = AS_PROTO_RESULT_OK,
	};

	if ((int)state.type <= AS_CDT_OP_LIST_LAST) {
		cdt_process_state_packed_list_read_optype(&state, &udata);
	}
	else {
		cdt_process_state_packed_map_read_optype(&state, &udata);
	}

	return udata.ret_code;
}


//==========================================================
// msgpacked_index
//

void
msgpacked_index_set(msgpacked_index *idxs, uint32_t index, uint32_t value)
{
	switch (idxs->ele_sz) {
	case 1:
		idxs->ptr[index] = (uint8_t)value;
		break;
	case 2:
		((uint16_t *)idxs->ptr)[index] = (uint16_t)value;
		break;
	case 3:
		((index_pack24 *)idxs->ptr)[index].value = value;
		break;
	default:
		((uint32_t *)idxs->ptr)[index] = value;
		break;
	}
}

void
msgpacked_index_set_ptr(msgpacked_index *idxs, uint8_t *ptr)
{
	idxs->ptr = ptr;
}

// Get pointer at index.
void *
msgpacked_index_get_mem(const msgpacked_index *idxs, uint32_t index)
{
	return (void *)(idxs->ptr + idxs->ele_sz * index);
}

size_t
msgpacked_index_size(const msgpacked_index *idxs)
{
	return idxs->ele_sz * idxs->ele_count;
}

uint32_t
msgpacked_index_ptr2value(const msgpacked_index *idxs, const void *ptr)
{
	switch (idxs->ele_sz) {
	case 1:
		return *((const uint8_t *)ptr);
	case 2:
		return *((const uint16_t *)ptr);
	case 3:
		return ((const index_pack24 *)ptr)->value;
	default:
		break;
	}

	return *((const uint32_t *)ptr);
}

uint32_t
msgpacked_index_get(const msgpacked_index *idxs, uint32_t index)
{
	switch (idxs->ele_sz) {
	case 1:
		return idxs->ptr[index];
	case 2:
		return ((const uint16_t *)idxs->ptr)[index];
	case 3:
		return ((const index_pack24 *)idxs->ptr)[index].value;
	default:
		break;
	}

	return ((const uint32_t *)idxs->ptr)[index];
}

// Find find_index in a list of sorted_indexes.
// *where will be the location where find_index is (if exist) or is suppose to be (if not exist).
// Return true if find_index is in sorted_indexes.
bool
msgpacked_index_find_index_sorted(const msgpacked_index *sorted_indexes,
		uint32_t find_index, uint32_t count, uint32_t *where)
{
	if (count == 0) {
		*where = 0;
		return false;
	}

	uint32_t upper = count;
	uint32_t lower = 0;
	uint32_t i = count / 2;

	while (true) {
		uint32_t index = msgpacked_index_get(sorted_indexes, i);

		if (find_index == index) {
			*where = i;
			return true;
		}

		if (find_index > index) {
			if (i >= upper - 1) {
				*where = i + 1;
				break;
			}

			lower = i + 1;
			i += upper;
			i /= 2;
		}
		else {
			if (i <= lower) {
				*where = i;
				break;
			}

			upper = i;
			i += lower;
			i /= 2;
		}
	}

	return false;
}

void
msgpacked_index_print(const msgpacked_index *idxs, const char *name)
{
	size_t ele_count = idxs->ele_count;
	char buf[1024];
	char *ptr = buf;

	if (idxs->ptr) {
		for (size_t i = 0; i < ele_count; i++) {
			if (buf + 1024 - ptr < 12) {
				break;
			}

			ptr += sprintf(ptr, "%u, ", msgpacked_index_get(idxs, i));
		}

		if (ele_count > 0) {
			ptr -= 2;
		}

		*ptr = '\0';
	}
	else {
		strcpy(buf, "(null)");
	}

	cf_warning(AS_PARTICLE, "%s: index[%zu]={%s}", name, ele_count, buf);
}


//==========================================================
// offset_index
//

void
offset_index_init(offset_index *offidx, uint8_t *idx_mem_ptr,
		uint32_t ele_count, uint32_t content_sz)
{
	offidx->_.ele_count = ele_count;
	offidx->tot_ele_sz = content_sz;

	if (content_sz < (1 << 8)) {
		offidx->_.ele_sz = 1;
	}
	else if (content_sz < (1 << 16)) {
		offidx->_.ele_sz = 2;
	}
	else if (content_sz < (1 << 24)) {
		offidx->_.ele_sz = 3;
	}
	else {
		offidx->_.ele_sz = 4;
	}

	offidx->_.ptr = idx_mem_ptr;
	offidx->ele_start = NULL;
}

void
offset_index_set(offset_index *offidx, uint32_t index, uint32_t value)
{
	if (index == 0 || index == offidx->_.ele_count) {
		return;
	}

	msgpacked_index_set((msgpacked_index *)offidx, index, value);
}

bool
offset_index_set_next(offset_index *offidx, uint32_t index, uint32_t value)
{
	if (index >= offidx->_.ele_count) {
		return true;
	}

	uint32_t filled = offset_index_get_filled(offidx);

	if (index == filled) {
		offset_index_set(offidx, index, value);
		offset_index_set_filled(offidx, filled + 1);

		return true;
	}

	if (index < filled) {
		return value == offset_index_get_const(offidx, index);
	}

	return false;
}

void
offset_index_set_filled(offset_index *offidx, uint32_t ele_filled)
{
	if (offidx->_.ele_count == 0) {
		return;
	}

	msgpacked_index_set((msgpacked_index *)offidx, 0, ele_filled);
}

void
offset_index_set_ptr(offset_index *offidx, uint8_t *idx_mem,
		const uint8_t *packed_mem)
{
	msgpacked_index_set_ptr((msgpacked_index *)offidx, idx_mem);
	offidx->ele_start = packed_mem;
}

void
offset_index_copy(offset_index *dest, const offset_index *src, uint32_t d_start,
		uint32_t s_start, uint32_t count, int delta)
{
	if (count > dest->_.ele_count) {
		count = dest->_.ele_count;
	}

	if (dest->_.ele_sz == src->_.ele_sz && delta == 0) {
		memcpy(offset_index_get_mem(dest, d_start),
				offset_index_get_mem(src, s_start),
				dest->_.ele_sz * count);
	}
	else {
		for (size_t i = 0; i < count; i++) {
			uint32_t value = offset_index_get_const(src, s_start + i);

			value += delta;
			offset_index_set(dest, d_start + i, value);
		}
	}
}

void
offset_index_append_size(offset_index *offidx, uint32_t delta)
{
	uint32_t filled = offset_index_get_filled(offidx);

	if (filled == offidx->_.ele_count) {
		return;
	}

	uint32_t last = offset_index_get_const(offidx, filled - 1);

	offset_index_set_filled(offidx, filled + 1);
	offset_index_set(offidx, filled, last + delta);
}

void *
offset_index_get_mem(const offset_index *offidx, uint32_t index)
{
	return msgpacked_index_get_mem((msgpacked_index *)offidx, index);
}

size_t
offset_index_size(const offset_index *offidx)
{
	return msgpacked_index_size((const msgpacked_index *)offidx);
}

bool
offset_index_is_null(const offset_index *offidx)
{
	return offidx->_.ptr == NULL;
}

bool
offset_index_is_valid(const offset_index *offidx)
{
	return offidx->_.ptr != NULL;
}

bool
offset_index_is_full(const offset_index *offidx)
{
	if (offset_index_is_null(offidx)) {
		return false;
	}

	if (offidx->_.ele_count == 0) {
		return true;
	}

	uint32_t filled = offset_index_get_filled(offidx);

	cf_assert(filled <= offidx->_.ele_count, AS_PARTICLE, "filled(%u) > ele_count(%u)", filled, offidx->_.ele_count);

	if (filled == offidx->_.ele_count) {
		return true;
	}

	return false;
}

uint32_t
offset_index_get_const(const offset_index *offidx, uint32_t idx)
{
	if (idx == 0) {
		return 0;
	}

	if (idx == offidx->_.ele_count) {
		return offidx->tot_ele_sz;
	}

	if (idx >= offset_index_get_filled(offidx)) {
		offset_index_print(offidx, "offset_index_get_const() offidx");
		print_packed(offidx->ele_start, offidx->tot_ele_sz, "offset_index_get_const() offidx->ele_start");
		cf_crash(AS_PARTICLE, "offset_index_get_const() idx=%u >= filled=%u ele_count=%u", idx, offset_index_get_filled(offidx), offidx->_.ele_count);
	}

	return msgpacked_index_get((const msgpacked_index *)offidx, idx);
}

uint32_t
offset_index_get_delta_const(const offset_index *offidx, uint32_t index)
{
	uint32_t offset = offset_index_get_const(offidx, index);

	if (index == offidx->_.ele_count - 1) {
		return offidx->tot_ele_sz - offset;
	}

	return offset_index_get_const(offidx, index + 1) - offset;
}

uint32_t
offset_index_get_filled(const offset_index *offidx)
{
	if (offidx->_.ele_count == 0) {
		return 1;
	}

	return msgpacked_index_get((const msgpacked_index *)offidx, 0);
}

void
offset_index_print(const offset_index *offidx, const char *name)
{
	if (! name) {
		name = "offset";
	}

	msgpacked_index_print((msgpacked_index *)offidx, name);
}

void
offset_index_delta_print(const offset_index *offidx, const char *name)
{
	size_t ele_count = offidx->_.ele_count;
	char buf[1024];
	char *ptr = buf;

	if (offidx->_.ptr) {
		for (size_t i = 0; i < ele_count; i++) {
			if (buf + 1024 - ptr < 12) {
				break;
			}

			ptr += sprintf(ptr, "%u, ", offset_index_get_delta_const(offidx, i));
		}

		if (ele_count > 0) {
			ptr -= 2;
		}

		*ptr = '\0';
	}
	else {
		strcpy(buf, "(null)");
	}

	cf_warning(AS_PARTICLE, "%s: delta_off[%zu]={%s} %zu", name, ele_count, buf, offidx->tot_ele_sz);
}


//==========================================================
// Debugging support.
//

void
print_hex(const uint8_t *packed, uint32_t packed_sz, char *buf, uint32_t buf_sz)
{
	uint32_t n = (buf_sz - 3) / 2;

	if (n > packed_sz) {
		n = packed_sz;
		buf[buf_sz - 3] = '.';
		buf[buf_sz - 2] = '.';
		buf[buf_sz - 1] = '\0';
	}

	char *ptr = (char *)buf;

	for (int i = 0; i < n; i++) {
		sprintf(ptr, "%02X", packed[i]);
		ptr += 2;
	}
}

void
print_packed(const uint8_t *packed, uint32_t size, const char *name)
{
	char buf[4096];
	print_hex(packed, size, buf, 4096);
	cf_warning(AS_PARTICLE, "%s: buf[%u]='%s'", name, size, buf);
}
