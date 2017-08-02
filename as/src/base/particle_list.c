/*
 * particle_list.c
 *
 * Copyright (C) 2015-2017 Aerospike, Inc.
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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aerospike/as_buffer.h"
#include "aerospike/as_msgpack.h"
#include "aerospike/as_serializer.h"
#include "aerospike/as_val.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_byte_order.h"

#include "fault.h"

#include "base/cdt.h"
#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/particle.h"
#include "base/proto.h"


//==========================================================
// LIST particle interface - function declarations.
//

// Destructor, etc.
void list_destruct(as_particle *p);
uint32_t list_size(const as_particle *p);

// Handle "wire" format.
int32_t list_concat_size_from_wire(as_particle_type wire_type, const uint8_t *wire_value, uint32_t value_size, as_particle **pp);
int list_append_from_wire(as_particle_type wire_type, const uint8_t *wire_value, uint32_t value_size, as_particle **pp);
int list_prepend_from_wire(as_particle_type wire_type, const uint8_t *wire_value, uint32_t value_size, as_particle **pp);
int list_incr_from_wire(as_particle_type wire_type, const uint8_t *wire_value, uint32_t value_size, as_particle **pp);
int32_t list_size_from_wire(const uint8_t *wire_value, uint32_t value_size);
int list_from_wire(as_particle_type wire_type, const uint8_t *wire_value, uint32_t value_size, as_particle **pp);
int list_compare_from_wire(const as_particle *p, as_particle_type wire_type, const uint8_t *wire_value, uint32_t value_size);
uint32_t list_wire_size(const as_particle *p);
uint32_t list_to_wire(const as_particle *p, uint8_t *wire);

// Handle as_val translation.
uint32_t list_size_from_asval(const as_val *val);
void list_from_asval(const as_val *val, as_particle **pp);
as_val *list_to_asval(const as_particle *p);
uint32_t list_asval_wire_size(const as_val *val);
uint32_t list_asval_to_wire(const as_val *val, uint8_t *wire);

// Handle msgpack translation.
uint32_t list_size_from_msgpack(const uint8_t *packed, uint32_t packed_size);
void list_from_msgpack(const uint8_t *packed, uint32_t packed_size, as_particle **pp);

// Handle on-device "flat" format.
int32_t list_size_from_flat(const uint8_t *flat, uint32_t flat_size);
int list_cast_from_flat(uint8_t *flat, uint32_t flat_size, as_particle **pp);
int list_from_flat(const uint8_t *flat, uint32_t flat_size, as_particle **pp);
uint32_t list_flat_size(const as_particle *p);
uint32_t list_to_flat(const as_particle *p, uint8_t *flat);


//==========================================================
// LIST particle interface - vtable.
//

const as_particle_vtable list_vtable = {
		list_destruct,
		list_size,

		list_concat_size_from_wire,
		list_append_from_wire,
		list_prepend_from_wire,
		list_incr_from_wire,
		list_size_from_wire,
		list_from_wire,
		list_compare_from_wire,
		list_wire_size,
		list_to_wire,

		list_size_from_asval,
		list_from_asval,
		list_to_asval,
		list_asval_wire_size,
		list_asval_to_wire,

		list_size_from_msgpack,
		list_from_msgpack,

		list_size_from_flat,
		list_cast_from_flat,
		list_from_flat,
		list_flat_size,
		list_to_flat
};


//==========================================================
// Typedefs & constants.
//

#define PACKED_LIST_INDEX_STEP 128

#define PACKED_LIST_FLAG_OFF_IDX 0x10 // has list offset index

typedef struct packed_list_op_s {
	// Input fields.
	const uint8_t *packed;
	uint32_t packed_sz;

	// Parsed fields.
	uint32_t ele_count; // excludes ext ele
	// Mutable state member (is considered mutable in const objects).
	offset_index offidx; // offset start at ele_start (excluding ext metadata ele)
	uint8_t ext_flags;

	// Calculated fields.
	const uint8_t *contents; // where elements start (excludes ext)
	uint32_t content_sz;

	// Calculated post-op fields.
	uint32_t new_ele_count;
	uint32_t seg1_sz;
	uint32_t seg2_index;
	uint32_t seg2_sz;
	uint32_t nil_ele_sz; // number of nils we need to insert
} packed_list_op;

typedef struct list_mem_s {
	uint8_t		type;
	uint32_t	sz;
	uint8_t		data[];
} __attribute__ ((__packed__)) list_mem;

typedef struct list_flat_s {
	uint8_t		type;
	uint32_t	sz; // host order on device and in memory
	uint8_t		data[];
} __attribute__ ((__packed__)) list_flat;

static const list_mem list_mem_empty = {
		.type = AS_PARTICLE_TYPE_LIST,
		.sz = 1,
		.data = {0x90},
};

#define define_packed_list_op_particle(__name, __particle, __ret) \
		packed_list_op __name; \
		bool __ret = packed_list_op_init_from_particle(&__name, __particle)


//==========================================================
// Forward declarations.
//

static inline bool is_list_type(uint8_t type);
static uint32_t list_calc_ext_content_sz(uint32_t ele_count, uint32_t content_sz);

static uint32_t list_pack_header(uint8_t *buf, uint32_t ele_count);
static void list_pack_empty_index(as_packer *pk, uint32_t ele_count, uint32_t content_sz);

// as_bin
static inline void as_bin_set_empty_packed_list(as_bin *b, rollback_alloc *alloc_buf);
static inline void as_bin_create_temp_packed_list_if_notinuse(as_bin *b);
static inline bool as_bin_is_temp_packed_list(const as_bin *b);

// packed_list_op
static bool packed_list_op_init(packed_list_op *op, const uint8_t *buf, uint32_t sz);
static inline bool packed_list_op_init_from_particle(packed_list_op *op, const as_particle *p);
static bool packed_list_op_init_from_bin(packed_list_op *op, const as_bin *b);
static bool packed_list_op_unpack_hdridx(packed_list_op *op);

static int64_t packed_list_op_insert(packed_list_op *op, uint32_t index, uint32_t count, uint32_t insert_sz);
static int32_t packed_list_op_remove(packed_list_op *op, uint32_t index, uint32_t count);

static uint32_t packed_list_op_write_seg1(const packed_list_op *op, uint8_t *buf);
static uint32_t packed_list_op_write_seg2(const packed_list_op *op, uint8_t *buf);

static uint32_t packed_list_op_find_idx_offset(const packed_list_op *op, uint32_t index);

static uint32_t packed_list_op_list_size(const packed_list_op *op, bool has_ext, uint32_t *ext_content_sz_r);
static void packed_list_op_buf_pack(const packed_list_op *op, uint8_t *buf, uint32_t sz, bool has_ext, uint32_t ext_content_sz);
static list_mem *packed_list_op_list_pack(const packed_list_op *op, list_mem *p_list_mem, bool has_ext);
static void packed_list_op_pack_content(const packed_list_op *op, as_packer *pk);

// packed_list
static list_mem *packed_list_create(rollback_alloc *alloc_buf, uint32_t ele_count, uint32_t content_sz);
static as_particle *packed_list_simple_create_from_buf(rollback_alloc *alloc_buf, uint32_t ele_count, const uint8_t *contents, uint32_t content_sz);

static int packed_list_append(as_bin *b, rollback_alloc *alloc_buf, const cdt_payload *payload, bool payload_is_container, as_bin *result);
static int packed_list_insert(as_bin *b, rollback_alloc *alloc_buf, const cdt_payload *payload, bool payload_is_container, int64_t index, as_bin *result);
static int packed_list_remove(as_bin *b, rollback_alloc *alloc_buf, int64_t index, uint64_t count, as_bin *result, bool result_is_count, bool result_is_list, rollback_alloc *alloc_result);
static int packed_list_set(as_bin *b, rollback_alloc *alloc_buf, const cdt_payload *payload, int64_t index);
static int packed_list_increment(as_bin *b, rollback_alloc *alloc_buf, int64_t index, cdt_payload *delta_value, as_bin *result);
static int packed_list_trim(as_bin *b, rollback_alloc *alloc_buf, int64_t index, uint64_t count, as_bin *result);
static uint8_t *packed_list_setup_bin(as_bin *b, rollback_alloc *alloc_buf, uint32_t content_sz, uint32_t ele_count, uint32_t idx_trunc, const offset_index *old_offidx);

// Debugging support
static void print_cdt_list_particle(const as_particle *p);
void print_cdt_list_bin(const as_bin *b);
void print_packed_list_op(const packed_list_op *op);


//==========================================================
// LIST particle interface - function definitions.
//

//------------------------------------------------
// Destructor, etc.
//

void
list_destruct(as_particle *p)
{
	cf_free(p);
}

uint32_t
list_size(const as_particle *p)
{
	const list_mem *p_list_mem = (const list_mem *)p;
	return (uint32_t)sizeof(list_mem) + p_list_mem->sz;
}

//------------------------------------------------
// Handle "wire" format.
//

int32_t
list_concat_size_from_wire(as_particle_type wire_type,
		const uint8_t *wire_value, uint32_t value_size, as_particle **pp)
{
	cf_warning(AS_PARTICLE, "concat size for list");
	return -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
}

int
list_append_from_wire(as_particle_type wire_type, const uint8_t *wire_value,
		uint32_t value_size, as_particle **pp)
{
	cf_warning(AS_PARTICLE, "append to list");
	return -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
}

int
list_prepend_from_wire(as_particle_type wire_type, const uint8_t *wire_value,
		uint32_t value_size, as_particle **pp)
{
	cf_warning(AS_PARTICLE, "prepend to list");
	return -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
}

int
list_incr_from_wire(as_particle_type wire_type, const uint8_t *wire_value,
		uint32_t value_size, as_particle **pp)
{
	cf_warning(AS_PARTICLE, "increment of list");
	return -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
}

int32_t
list_size_from_wire(const uint8_t *wire_value, uint32_t value_size)
{
	// TODO - CDT can't determine in memory or not.
	packed_list_op op;

	if (! packed_list_op_init(&op, wire_value, value_size)) {
		cf_warning(AS_PARTICLE, "list_size_from_wire() invalid packed list");
		return -AS_PROTO_RESULT_FAIL_UNKNOWN;
	}

	return (int32_t)(sizeof(list_mem) +
			packed_list_op_list_size(&op, true, NULL));
}

int
list_from_wire(as_particle_type wire_type, const uint8_t *wire_value,
		uint32_t value_size, as_particle **pp)
{
	// TODO - CDT can't determine in memory or not.
	// It works for data-not-in-memory but we'll incur a memcpy that could be
	// eliminated.
	packed_list_op op;

	if (! packed_list_op_init(&op, wire_value, value_size)) {
		cf_warning(AS_PARTICLE, "list_from_wire() invalid packed list");
		return -AS_PROTO_RESULT_FAIL_UNKNOWN;
	}

	list_mem *p_list_mem = packed_list_op_list_pack(&op, (list_mem *)*pp, true);

	p_list_mem->type = wire_type;

	return AS_PROTO_RESULT_OK;
}

int
list_compare_from_wire(const as_particle *p, as_particle_type wire_type,
		const uint8_t *wire_value, uint32_t value_size)
{
	// TODO
	cf_warning(AS_PARTICLE, "list_compare_from_wire() not implemented");
	return -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
}

uint32_t
list_wire_size(const as_particle *p)
{
	define_packed_list_op_particle(op, p, success);
	cf_assert(success, AS_PARTICLE, "list_wire_size() invalid packed list");
	return as_pack_list_header_get_size(op.ele_count) + op.content_sz;
}

uint32_t
list_to_wire(const as_particle *p, uint8_t *wire)
{
	define_packed_list_op_particle(op, p, success);
	cf_assert(success, AS_PARTICLE, "list_to_wire() invalid packed list");

	uint32_t hdr_sz = as_pack_list_header_get_size(op.ele_count);
	uint32_t sz = hdr_sz + op.content_sz;

	as_packer pk = {
			.buffer = wire,
			.capacity = (int)sz
	};

	as_pack_list_header(&pk, op.ele_count);
	packed_list_op_pack_content(&op, &pk);

	return sz;
}

//------------------------------------------------
// Handle as_val translation.
//

uint32_t
list_size_from_asval(const as_val *val)
{
	as_serializer s;
	as_msgpack_init(&s);

	uint32_t sz = as_serializer_serialize_getsize(&s, (as_val *)val);

	as_serializer_destroy(&s);

	uint32_t ele_count = as_list_size((as_list *)val);
	uint32_t base_hdr_sz = as_pack_list_header_get_size(ele_count);
	uint32_t content_sz = sz - base_hdr_sz;
	uint32_t ext_content_sz = list_calc_ext_content_sz(ele_count, content_sz);
	uint32_t hdr_sz = as_pack_list_header_get_size(ele_count + 1);

	return (uint32_t)sizeof(list_mem) + hdr_sz +
			as_pack_ext_header_get_size(ext_content_sz) + ext_content_sz +
			content_sz;
}

void
list_from_asval(const as_val *val, as_particle **pp)
{
	as_serializer s;
	as_msgpack_init(&s);

	list_mem *p_list_mem = (list_mem *)*pp;
	int32_t sz = as_serializer_serialize_presized(&s, val, p_list_mem->data);

	cf_assert(sz >= 0, AS_PARTICLE, "list_from_asval() failed to presize");
	as_serializer_destroy(&s);

	uint32_t ele_count = as_list_size((as_list *)val);
	uint32_t base_hdr_sz = as_pack_list_header_get_size(ele_count);
	uint32_t content_sz = (uint32_t)sz - base_hdr_sz;
	uint32_t ext_content_sz = list_calc_ext_content_sz(ele_count, content_sz);
	uint32_t hdr_sz = as_pack_list_header_get_size(ele_count + 1);
	uint32_t ele_start = hdr_sz + as_pack_ext_header_get_size(ext_content_sz) +
			ext_content_sz;

	p_list_mem->type = AS_PARTICLE_TYPE_LIST;
	p_list_mem->sz = ele_start + content_sz;

	// Prefer memmove over 2x serialize.
	memmove(p_list_mem->data + ele_start, p_list_mem->data + base_hdr_sz,
			content_sz);

	as_packer pk = {
			.buffer = p_list_mem->data,
			.capacity = ele_start
	};

	as_pack_list_header(&pk, ele_count + 1);
	as_pack_ext_header(&pk, ext_content_sz, PACKED_LIST_FLAG_OFF_IDX);
	list_pack_empty_index(&pk, ele_count, content_sz);
}

as_val *
list_to_asval(const as_particle *p)
{
	list_mem *p_list_mem = (list_mem *)p;

	as_buffer buf = {
			.capacity = p_list_mem->sz,
			.size = p_list_mem->sz,
			.data = p_list_mem->data
	};

	as_serializer s;
	as_msgpack_init(&s);

	as_val *val = NULL;

	as_serializer_deserialize(&s, &buf, &val);
	as_serializer_destroy(&s);

	if (! val) {
		return (as_val *)as_arraylist_new(0, 1);
	}

	return val;
}

uint32_t
list_asval_wire_size(const as_val *val)
{
	as_serializer s;
	as_msgpack_init(&s);

	uint32_t sz = as_serializer_serialize_getsize(&s, (as_val *)val);

	as_serializer_destroy(&s);

	return sz;
}

uint32_t
list_asval_to_wire(const as_val *val, uint8_t *wire)
{
	as_serializer s;
	as_msgpack_init(&s);

	int32_t sz = as_serializer_serialize_presized(&s, val, wire);

	as_serializer_destroy(&s);
	cf_assert(sz > 0, AS_PARTICLE, "list_asval_to_wire() sz %d failed to serialize", sz);

	return (uint32_t)sz;
}

//------------------------------------------------
// Handle msgpack translation.
//

uint32_t
list_size_from_msgpack(const uint8_t *packed, uint32_t packed_size)
{
	return (uint32_t)sizeof(list_mem) + packed_size;
}

void
list_from_msgpack(const uint8_t *packed, uint32_t packed_size, as_particle **pp)
{
	list_mem *p_list_mem = (list_mem *)*pp;

	p_list_mem->type = AS_PARTICLE_TYPE_LIST;
	p_list_mem->sz = packed_size;
	memcpy(p_list_mem->data, packed, p_list_mem->sz);
}

//------------------------------------------------
// Handle on-device "flat" format.
//

int32_t
list_size_from_flat(const uint8_t *flat, uint32_t flat_size)
{
	// TODO - maybe never used
	return -1;
}

int
list_cast_from_flat(uint8_t *flat, uint32_t flat_size, as_particle **pp)
{
	// Cast temp buffer from disk to data-not-in-memory.
	list_flat *p_list_flat = (list_flat *)flat;

	// This assumes list_flat is the same as list_mem.
	*pp = (as_particle *)p_list_flat;

	return 0;
}

int
list_from_flat(const uint8_t *flat, uint32_t flat_size, as_particle **pp)
{
	// Convert temp buffer from disk to data-in-memory.
	const list_flat *p_list_flat = (const list_flat *)flat;
	packed_list_op op;

	if (! packed_list_op_init(&op, p_list_flat->data, p_list_flat->sz)) {
		cf_warning(AS_PARTICLE, "list_from_flat() invalid packed list");
		return -1;
	}

	list_mem *p_list_mem = packed_list_op_list_pack(&op, NULL, true);

	if (! p_list_mem) {
		cf_warning(AS_PARTICLE, "list_from_flat() failed to create particle");
		return -1;
	}

	p_list_mem->type = p_list_flat->type;
	*pp = (as_particle *)p_list_mem;

	return 0;
}

uint32_t
list_flat_size(const as_particle *p)
{
	define_packed_list_op_particle(op, p, success);
	cf_assert(success, AS_PARTICLE, "list_to_flat() invalid packed list");

	return sizeof(list_flat) + packed_list_op_list_size(&op, false, NULL);
}

uint32_t
list_to_flat(const as_particle *p, uint8_t *flat)
{
	define_packed_list_op_particle(op, p, success);
	cf_assert(success, AS_PARTICLE, "list_to_flat() invalid packed list");

	list_flat *p_list_flat = (list_flat *)flat;

	p_list_flat->sz = packed_list_op_list_size(&op, false, NULL);
	packed_list_op_buf_pack(&op, p_list_flat->data, p_list_flat->sz, false, 0);

	// Already wrote the type.

	return sizeof(list_flat) + p_list_flat->sz;
}


//==========================================================
// as_bin particle functions specific to LIST.
//

void
as_bin_particle_list_get_packed_val(const as_bin *b, cdt_payload *packed)
{
	const list_mem *p_list_mem = (const list_mem *)b->particle;

	packed->ptr = (uint8_t *)p_list_mem->data;
	packed->sz = p_list_mem->sz;
}


//==========================================================
// Local helpers.
//

static inline bool
is_list_type(uint8_t type)
{
	return type == AS_PARTICLE_TYPE_LIST;
}

static inline void
list_offset_index_init(offset_index *offidx, uint8_t *idx_mem_ptr,
		uint32_t ele_count, uint32_t content_sz)
{
	ele_count /= PACKED_LIST_INDEX_STEP;

	if (ele_count != 0) {
		ele_count++;
	}

	offset_index_init(offidx, idx_mem_ptr, ele_count, content_sz);
}

static uint32_t
list_calc_ext_content_sz(uint32_t ele_count, uint32_t content_sz)
{
	offset_index offidx;
	list_offset_index_init(&offidx, NULL, ele_count, content_sz);

	return (uint32_t)offset_index_size(&offidx);
}

static uint32_t
list_pack_header(uint8_t *buf, uint32_t ele_count)
{
	as_packer pk = {
			.buffer = buf,
			.capacity = INT_MAX,
	};

	if (as_pack_list_header(&pk, ele_count) != 0) {
		cf_crash(AS_PARTICLE, "as_pack_list_header() unexpected failure");
	}

	return (uint32_t)pk.offset;
}

static void
list_pack_empty_index(as_packer *pk, uint32_t ele_count, uint32_t content_sz)
{
	offset_index offidx;

	list_offset_index_init(&offidx, pk->buffer + pk->offset, ele_count,
			content_sz);
	offset_index_set_filled(&offidx, 1);
	pk->offset += offset_index_size(&offidx);
}

//------------------------------------------------
// as_bin
//

static inline void
as_bin_set_empty_packed_list(as_bin *b, rollback_alloc *alloc_buf)
{
#if defined(CDT_LIST_DISALLOW_EMPTY)
	as_bin_set_empty(b);
#else
	b->particle = packed_list_simple_create_empty(alloc_buf);
	as_bin_state_set_from_type(b, AS_PARTICLE_TYPE_LIST);
#endif
}

static inline void
as_bin_create_temp_packed_list_if_notinuse(as_bin *b)
{
	if (! as_bin_inuse(b)) {
		b->particle = (as_particle *)&list_mem_empty;
		as_bin_state_set_from_type(b, AS_PARTICLE_TYPE_LIST);
	}
}

static inline bool
as_bin_is_temp_packed_list(const as_bin *b)
{
	return b->particle == (const as_particle *)&list_mem_empty;
}

//----------------------------------------------------------
// packed_list_op
//

static bool
packed_list_op_init(packed_list_op *op, const uint8_t *buf, uint32_t sz)
{
	op->packed = buf;
	op->packed_sz = sz;

	op->ele_count = 0;
	op->ext_flags = 0;

	op->new_ele_count = 0;
	op->contents = NULL;

	op->seg1_sz = 0;
	op->seg2_index = 0;
	op->seg2_sz = 0;
	op->nil_ele_sz = 0;

	return packed_list_op_unpack_hdridx(op);
}

static inline bool
packed_list_op_init_from_particle(packed_list_op *op, const as_particle *p)
{
	const list_mem *p_list_mem = (const list_mem *)p;
	return packed_list_op_init(op, p_list_mem->data, p_list_mem->sz);
}

static bool
packed_list_op_init_from_bin(packed_list_op *op, const as_bin *b)
{
	uint8_t type = as_bin_get_particle_type(b);
	cf_assert(is_list_type(type), AS_PARTICLE, "packed_list_op_init_from_bin() invalid type %d", type);
	return packed_list_op_init_from_particle(op, b->particle);
}

static bool
packed_list_op_unpack_hdridx(packed_list_op *op)
{
	as_unpacker pk = {
			.buffer = op->packed,
			.offset = 0,
			.length = (int)op->packed_sz
	};

	if (op->packed_sz == 0) {
		op->ext_flags = 0;
		return false;
	}

	int64_t ele_count = as_unpack_list_header_element_count(&pk);

	if (ele_count < 0) {
		return false;
	}

	op->ele_count = (uint32_t)ele_count;

	if (ele_count > 0 && as_unpack_peek_is_ext(&pk)) {
		as_msgpack_ext ext;

		if (as_unpack_ext(&pk, &ext) != 0) {
			return false;
		}

		op->ext_flags = ext.type;
		op->ele_count--;

		op->content_sz = op->packed_sz - (uint32_t)pk.offset;
		list_offset_index_init(&op->offidx, NULL, op->ele_count,
				op->content_sz);

		if ((op->ext_flags & PACKED_LIST_FLAG_OFF_IDX) &&
				(size_t)ext.size >= offset_index_size(&op->offidx)) {
			offset_index_set_ptr(&op->offidx, (uint8_t *)ext.data,
					op->packed + pk.offset);
		}
	}
	else {
		op->content_sz = op->packed_sz - (uint32_t)pk.offset;
		list_offset_index_init(&op->offidx, NULL, op->ele_count,
				op->content_sz);
		op->ext_flags = 0;
	}

	op->contents = op->packed + pk.offset;

	return true;
}

// Calculate a packed list split via insert op.
// Return negative int on failure, new size of packed buffer.
static int64_t
packed_list_op_insert(packed_list_op *op, uint32_t index, uint32_t count,
		uint32_t insert_sz)
{
	uint32_t ele_count = op->ele_count;

	if (index >= ele_count) { // insert off the end
		if (index + count >= INT32_MAX) {
			cf_warning(AS_PARTICLE, "as_packed_list_insert() index %u + count %u overflow", index, count);
			return -1;
		}

		op->new_ele_count = index + count;
		op->nil_ele_sz = index - ele_count;

		op->seg1_sz = op->content_sz;
		op->seg2_sz = 0;
	}
	else { // insert front or middle
		op->new_ele_count = ele_count + count;
		op->nil_ele_sz = 0;
		uint32_t offset = packed_list_op_find_idx_offset(op, index);

		if (index != 0 && offset == 0) {
			return -2;
		}

		op->seg1_sz = offset;
		op->seg2_index = offset;
		op->seg2_sz = op->content_sz - offset;
	}

	return (int64_t)(op->seg1_sz + op->nil_ele_sz + insert_sz + op->seg2_sz);
}

// Calculate a packed list split via remove op.
// Return negative int on failure, new size of packed buffer.
static int32_t
packed_list_op_remove(packed_list_op *op, uint32_t index, uint32_t count)
{
	uint32_t ele_count = op->ele_count;

	if (index >= ele_count) { // nothing to remove
		op->seg1_sz = op->content_sz;
		op->seg2_sz = 0;
		op->new_ele_count = ele_count;

		return (int32_t)op->content_sz;
	}

	uint32_t offset = packed_list_op_find_idx_offset(op, index);

	if (index != 0 && offset == 0) {
		return -1;
	}

	if (count >= ele_count - index) { // remove tail elements
		op->new_ele_count = index;

		op->seg1_sz = offset;
		op->seg2_index = 0;
		op->seg2_sz = 0;
	}
	else { // remove front or middle
		op->new_ele_count = ele_count - count;

		op->seg1_sz = offset;

		as_unpacker pk = {
				.buffer = op->contents,
				.offset = (int)offset,
				.length = op->content_sz
		};

		for (uint32_t i = 0; i < count; i++) {
			if (as_unpack_size(&pk) < 0) {
				return -2 - i;
			}
		}

		op->seg2_index = (uint32_t)pk.offset;
		op->seg2_sz = (uint32_t)(pk.length - pk.offset);
	}

	return (int32_t)(op->seg1_sz + op->seg2_sz);
}

// Write segment 1 and trailing nils if any.
// Return number of bytes written.
static uint32_t
packed_list_op_write_seg1(const packed_list_op *op, uint8_t *buf)
{
	memcpy(buf, op->contents, op->seg1_sz);

	if (op->nil_ele_sz == 0) {
		return op->seg1_sz;
	}

	buf += op->seg1_sz;
	memset(buf, msgpack_nil[0], op->nil_ele_sz);

	return op->seg1_sz + op->nil_ele_sz;
}

// Write segment 2 if any.
// Return number of bytes written.
static uint32_t
packed_list_op_write_seg2(const packed_list_op *op, uint8_t *buf)
{
	if (op->seg2_sz == 0) {
		return 0;
	}

	memcpy(buf, op->contents + op->seg2_index, op->seg2_sz);

	return op->seg2_sz;
}

static uint32_t
packed_list_op_find_idx_offset(const packed_list_op *op, uint32_t index)
{
	if (index == 0) {
		return 0;
	}

	as_unpacker pk = {
			.buffer = op->contents,
			.length = op->content_sz
	};

	uint32_t steps = index;

	if (offset_index_is_valid(&op->offidx)) {
		uint32_t idx = index / PACKED_LIST_INDEX_STEP;
		uint32_t filled = offset_index_get_filled(&op->offidx);

		if (idx >= filled) {
			cf_assert(filled != 0, AS_PARTICLE, "packed_list_op_find_idx_offset() filled is zero");
			idx = filled - 1;
		}

		pk.offset = (int)offset_index_get_const(&op->offidx, idx);
		steps -= idx * PACKED_LIST_INDEX_STEP;

		offset_index *offidx = (offset_index *)&op->offidx; // mutable struct variable
		uint32_t blocks = steps / PACKED_LIST_INDEX_STEP;

		steps %= PACKED_LIST_INDEX_STEP;

		for (uint32_t i = 0; i < blocks; i++) {
			for (uint32_t j = 0; j < PACKED_LIST_INDEX_STEP; j++) {
				if (as_unpack_size(&pk) < 0) {
					return 0;
				}
			}

			idx++;
			offset_index_set_next(offidx, idx, (uint32_t)pk.offset);
		}
	}

	for (uint32_t i = 0; i < steps; i++) {
		if (as_unpack_size(&pk) < 0) {
			return 0;
		}
	}

	return (uint32_t)pk.offset;
}

static uint32_t
packed_list_op_list_size(const packed_list_op *op, bool has_ext,
		uint32_t *ext_content_sz_r)
{
	uint32_t hdr_sz = as_pack_list_header_get_size(op->ele_count + 1);

	if (! has_ext) {
		return hdr_sz + op->content_sz;
	}

	uint32_t ext_content_sz =
			list_calc_ext_content_sz(op->ele_count, op->content_sz);
	uint32_t ext_sz = as_pack_ext_header_get_size(ext_content_sz) +
			ext_content_sz;

	if (ext_content_sz_r) {
		*ext_content_sz_r = ext_content_sz;
	}

	return hdr_sz + ext_sz + op->content_sz;
}

static void
packed_list_op_buf_pack(const packed_list_op *op, uint8_t *buf, uint32_t sz,
		bool has_ext, uint32_t ext_content_sz)
{
	as_packer pk = {
			.buffer = buf,
			.capacity = (int)sz
	};

	if (has_ext) {
		as_pack_list_header(&pk, op->ele_count + 1);
		as_pack_ext_header(&pk, ext_content_sz, PACKED_LIST_FLAG_OFF_IDX);
		list_pack_empty_index(&pk, op->ele_count, op->content_sz);
	}
	else {
		as_pack_list_header(&pk, op->ele_count);
	}

	packed_list_op_pack_content(op, &pk);
}

static list_mem *
packed_list_op_list_pack(const packed_list_op *op, list_mem *p_list_mem,
		bool has_ext)
{
	uint32_t ext_content_sz;
	uint32_t sz = packed_list_op_list_size(op, has_ext, &ext_content_sz);

	if (! p_list_mem && ! (p_list_mem = cf_malloc_ns(sizeof(list_mem) + sz))) {
		return NULL;
	}

	p_list_mem->sz = sz;
	packed_list_op_buf_pack(op, p_list_mem->data, sz, has_ext, ext_content_sz);

	return p_list_mem;
}

static void
packed_list_op_pack_content(const packed_list_op *op, as_packer *pk)
{
	uint8_t *ptr = pk->buffer + pk->offset;

	memcpy(ptr, op->contents, op->content_sz);
	pk->offset += (int)op->content_sz;
}

//----------------------------------------------------------
// packed_list
//

// Create a non-indexed list.
// If alloc_buf is NULL, memory is reserved using cf_malloc.
static list_mem *
packed_list_create(rollback_alloc *alloc_buf, uint32_t ele_count,
		uint32_t content_sz)
{
	uint32_t hdr_sz = as_pack_list_header_get_size(ele_count);
	uint32_t sz = hdr_sz + content_sz;
	list_mem *p_list_mem = (list_mem *)rollback_alloc_reserve(alloc_buf,
			sizeof(list_mem) + sz);

	if (! p_list_mem) {
		rollback_alloc_rollback(alloc_buf);
		return NULL;
	}

	p_list_mem->type = AS_PARTICLE_TYPE_LIST;
	p_list_mem->sz = sz;

	return p_list_mem;
}

static as_particle *
packed_list_simple_create_from_buf(rollback_alloc *alloc_buf,
		uint32_t ele_count, const uint8_t *contents, uint32_t content_sz)
{
	list_mem *p_list_mem = packed_list_create(alloc_buf, ele_count, content_sz);

	if (p_list_mem) {
		uint32_t hdr_sz = list_pack_header(p_list_mem->data, ele_count);

		if (content_sz > 0 && contents) {
			memcpy(p_list_mem->data + hdr_sz, contents, content_sz);
		}
	}

	return (as_particle *)p_list_mem;
}

as_particle *
packed_list_simple_create_empty(rollback_alloc *alloc_buf)
{
	return packed_list_simple_create_from_buf(alloc_buf, 0, NULL, 0);
}

static int
packed_list_append(as_bin *b, rollback_alloc *alloc_buf,
		const cdt_payload *payload, bool payload_is_container, as_bin *result)
{
	packed_list_op op;

	if (! packed_list_op_init_from_bin(&op, b)) {
		cf_warning(AS_PARTICLE, "packed_list_append() invalid packed list");
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	return packed_list_insert(b, alloc_buf, payload, payload_is_container,
			(int64_t)op.ele_count, result);
}

static int
packed_list_insert(as_bin *b, rollback_alloc *alloc_buf,
		const cdt_payload *payload, bool payload_is_container, int64_t index,
		as_bin *result)
{
	uint32_t count = 1;
	uint32_t payload_hdr_sz = 0;

	if (payload_is_container) {
		int64_t payload_count =
				as_unpack_buf_list_element_count(payload->ptr, payload->sz);

		if (payload_count < 0) {
			cf_warning(AS_PARTICLE, "packed_list_insert() invalid payload, expected a list");
			return -AS_PROTO_RESULT_FAIL_PARAMETER;
		}

		if (payload_count == 0) {
			return AS_PROTO_RESULT_OK;
		}

		count = (uint32_t)payload_count;
		payload_hdr_sz = as_pack_list_header_get_size((uint32_t)payload_count);

		if (payload_hdr_sz > payload->sz) {
			cf_warning(AS_PARTICLE, "packed_list_insert() invalid list header: payload->size=%d", payload->sz);
			return -AS_PROTO_RESULT_FAIL_PARAMETER;
		}
	}

	packed_list_op op;

	if (! packed_list_op_init_from_bin(&op, b)) {
		cf_warning(AS_PARTICLE, "packed_list_insert() invalid list");
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t ele_count = op.ele_count;

	if (index > INT32_MAX || (index = calc_index(index, ele_count)) < 0) {
		cf_warning(AS_PARTICLE, "packed_list_insert() index %ld out of bounds for ele_count %d", index > 0 ? index : index - ele_count, ele_count);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t uindex = (uint32_t)index;
	int64_t content_sz = packed_list_op_insert(&op, uindex, count,
			payload->sz - payload_hdr_sz);

	if (content_sz < 0) {
		cf_warning(AS_PARTICLE, "packed_list_insert() packed_list_insert failed with ret=%ld", content_sz);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	if (content_sz > (int64_t)UINT32_MAX) {
		cf_warning(AS_PARTICLE, "packed_list_insert() mem size overflow with new_size=%ld", content_sz);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint8_t *ptr = packed_list_setup_bin(b, alloc_buf, (uint32_t)content_sz,
			op.new_ele_count, uindex, &op.offidx);

	if (! ptr) {
		cf_warning(AS_PARTICLE, "packed_list_insert() failed to alloc list particle");
		return -AS_PROTO_RESULT_FAIL_UNKNOWN;
	}

	int32_t ret = packed_list_op_write_seg1(&op, ptr);

	if (ret < 0) {
		cf_warning(AS_PARTICLE, "packed_list_insert() write seg1 failed with ret=%d", ret);
		return -AS_PROTO_RESULT_FAIL_UNKNOWN;
	}

	ptr += ret;

	const uint8_t *p = payload->ptr + payload_hdr_sz;
	uint32_t sz = payload->sz - payload_hdr_sz;

	memcpy(ptr, p, sz);
	ptr += sz;

	packed_list_op_write_seg2(&op, ptr);

	if (result) {
		as_bin_set_int(result, op.new_ele_count);
	}

	return AS_PROTO_RESULT_OK;
}

// count == 0 means missing count.
static int
packed_list_remove(as_bin *b, rollback_alloc *alloc_buf, int64_t index,
		uint64_t count, as_bin *result, bool result_is_count,
		bool result_is_list, rollback_alloc *alloc_result)
{
	packed_list_op op;

	if (! packed_list_op_init_from_bin(&op, b)) {
		cf_warning(AS_PARTICLE, "packed_list_remove() invalid list header");
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t ele_count = op.ele_count;

	if (index >= ele_count || (index = calc_index(index, ele_count)) < 0) {
		cf_warning(AS_PARTICLE, "packed_list_remove() index %ld out of bounds for ele_count %d", index > 0 ? index : index - ele_count, ele_count);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t uindex = (uint32_t)index;

	count = calc_count((uint64_t)index, count, ele_count);

	int32_t content_sz = packed_list_op_remove(&op, uindex, (uint32_t)count);

	if (content_sz < 0) {
		cf_warning(AS_PARTICLE, "packed_list_remove() as_packed_list_remove failed with ret=%d", content_sz);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	if (op.new_ele_count == 0) {
		as_bin_set_empty_packed_list(b, alloc_buf);
	}
	else {
		uint8_t *ptr = packed_list_setup_bin(b, alloc_buf, (uint32_t)content_sz,
				op.new_ele_count, uindex, &op.offidx);

		if (! ptr) {
			cf_warning(AS_PARTICLE, "packed_list_remove() failed to alloc list particle");
			return -AS_PROTO_RESULT_FAIL_UNKNOWN;
		}

		int32_t ret = packed_list_op_write_seg1(&op, ptr);

		cf_assert(ret >= 0, AS_PARTICLE, "packed_list_remove() write seg1 failed with ret=%d", ret);

		ptr += ret;

		packed_list_op_write_seg2(&op, ptr);
	}

	if (result) {
		uint32_t result_count = op.ele_count - op.new_ele_count;

		if (result_is_count) {
			as_bin_set_int(result, result_count);
		}
		else {
			const uint8_t *result_ptr = op.contents + op.seg1_sz;
			uint32_t end = (op.seg2_sz != 0) ? op.seg2_index : op.content_sz;
			uint32_t result_sz = end - op.seg1_sz;

			if (result_is_list) {
				result->particle =
						packed_list_simple_create_from_buf(alloc_result,
								result_count, result_ptr, result_sz);

				if (! result->particle) {
					return -AS_PROTO_RESULT_FAIL_UNKNOWN;
				}

				as_bin_state_set_from_type(result, AS_PARTICLE_TYPE_LIST);
			}
			else if (result_sz > 0) {
				cf_assert(count <= 1, AS_PARTICLE, "packed_list_remove() result must be list for count > 1");
				as_bin_particle_alloc_from_msgpack(result, result_ptr,
						result_sz);
			}
			// else - leave result bin empty because result_size is 0.
		}
	}

	return AS_PROTO_RESULT_OK;
}

static int
packed_list_set(as_bin *b, rollback_alloc *alloc_buf,
		const cdt_payload *payload, int64_t index)
{
	packed_list_op op;

	if (! packed_list_op_init_from_bin(&op, b)) {
		cf_warning(AS_PARTICLE, "packed_list_set() invalid list");
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t ele_count = op.ele_count;

	if (index >= ele_count) {
		return packed_list_insert(b, alloc_buf, payload, false, index, NULL);
	}

	if (index > UINT32_MAX || (index = calc_index(index, ele_count)) < 0) {
		cf_warning(AS_PARTICLE, "packed_list_set() index %ld out of bounds for ele_count %d", index > 0 ? index : index - ele_count, ele_count);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t uindex = (uint32_t)index;
	int32_t content_sz = packed_list_op_remove(&op, uindex, 1);

	if (content_sz < 0) {
		cf_warning(AS_PARTICLE, "packed_list_set() as_packed_list_remove failed with ret=%d", content_sz);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	content_sz += payload->sz;

	uint8_t *ptr = packed_list_setup_bin(b, alloc_buf, (uint32_t)content_sz,
			ele_count, uindex, &op.offidx);

	if (! ptr) {
		cf_warning(AS_PARTICLE, "packed_list_set() failed to alloc list particle");
		return -AS_PROTO_RESULT_FAIL_UNKNOWN;
	}

	ptr += packed_list_op_write_seg1(&op, ptr);

	memcpy(ptr, payload->ptr, payload->sz);
	ptr += payload->sz;

	packed_list_op_write_seg2(&op, ptr);

	return AS_PROTO_RESULT_OK;
}

static int
packed_list_increment(as_bin *b, rollback_alloc *alloc_buf, int64_t index,
		cdt_payload *delta_value, as_bin *result)
{
	packed_list_op op;

	if (! packed_list_op_init_from_bin(&op, b)) {
		cf_warning(AS_PARTICLE, "packed_list_increment() invalid list");
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t ele_count = op.ele_count;

	if (index > INT32_MAX || (index = calc_index(index, ele_count)) < 0) {
		cf_warning(AS_PARTICLE, "packed_list_increment() index %ld out of bounds for ele_count %d", index > 0 ? index : index - ele_count, ele_count);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t uindex = (uint32_t)index;

	cdt_calc_delta calc_delta;

	if (! cdt_calc_delta_init(&calc_delta, delta_value, false)) {
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	if (uindex < ele_count) {
		uint32_t offset = packed_list_op_find_idx_offset(&op, uindex);

		if (uindex != 0 && offset == 0) {
			cf_warning(AS_PARTICLE, "packed_list_increment() unable to unpack element at %u", uindex);
			return -AS_PROTO_RESULT_FAIL_PARAMETER;
		}

		as_unpacker pk = {
				.buffer = op.contents + offset,
				.length = op.content_sz - offset
		};

		if (! cdt_calc_delta_add(&calc_delta, &pk)) {
			return -AS_PROTO_RESULT_FAIL_PARAMETER;
		}
	}
	else {
		if (! cdt_calc_delta_add(&calc_delta, NULL)) {
			return -AS_PROTO_RESULT_FAIL_PARAMETER;
		}
	}

	uint8_t value_buf[CDT_MAX_PACKED_INT_SZ];
	cdt_payload value = {
			.ptr = value_buf,
			.sz = 0
	};

	cdt_calc_delta_pack_and_result(&calc_delta, &value, result);

	return packed_list_set(b, alloc_buf, &value, (int64_t)uindex);
}

static int
packed_list_trim(as_bin *b, rollback_alloc *alloc_buf, int64_t index,
		uint64_t count, as_bin *result)
{
	// Remove head section.
	packed_list_op op;

	if (! packed_list_op_init_from_bin(&op, b)) {
		cf_warning(AS_PARTICLE, "packed_list_trim() invalid list");
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	if (count == 0) {
		// Remove everything.
		as_bin_set_int(result, op.ele_count);
		as_bin_set_empty_packed_list(b, alloc_buf);

		return AS_PROTO_RESULT_OK;
	}

	uint32_t ele_count = op.ele_count;

	if (index >= ele_count || (index = calc_index(index, ele_count)) < 0) {
		cf_warning(AS_PARTICLE, "packed_list_trim() index %ld out of bounds for ele_count %d", index > 0 ? index : index - ele_count, ele_count);
		return -AS_PROTO_RESULT_FAIL_PARAMETER;
	}

	uint32_t uindex = (uint32_t)index;

	count = calc_count((uint64_t)index, count, ele_count);

	if (uindex + (uint32_t)count == ele_count) {
		return packed_list_remove(b, alloc_buf, index, count, result, true,
				false, NULL);
	}

	uint32_t new_count = (uint32_t)count;
	uint32_t offset0 = packed_list_op_find_idx_offset(&op, uindex);
	uint32_t offset1 = packed_list_op_find_idx_offset(&op, uindex + new_count);
	uint32_t content_sz = offset1 - offset0;
	uint8_t *ptr = packed_list_setup_bin(b, alloc_buf, content_sz, new_count,
			uindex, &op.offidx);

	if (! ptr) {
		cf_warning(AS_PARTICLE, "packed_list_trim() failed to alloc list particle");
		return -AS_PROTO_RESULT_FAIL_UNKNOWN;
	}

	memcpy(ptr, op.contents + offset0, content_sz);
	as_bin_set_int(result, ele_count - new_count);

	return AS_PROTO_RESULT_OK;
}

// Return ptr to packed + ele_start.
static uint8_t *
packed_list_setup_bin(as_bin *b, rollback_alloc *alloc_buf, uint32_t content_sz,
		uint32_t ele_count, uint32_t idx_trunc, const offset_index *old_offidx)
{
	uint32_t ext_content_sz = list_calc_ext_content_sz(ele_count, content_sz);
	uint32_t ext_sz = (ext_content_sz == 0) ?
			0 : as_pack_ext_header_get_size(ext_content_sz) + ext_content_sz;
	list_mem *p_list_mem = packed_list_create(alloc_buf,
			ele_count + (ext_sz == 0 ? 0 : 1), ext_sz + content_sz);

	if (! p_list_mem) {
		return NULL;
	}

	b->particle = (as_particle *)p_list_mem;

	as_packer pk = {
			.buffer = p_list_mem->data,
			.capacity = p_list_mem->sz
	};

	if (ext_content_sz == 0) {
		as_pack_list_header(&pk, ele_count);
		return pk.buffer + pk.offset;
	}

	as_pack_list_header(&pk, ele_count + 1);
	as_pack_ext_header(&pk, ext_content_sz, PACKED_LIST_FLAG_OFF_IDX);

	uint8_t *ptr = pk.buffer + pk.offset;
	offset_index offidx;

	list_offset_index_init(&offidx, ptr, ele_count, content_sz);
	idx_trunc /= PACKED_LIST_INDEX_STEP;

	if (idx_trunc == 0) {
		offset_index_set_filled(&offidx, 1);
	}
	else {
		if (idx_trunc > offset_index_get_filled(old_offidx)) {
			idx_trunc = offset_index_get_filled(old_offidx);
		}

		offset_index_copy(&offidx, old_offidx, 0, 0, idx_trunc, 0);
		offset_index_set_filled(&offidx, idx_trunc);
	}

	return ptr + offset_index_size(&offidx);
}


//==========================================================
// cdt_list_builder
//

bool
cdt_list_builder_start(cdt_container_builder *builder,
		rollback_alloc *alloc_buf, uint32_t ele_count, uint32_t max_sz)
{
	uint32_t sz = sizeof(list_mem) + sizeof(uint64_t) + 1 + max_sz;
	list_mem *p_list_mem = (list_mem *)rollback_alloc_reserve(alloc_buf, sz);

	if (! p_list_mem) {
		return false;
	}

	p_list_mem->type = AS_PARTICLE_TYPE_LIST;
	p_list_mem->sz = list_pack_header(p_list_mem->data, ele_count);

	builder->particle = (as_particle *)p_list_mem;
	builder->write_ptr = p_list_mem->data + p_list_mem->sz;
	builder->ele_count = 0;
	builder->sz = &p_list_mem->sz;

	return true;
}


//==========================================================
// cdt_process_state_packed_list
//

bool
cdt_process_state_packed_list_modify_optype(cdt_process_state *state,
		cdt_modify_data *cdt_udata)
{
	as_bin *b = cdt_udata->b;
	as_bin *result = cdt_udata->result;
	as_cdt_optype optype = state->type;

	if (! is_list_type(as_bin_get_particle_type(b)) && as_bin_inuse(b)) {
		cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() invalid type %d", as_bin_get_particle_type(b));
		cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
		return false;
	}

	rollback_alloc_inita(alloc_buf, cdt_udata->alloc_buf, 5, true);
	// Results always on the heap.
	rollback_alloc_inita(alloc_result, NULL, 1, false);

	switch (optype) {
	// Add to list.
	case AS_CDT_OP_LIST_APPEND: {
		cdt_payload payload;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &payload)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		as_bin_create_temp_packed_list_if_notinuse(b);

		int ret = packed_list_append(b, alloc_buf, &payload, false, result);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() APPEND failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		break;
	}
	case AS_CDT_OP_LIST_APPEND_ITEMS: {
		cdt_payload payload;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &payload)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		as_bin_create_temp_packed_list_if_notinuse(b);

		int ret = packed_list_append(b, alloc_buf, &payload, true, result);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() APPEND_ITEMS failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		if (as_bin_is_temp_packed_list(b)) {
			b->particle = packed_list_simple_create_empty(alloc_buf);
			as_bin_state_set_from_type(b, AS_PARTICLE_TYPE_LIST);
		}

		break;
	}
	case AS_CDT_OP_LIST_INSERT: {
		int64_t index;
		cdt_payload payload;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index, &payload)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		as_bin_create_temp_packed_list_if_notinuse(b);

		int ret = packed_list_insert(b, alloc_buf, &payload, false, index,
				result);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() INSERT failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		break;
	}
	case AS_CDT_OP_LIST_INSERT_ITEMS: {
		const cdt_payload payload;
		int64_t index;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index, &payload)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		as_bin_create_temp_packed_list_if_notinuse(b);

		int ret = packed_list_insert(b, alloc_buf, &payload, true, index,
				result);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() INSERT_ITEMS failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		if (as_bin_is_temp_packed_list(b)) {
			b->particle = packed_list_simple_create_empty(alloc_buf);
			as_bin_state_set_from_type(b, AS_PARTICLE_TYPE_LIST);
		}

		break;
	}
	case AS_CDT_OP_LIST_SET: {
		cdt_payload payload;
		int64_t index;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index, &payload)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		as_bin_create_temp_packed_list_if_notinuse(b);

		int ret = packed_list_set(b, alloc_buf, &payload, index);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() SET failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		break;
	}

	// OP by Index
	case AS_CDT_OP_LIST_REMOVE:
	case AS_CDT_OP_LIST_POP: {
		int64_t index;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		if (! is_list_type(as_bin_get_particle_type(b))) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
			return false;
		}

		int ret = packed_list_remove(b, alloc_buf, index, 1, result,
				optype == AS_CDT_OP_LIST_REMOVE, false, alloc_result);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() POP/REMOVE failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_result);
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		break;
	}
	case AS_CDT_OP_LIST_REMOVE_RANGE:
	case AS_CDT_OP_LIST_POP_RANGE: {
		int64_t index;
		uint64_t count;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index, &count)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		if (! is_list_type(as_bin_get_particle_type(b))) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
			return false;
		}

		// User specifically asked for 0 count.
		if (state->ele_count == 2 && count == 0) {
			if (optype == AS_CDT_OP_LIST_POP_RANGE) {
				result->particle =
						packed_list_simple_create_empty(alloc_result);
				as_bin_state_set_from_type(result, AS_PARTICLE_TYPE_LIST);
			}
			else {
				as_bin_set_int(result, 0);
			}

			break;
		}

		int ret = packed_list_remove(b,
				alloc_buf,
				index,
				state->ele_count == 1 ? 0 : count,
				result,
				optype == AS_CDT_OP_LIST_REMOVE_RANGE,	// result_is_count
				optype == AS_CDT_OP_LIST_POP_RANGE,		// result_is_list
				alloc_result);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() POP_RANGE/REMOVE_RANGE failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_result);
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		break;
	}
	// Misc
	case AS_CDT_OP_LIST_CLEAR: {
		if (! is_list_type(as_bin_get_particle_type(b))) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
			return false;
		}

		as_bin_set_empty_packed_list(b, alloc_buf);

		break;
	}
	case AS_CDT_OP_LIST_INCREMENT: {
		int64_t index;
		cdt_payload delta_value;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index, &delta_value)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		as_bin_create_temp_packed_list_if_notinuse(b);

		int ret = packed_list_increment(b, alloc_buf, index,
				state->ele_count >= 2 ? &delta_value : NULL, result);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() INCREMENT failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		break;
	}
	case AS_CDT_OP_LIST_TRIM: {
		int64_t index;
		uint64_t count;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index, &count)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		if (! is_list_type(as_bin_get_particle_type(b))) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
			return false;
		}

		int ret = packed_list_trim(b, alloc_buf, index, count, result);

		if (ret < 0) {
			cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() TRIM failed");
			cdt_udata->ret_code = ret;
			rollback_alloc_rollback(alloc_buf);
			return false;
		}

		break;
	}
	default:
		cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_modify_optype() invalid cdt op: %d", optype);
		cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
		return false;
	}

	return true;
}

bool
cdt_process_state_packed_list_read_optype(cdt_process_state *state,
		cdt_read_data *cdt_udata)
{
	const as_bin *b = cdt_udata->b;
	as_bin *result = cdt_udata->result;
	as_cdt_optype optype = state->type;

	if (! is_list_type(as_bin_get_particle_type(b))) {
		cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_INCOMPATIBLE_TYPE;
		return false;
	}

	// Just one entry needed for results bin.
	rollback_alloc_inita(packed_alloc, NULL, 1, false);

	switch (optype) {
	case AS_CDT_OP_LIST_GET: {
		int64_t index;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		packed_list_op op;

		if (! packed_list_op_init_from_bin(&op, b)) {
			cf_warning(AS_PARTICLE, "OP_LIST_GET: invalid list header");
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		uint32_t ele_count = op.ele_count;

		if (index >= ele_count || (index = calc_index(index, ele_count)) < 0) {
			cf_warning(AS_PARTICLE, "OP_LIST_GET: index %ld out of bounds for ele_count %d", index > 0 ? index : index - ele_count, ele_count);
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		uint32_t uindex = (uint32_t)index;
		uint32_t offset = packed_list_op_find_idx_offset(&op, uindex);

		if (uindex != 0 && offset == 0) {
			cf_warning(AS_PARTICLE, "OP_LIST_GET: unable to unpack element at %u", uindex);
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		as_unpacker pk = {
				.buffer = op.contents + offset,
				.length = op.content_sz - offset
		};

		int64_t ele_sz = as_unpack_size(&pk);

		if (ele_sz < 0) {
			cf_warning(AS_PARTICLE, "OP_LIST_GET: unable to unpack element at %u", uindex);
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_UNKNOWN;
			return false;
		}

		if (ele_sz != 0) {
			as_bin_particle_alloc_from_msgpack(result, pk.buffer,
					(uint32_t)ele_sz);
		}
		// else - leave result bin empty because ele_size is 0.

		break;
	}
	case AS_CDT_OP_LIST_GET_RANGE: {
		int64_t index;
		uint64_t count;

		if (! CDT_OP_TABLE_GET_PARAMS(state, &index, &count)) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		packed_list_op op;

		if (! packed_list_op_init_from_bin(&op, b)) {
			cf_warning(AS_PARTICLE, "OP_LIST_GET_RANGE: invalid list header");
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		uint32_t ele_count = op.ele_count;

		if (index >= ele_count || (index = calc_index(index, ele_count)) < 0) {
			cf_warning(AS_PARTICLE, "OP_LIST_GET_RANGE: index %ld out of bounds for ele_count %d", index > 0 ? index : index - ele_count, ele_count);
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		// User specifically asked for 0 count.
		if (state->ele_count == 2 && count == 0) {
			result->particle = packed_list_simple_create_empty(packed_alloc);
			as_bin_state_set_from_type(result, AS_PARTICLE_TYPE_LIST);

			break;
		}

		// If missing count, take the rest of the list.
		count = calc_count((uint64_t)index,
				state->ele_count == 1 ? 0 : (uint32_t)count, ele_count);

		uint32_t uindex = (uint32_t)index;
		uint32_t offset = packed_list_op_find_idx_offset(&op, uindex);

		if (uindex != 0 && offset == 0) {
			cf_warning(AS_PARTICLE, "OP_LIST_GET_RANGE: invalid list element with index <= %u", uindex);
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
			return false;
		}

		as_unpacker pk = {
				.buffer = op.contents + offset,
				.length = op.content_sz - offset
		};

		uint32_t ele_sz = 0;

		for (uint64_t i = 0; i < count; i++) {
			int64_t i_sz = as_unpack_size(&pk);

			if (i_sz < 0) {
				cf_warning(AS_PARTICLE, "OP_LIST_GET_RANGE: invalid list element at index %u", uindex + (uint32_t)i);
				cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
				return false;
			}

			ele_sz += (uint32_t)i_sz;
		}

		result->particle = packed_list_simple_create_from_buf(packed_alloc,
				count, pk.buffer, ele_sz);

		if (! result->particle) {
			cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_UNKNOWN;
			return false;
		}

		as_bin_state_set_from_type(result, AS_PARTICLE_TYPE_LIST);

		break;
	}
	case AS_CDT_OP_LIST_SIZE: {
		packed_list_op op;

		if (! packed_list_op_init_from_bin(&op, b)) {
			// TODO - is this the right policy?
			as_bin_set_int(result, 0);
		}
		else {
			as_bin_set_int(result, op.ele_count);
		}

		break;
	}
	default:
		cf_warning(AS_PARTICLE, "cdt_process_state_packed_list_read_optype() invalid cdt op: %d", optype);
		cdt_udata->ret_code = -AS_PROTO_RESULT_FAIL_PARAMETER;
		return false;
	}

	return true;
}


//==========================================================
// Debugging support.
//

static void
print_cdt_list_particle(const as_particle *p)
{
	list_mem *p_list_mem = (list_mem *)p;

	cf_warning(AS_PARTICLE, "print_cdt_list_particle: type=%d", p_list_mem->type);
	cf_warning(AS_PARTICLE, "  packed_sz=%d", p_list_mem->sz);
	char buf[1024];
	print_hex(p_list_mem->data, p_list_mem->sz, buf, 1024);
	cf_warning(AS_PARTICLE, "  packed=%s", buf);
}

void
print_cdt_list_bin(const as_bin *b)
{
	int8_t type = as_bin_get_particle_type(b);
	cf_warning(AS_PARTICLE, "print_cdt_list_bin: type=%d", type);

	if (type != AS_PARTICLE_TYPE_LIST) {
		return;
	}

	print_cdt_list_particle(b->particle);
}

void
print_packed_list_op(const packed_list_op *op)
{
	char buf[1024];

	print_hex(op->packed, op->packed_sz, buf, 1024);
	cf_warning(AS_PARTICLE, "as_packed_list: buf='%s' buf_sz=%u ele_count=%u", buf, op->packed_sz, op->ele_count);
}
