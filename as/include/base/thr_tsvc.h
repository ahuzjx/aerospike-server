/*
 * thr_tsvc.h
 *
 * Copyright (C) 2008-2016 Aerospike, Inc.
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

#include "base/transaction.h"

int thr_tsvc_process_or_enqueue(as_transaction *tr);
int thr_tsvc_enqueue(as_transaction *tr);
void process_transaction(as_transaction *tr);

// Statistics function for monitoring server load.
extern int thr_tsvc_queue_get_size();

// Initialize the queues and start the handler threads.
extern void as_tsvc_init();
