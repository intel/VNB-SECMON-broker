/*    Copyright (c) 2016 Intel Corporation.
 *    All Rights Reserved.
 *
 *    Licensed under the Apache License ,  Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing ,  software
 *    distributed under the License is distributed on an "AS IS" BASIS ,  WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND ,  either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */


#ifndef _UTILS_H
#define _UTILS_H

/** @file
 *  utils header for netflow plugin
 */

#include "common.h"


enum 
{
    COLLECTOR=0,
    COLLECTOR_SET=1,
};
extern struct rule_hash *netflow_rule_hash_table[HASH_TABLE_SIZE];
extern struct Collector_object *collector_obj_head;
extern int *netflow_rule_futex;

struct Collector_object *append_tools(struct Collector_object *cobj, struct Collector_object *cobj_head,                                       bool in_collector_set);


void add_hash_entry(uint32_t hash_code, bool action, uint32_t truncate_to_size);
                      struct Collector_object *fetch_tools(uint32_t hash_code);
void add_tools_to_hash(uint32_t hash_code, struct Collector_object *cobj);

struct Collector_object *copy_collector_details(void *cobj, struct Collector_object *cobj_head, 
                                                bool in_collector_set, uint8_t load_balancer_algo);

struct Collector_details *get_collector_by_sessions(struct Collector_object *cobj);
struct Collector_details *get_collector_by_round_robin(struct Collector_object *cobj);
struct Collector_details *get_collector_by_weighted_round_robin(struct Collector_object *cobj);
struct Collector_details* find_collector_set_by_id(struct Collector_object *cobj, char *id);
#endif
