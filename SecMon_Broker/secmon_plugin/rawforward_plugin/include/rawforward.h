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


#ifndef _RAWFORWARD_H_
#define _RAWFORWARD_H_

/** @file
 *  rawforward header
 */

#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>

#include "utils.h"

#define CONF_FILE   			"/opt/secmon/plugins/config/conf_params.cfg"		/**< Path to config file */

/**
 *	Struct containing information about policy object
 */
struct policy_object
{
    char policy_id[MAX_ID_LEN];			/**< Policy ID */
};

int init();
int config();
int receive_data();
int deinit();

void *get_configurations(void *arg);
#ifdef USE_RING
void *get_packets(void *arg);
#endif
void apply_filters(struct Tuple *tuple ,  uint32_t hash_code , bool *found);

struct Collector_object *append_collectors(struct Collector_object *cobj ,  uint32_t hash_code , 
        struct Collector_object *cobj_head);

inline bool hash_entry_available(uint32_t value);
void send_to_tools(char *pkt ,  unsigned int hash_code ,  int pkt_len);
void initialize_hash_table(void);

/* uncomment if needed sflow plugin */
/*
char *get_interface_ip();
void init_sflow(char *);
*/
void add_configurations(void);

void *hash_timer(void *arg);
void *configurations(void *arg);
void fetch_all_config(void);
void remove_hash_entry(unsigned int i);
void decrement_session(struct Collector_object *collec_obj);

#endif
