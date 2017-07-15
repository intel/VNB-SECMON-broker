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

/* @file
 * 	contains functions to parse the packet ,  utility functions related to hash table ,  
 * 	function to strip gtp header. 
 */

#include <arpa/inet.h>
#include <rte_mbuf.h>

#include "utils.h"

struct rule_hash *hash_table[HASH_TABLE_SIZE];

/**  initialize rule hash table with null entries
 *   @returns void
 *
 */
void initialize_hash_table(void)
{
    int i;
    for(i = 0;i<HASH_TABLE_SIZE;i++)
    {
        hash_table[i]  =  NULL;
    }
}

/** add hash entry to hash table for rawforward plugin
 * @param 
 *      hash_code - index of the hash to store
 * @param
 *      action - action to perform when a packet matches the rule ,  forward or drop
 * @param
 *      truncate_to_size - packet size to truncate
 * @returns 
 *      void
 */
void add_hash_entry(uint32_t hash_code,  bool action ,  uint32_t truncate_to_size)
{

    struct rule_hash *hash_entry  =  (struct rule_hash *)malloc(sizeof(struct rule_hash));
    memset(hash_entry, '\0',sizeof(struct rule_hash));
    hash_entry->next  =  NULL;
    hash_entry->collectors  =  (struct Collector_object *)malloc(sizeof(struct Collector_object));
    memset(hash_entry->collectors, '\0',sizeof(struct Collector_object));
    hash_entry->collectors->next  =  NULL;
    if(hash_table[hash_code] == NULL)
    {
        hash_table[hash_code]  =  hash_entry;
        hash_table[hash_code]->action  =  action;
        //hash_table[hash_code]->encap_protocol  =  encap_protocol;
        hash_table[hash_code]->truncate_to_size  =  truncate_to_size;
    }
    else
    {
        struct rule_hash *rhash  =  hash_table[hash_code];
        while(rhash != NULL)
        {
            rhash  =  rhash->next;
        }
        rhash  =  hash_entry; 
        rhash->action  =  action;
        //rhash->encap_protocol  =  encap_protocol;
        rhash->truncate_to_size  =  truncate_to_size;
    }
}

/** checks whether a hash entry with value hash is available 
 * in the hash table or not.
 * @param
 * 	hash - index of the hash to find
 * @return 
 * 	TRUE - if found
 * 	FALSE - if not found
 */
inline bool hash_entry_available(uint32_t hash)
{
    if(hash_table[hash] != NULL)
    {
        return TRUE;
    }
    return FALSE;
}

