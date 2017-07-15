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

/** @file
 * Apply filters to packet ,  take tools according to it & process
 * tools 
 *
 */

#include <rte_mbuf.h>

#include <timehelper.h>
#include "utils.h"

#ifdef SECMON_DEBUG_LOG
static int count_apply_filters = 0;
#endif
int tool_count = 0;
/* Loops over each collector_object and find the match
 * for tuple against each classification_object(filter_rule) inside 
 * the collector_object. If any classification_object matches 
 * with the tuple ,  corresponding collector_object details are stored. 
 * This function is called once for every new session.
 *
 * @param tuple 
 *     tuple containing 7 fields (src_mac , dst_mac , src_ip , 
 *     dst_ip , src_port , dst_port , protocol) from the monitored packet.
 * @param hash
 *     hash_value of the tuple
 * @param found
 *     value to update when tuple matches the classification_object
 * @returns void
 *
 */
void apply_filters(struct Tuple *tuple , uint32_t hash , bool *found)
{
  tool *temp  =  collector_obj_head;
  if(unlikely(temp == NULL))
  {
#ifdef SECMON_DEBUG_LOG
    count_apply_filters++;

    if(unlikely(count_apply_filters==1000))
    {
      SECMON_DEBUG("No configurations found for netflow plugin\n");
      count_apply_filters = 0;
    }
#endif
    return;
  }

  uint32_t truncate_to_size;
  bool action  =  DROP;
  bool rule_matched  =  FALSE;

  struct Collector_object *tool_list  =  NULL;

  /* loop over the collectors */
  while(temp != NULL)
  {
    SECMON_DEBUG("Searching collector object\n");

    // rule is classification object
    struct Classification_object *filter_rule  =  temp->classification_object;

    /* loop over each filter rule in collector */
    while(filter_rule != NULL)
    {
      SECMON_DEBUG("Searching classification rules\n");
      /*compare the tuple fields with rule fields. */
      *found  =  compare7tuple(filter_rule , tuple);
      if(*found == TRUE)
      {
        SECMON_DEBUG("found filter rule\n");
        //encap_protocol = temp->collector->encap_protocol;
        truncate_to_size  =  filter_rule->truncate_to_size;
        action  =  filter_rule->action;
        if(action == FORWARD)
        {
          rule_matched  =  TRUE;
          SECMON_DEBUG("adding collector to tools list\n");
          tool_list = append_tools(temp, tool_list, temp->collector_set);
        }
        break;
      }
      filter_rule  =  filter_rule->next;
    }
    temp  =  temp->next;
  }
  //SECMON_DEBUG("Completed searching collectors...\n");
  if(rule_matched == TRUE)
  {
    *found  =  TRUE;
    SECMON_DEBUG("rule matched and action is forward\n");

    /*add the tuple to hash table(cache) */
    add_hash_entry(hash, action, truncate_to_size);
    netflow_rule_hash_table[hash]->last_seen  =  get_jiffies();

    if(likely(tool_list != NULL))
    {
      /* add tools details for both ingress and egress traffic */
      add_tools_to_hash(hash , tool_list);

      while (tool_list)
      {
        struct Collector_object *next_node = tool_list->next;
        free(tool_list);
        tool_list = next_node;
      }

    }
  }
  else
  {
    *found = FALSE;
    SECMON_DEBUG("rule matched and action is drop\n");
  }

  return;
}

/** appends collector object in collector object list to whom we have to send packets
 * @param cobj 
 * 		collector_object to append
 * @param tool_head
 * 		head of collector object list
 * @param is_collector_set
 *    varaible specifying whether the tool is in collector set or not
 * @returns
 *    updated collector object list      
 */
struct Collector_object *append_tools(struct Collector_object *cobj, struct Collector_object *tool_head, bool in_collector_set)
{
  //struct Collector_object *cobj_head;
  if(!in_collector_set)
  {
    SECMON_DEBUG("append_tools: in_collector_set is FALSE, algo = %d\n",cobj->load_balancer_algo);
    return copy_collector_details((void *)cobj, tool_head, in_collector_set, cobj->load_balancer_algo);
  }
  else
  {
    SECMON_DEBUG("append_tools: in_collector_set is TRUE, algo = %d\n",cobj->load_balancer_algo);
    struct Collector_details *collector_details;
    if(cobj->load_balancer_algo == ROUND_ROBIN)
    {
      SECMON_DEBUG("get_collector_by_round_robin. collector_count = %d\n",cobj->collector_count);
      collector_details = get_collector_by_round_robin(cobj);
      collector_details->sessions++;
    }
    else if(cobj->load_balancer_algo == SESSION_BASED)
    {
      SECMON_DEBUG("get_collector_by_sessions \n");
      collector_details = get_collector_by_sessions(cobj);
      collector_details->sessions++;
    }
    else if(cobj->load_balancer_algo == WEIGHTED_ROUND_ROBIN)
    {
      SECMON_DEBUG("get_collector_by_weighted_round_robin \n");
      collector_details = get_collector_by_weighted_round_robin(cobj);
      collector_details->sessions++;
    }
    else
    {
      SECMON_WARN("algorithm not supported\n");
      collector_details = NULL;
    }
    return copy_collector_details((void *)collector_details, tool_head, in_collector_set, cobj->load_balancer_algo);       

  }
  return NULL;
}

/**
 * copies collector details from collector object or collector details
 * if not inside collector set or when inside collector set respectively
 *
 * @param cobj
 *    object that contains collector details which we have to store
 * @param tool_head
 *    head of tool list
 * @param in_collector_set
 *    flag to denote that details passed are inside collector set or not
 * @param algo
 *    load balancing algorithm type
 * @returns
 *    updated tools list
 */
struct Collector_object *copy_collector_details(void *cobj, struct Collector_object *tool_head,
    bool in_collector_set, uint8_t algo)
{
  struct Collector_object *temp = tool_head;
  struct sockaddr_in server_address;
  int socket;
  uint8_t encap_proto;
  struct Collector_object *tool  =  (struct Collector_object *)malloc(sizeof(struct Collector_object));
  memset(tool, '\0', sizeof(struct Collector_object));

  if(in_collector_set == FALSE)
  {
    struct Collector_object *collector_obj = (struct Collector_object *)cobj;
    server_address = collector_obj->server_address;
    socket = collector_obj->socket;
    // encap_proto = collector_obj->encap_protocol;
    encap_proto = collector_obj->collector->encap_protocol;
  }
  else
  {
    struct Collector_details *collector_details = (struct Collector_details *)cobj;
    server_address = collector_details->server_address;
    socket = collector_details->socket;
    encap_proto = collector_details->encap_protocol;
    SECMON_DEBUG("encap_protocol = %d\n",encap_proto);
    // strncpy((char *)tool->collector_id, (char *)collector_details->id, strlen((char *)collector_details->id));
    strncpy((char *)tool->collector_id, (char *)collector_details->id, MAX_ID_LEN);
  }

  tool->server_length = sizeof(struct sockaddr_in);
  tool->server_address = server_address;
  tool->encap_protocol = encap_proto;
  tool->socket = socket;
  tool->load_balancer_algo = algo;
  tool->next = NULL;
  if(temp == NULL)
  {
    tool_head = tool;
  }
  else
  {
    while(temp->next != NULL)
      temp = temp->next;
    temp->next = tool;
  }
  return tool_head;
}

/* returns the head pointer of list of collectors 
 * in the hash entry with hash value hash_code.
 * @param hash_code 
 *     hash code for the tuple. 
 * @returns 
 *     collectors in the hash entry with hash value hash_code. 
 *
 */
inline struct Collector_object *fetch_tools(uint32_t hash_code)
{
  return netflow_rule_hash_table[hash_code]->collectors;
}

/* add tools list to collectors to node
 * in the hash entry with hash value hash_code.
 * @param hash_code 
 *     hash code for the tuple. 
 * @param tools 
 *     tools list to be added to collectors
 * @returns void
 *     
 */
inline void add_tools_to_hash(uint32_t hash_code ,  struct Collector_object *tools)
{
  struct Collector_object *cobj_temp = tools;
  struct Collector_object *cobj_temp1 = netflow_rule_hash_table[hash_code]->collectors;
  while(cobj_temp != NULL)
  {
    SECMON_DEBUG("adding collector objects to hash\n");
    memcpy((void *)&cobj_temp1->server_address,(void *)&cobj_temp->server_address, sizeof(struct sockaddr_in));
    cobj_temp1->server_length = cobj_temp->server_length;
    cobj_temp1->socket = cobj_temp->socket;
    cobj_temp1->encap_protocol = cobj_temp->encap_protocol;
    cobj_temp1->load_balancer_algo = cobj_temp->load_balancer_algo;
    // strncpy((char *)cobj_temp1->collector_id, (char *)cobj_temp->collector_id, strlen((char *)cobj_temp->collector_id));
    strncpy((char *)cobj_temp1->collector_id, (char *)cobj_temp->collector_id, MAX_ID_LEN);
    cobj_temp = cobj_temp->next;
    if(cobj_temp != NULL)
    {
      SECMON_DEBUG("there are more than one tool\n");
      cobj_temp1->next = (struct Collector_object *)malloc(sizeof(struct Collector_object));
      cobj_temp1 = cobj_temp1->next;
    }
  }
  cobj_temp1->next = NULL;

}




/** selects the collector which has minimum number of sessions
 *  @param
 *  cobj - Collector_object list 
 *  @returns 
 *  collector which has less sessions
 */
struct Collector_details *get_collector_by_sessions(struct Collector_object *cobj)
{
  /* select tool based on the number of sessions */
  struct Collector_details *temp = cobj->collector_details;
  struct Collector_details *collector = temp;
  int sessions = temp->sessions;
  while(temp != NULL)
  {
    SECMON_DEBUG("current session = %d, current min = %d\n",temp->sessions,sessions);
    if(temp->sessions < sessions)
    {
      sessions = temp->sessions;
      collector = temp;
    }
    temp = temp->next;        
  }
  return collector; 
}

/** selects the collector based on the round robin method
 *  @param
 *  cobj - Collector_object list 
 *  @returns 
 *  collector based on the round robin
 */
struct Collector_details *get_collector_by_round_robin(struct Collector_object *cobj)
{
  /* select tool based on the number of sessions */
  struct Collector_details *temp = cobj->collector_details;
  struct Collector_details *collector = temp;
  int count = cobj->collector_count;
  int col_turn = (cobj->collector_turn) % (count);
  SECMON_DEBUG("col_turn = %d\n", col_turn);
  while(col_turn > 0)
  {
    temp = temp->next;
    col_turn--;
    collector = temp;
  }
  cobj->collector_turn++;
  if(cobj->collector_turn == cobj->collector_count)
    cobj->collector_turn = 0;
  return collector;
}

/** selects the collector based on the weighted round robin method
 *  @param
 *  cobj - Collector_object list 
 *  @returns 
 *  collector based on the weighted round robin
 */
struct Collector_details *get_collector_by_weighted_round_robin(struct Collector_object *cobj)
{
  /* select tool based on the number of sessions */
  struct Collector_details *temp = cobj->collector_details;
  struct Collector_details *col_details = temp;

  unsigned int highest_weight;
  unsigned int weight;
  unsigned int sessions;
  weight = col_details->weight;
  sessions = col_details->sessions;

  weight <<= 8;
  highest_weight = weight/(sessions+1);
  SECMON_DEBUG("weight of first collector = %u\n", highest_weight); 
  SECMON_DEBUG("sessions of first collector = %u\n", sessions); 

  while(temp->next != NULL)
  {
    unsigned int next_collec_sessions = temp->next->sessions;
    unsigned int next_collec_weight = temp->next->weight;
    next_collec_weight <<= 8;
    unsigned int calc_weight = (next_collec_weight)/(next_collec_sessions + 1);

    if(calc_weight > highest_weight)
    {
      col_details = temp->next;
    }
    temp = temp->next;
  }

  return col_details;
}

/** Decrement the session count of collector in global list
 *  and delete collector object that passed
 *  @param collec_obj
 *      collector object to delete
 *  @returns void
 */
void decrement_session(struct Collector_object *collec_obj)
{
  /* To remove multiple collector corresponding to single rule */
  SECMON_DEBUG("decrementing sessions\n");
  struct Collector_details *collector;

  while (collec_obj != NULL) 
  {
    struct Collector_object *backup_collc_obj = collec_obj->next;

    collector = find_collector_set_by_id(collector_obj_head, (char *)collec_obj->collector_id);

    if (collector && collector->sessions > 0)
    {
      collector->sessions--;
    }

    free(collec_obj);
    collec_obj = backup_collc_obj;

  }

}
