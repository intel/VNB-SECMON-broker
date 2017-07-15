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

#ifndef STORAGE
#define STORAGE

/** @file
 *  contains struct for configurations
 *
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdbool.h>
#include "constants.h"

/** enum for packet processing.
	DROP 	- For dropping packets
	FORWARD - For forwarding packets	
 */
enum
{
    DROP = 0 , 
    FORWARD = 1 , 
};

/** enum for Load Balancing Algorithm.
	SESSION_BASED			- Session based load balancing
	ROUND_ROBIN   			- Round robin based load balancing
	WEIGHTED_ROUND_ROBIN	- Weighted round robin based load balancing, every collector 
							  have some weightage & load will be balanced accr to weight. 
 */
enum LOAD_BALANCING_ALGORITHMS
{
    SESSION_BASED=0,
    ROUND_ROBIN=1,
    WEIGHTED_ROUND_ROBIN=2,
    NONE=3,
};

/** Scope identifiers.
    id   - Scope internal ID
	name - Name of scope
 */
struct Scope
{
    uint8_t id[MAX_ID_LEN];
    char name[MAX_NAME_LEN];
};

/** Classification object details.
    name			- Name of scope
	rule_id			- Rule ID
	src_mac			- Source MAC Address
	dst_mac			- Destination MAC Address
	src_ip			- Source IP Address
	dst_ip			- Destination IP Address
	min_src_port	- Minimum source port
	max_src_port	- Maximum source port
	min_dst_port	- Minimum destination port
	max_dst_port	- Maximum destination port
	src_ip_subnet	- Source IP subnet
	dst_ip_subnet	- Destination IP subnet
	action			- Action
	priority		- Priority of rule
	protocol		- Protocol for which classification object is created (ICMP|UDP|TCP|SCTP)
	truncate_to_size- Packets will be truncated to this size
 */
struct Classification_object
{
    uint8_t name[MAX_NAME_LEN];
    uint8_t rule_id[MAX_ID_LEN];
    uint8_t src_mac[ETHER_ADDR_LEN];
    uint8_t dst_mac[ETHER_ADDR_LEN];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t min_src_port;
    uint16_t max_src_port;
    uint16_t min_dst_port;
    uint16_t max_dst_port;
    uint8_t src_ip_subnet;
    uint8_t dst_ip_subnet;
    uint16_t action;
    uint32_t priority;
    uint16_t protocol;
    uint32_t truncate_to_size;
    struct Classification_object *next;
};

/** Rules object details.
	rule_id				- Rule Internal ID
	name				- Rule name
	Classification_id	- Associated classification object ID
	action				- Action
	priority			- Priority of rule
	truncate_to_size	- Packets will be truncated to this size 
 */
struct Rules
{
    uint8_t rule_id[MAX_ID_LEN];
    uint8_t name[MAX_ID_LEN];
    uint8_t Classification_id[MAX_ID_LEN]; 
    uint32_t action;
    uint32_t priority;
    uint32_t truncate_to_size;
    struct Rules *next;
};

/** Policy details.
	id		- Policy ID
	name	- Policy name
	rule_ids- Associated rule Ids
 */
struct Policy
{
    uint8_t id[MAX_ID_LEN];
    uint8_t name[MAX_NAME_LEN];
    struct Rules *rule_ids;
    struct Policy *next;
};
/** Association details.
	id 					- Association internal Id
	policy_id			- Policies Id used in association
	collector_id		- Collector Id used in association
	direction			- Direction of packets which will be processed
	collector_set_id	- Collector Set used in association
	scope
 */
struct Association
{
    uint8_t id[MAX_ID_LEN];
    uint8_t policy_id[MAX_ID_LEN];
    uint8_t collector_id[MAX_ID_LEN];
    uint8_t direction[MAX_NAME_LEN];
    uint8_t collector_set_id[MAX_ID_LEN];
    uint32_t scope;
    struct Association *next;
};

/** Collector information.
	name	- Name of collector
	id		- ID of collector
	port	- Port of collector
	weight	- Weight assigned to collector in case of collector set and algo as weighted round robin.
	encap_protocol - Encapsulation protocol, in case of raw forwarding packets can be encapsulated in either UDP or SFlow
	dst_addr	   - IP of Collector in case of IPv4
	dst6_addr	   - IP of Collector in case of IPv6
 */
struct Collector
{
    uint8_t name[MAX_ID_LEN];
    uint8_t id[MAX_ID_LEN];
    uint32_t port;
    uint32_t weight;
    union
    {
        uint8_t dst_addr[IPV4_ADDR_LEN];
        uint8_t dst6_addr[IPV6_ADDR_LEN];
    }ip;
    uint8_t encap_protocol;
    struct Collector *next;
};

/** Collector details.
	id				- ID of collector
	server_address	- IP of Collector
	socket			- Port of collector
	encap_protocol	- Encapsulation protocol, in case of raw forwarding packets can be encapsulated in either UDP or SFlow
	weight			- Weight assigned to collector in case of collector set and algo as weighted round robin		
 */
struct Collector_details
{
    uint8_t id[MAX_ID_LEN];
    struct sockaddr_in server_address;
    int server_length;
    int socket;
    unsigned int sessions;
    uint8_t encap_protocol;
    unsigned int weight; 
    // removed weighted_sessions because we are using only sessions for 
    // indicating active sessions
    // unsigned int weighted_sessions; 
    struct Collector_details *next;
};

/** Collector Set details.
	collector		- Collector
	socket			- Port of collector
	server_address	- IP of Collector
	server_length	- Server Length
	encap_protocol	- Encapsulation protocol, in case of raw forwarding packets can be encapsulated in either UDP or SFlow
	collector_details		- Individual Collector details
	classification_object	- Classification Object
	collector_set			- Collector Set enabled or disabled
	load_balancer_algo		- Load Balancer Algo
	collector_count			- Number of used collectors
	collector_turn			- Collector turn
	collector_id			- Collector internal ID	
	collector_set_id		- ID of collector set	
 */
struct Collector_object
{
    struct Collector *collector;
    int socket;
    struct sockaddr_in server_address;
    int server_length;
    uint8_t encap_protocol;
    struct Collector_details *collector_details;   
    struct Classification_object *classification_object;
    bool collector_set;
    uint8_t load_balancer_algo;
    uint32_t collector_count;
    uint32_t collector_turn;
    char collector_id[MAX_ID_LEN];
    char collector_set_id[MAX_ID_LEN];
    struct Collector_object *next;
};

/** Collector Set details.
	id 			- ID of collector set 
	name		- Name of collector set 
	load_balancer_algo - Load Balancing Algo Round Robin | Session Based | Weighted Round Robin
	collectors	- Collectors in collector set
 */
 
struct Collector_set
{
    uint8_t id[MAX_ID_LEN];
    uint8_t name[MAX_ID_LEN];
    uint8_t load_balancer_algo;
    struct Collector *collectors;   
    struct Collector_set *next;
};

/** sFlow details
	id			- sFlow Internal ID
	agent_ip	- sFlow Agent IP
	agent_sub_id- sFlow Agent Sub ID
	truncate_to_size - Packet truncation for sFlow
	samplingrate- Sampling rate for sflow
 */
struct Sflow_Config
{
    uint8_t id[MAX_ID_LEN];
    uint8_t agent_ip[MAX_IP_LEN];
    uint32_t agent_sub_id;
    uint32_t truncate_to_size;
    uint32_t samplingrate;
};

/** NetFlow Config details
	id				- NetFlow Internal ID
	active_tmout	- Active timeout for NetFlow
	inactive_tmout	- Inactive timeout for NetFlow
	refresh_rate 	- Refresh Rate for NetFlow
	tm_rate			- Timeout for NetFlow
	maxflows		- MaxFlows for NetFlow
 */
struct Netflow_Config
{
    uint8_t id[MAX_ID_LEN];
    uint8_t active_tmout;
    uint8_t inactive_tmout;
    uint8_t refresh_rate;
    uint8_t tm_rate;
    uint8_t maxflows;
};

/** NetFlow Monitor details
	id				- NetFlow Monitor Internal ID
	match_field		- Fields need to be matched
	collect_field	- Fields need to be collected in case of match
 */
struct Netflow_Monitor
{
    uint8_t id[MAX_ID_LEN];
    uint32_t match_field;
    uint32_t collect_field;
};

typedef struct Collector_object tool;
void add_tools(uint32_t hash_code , struct Collector_object *collector_obj);

#endif
