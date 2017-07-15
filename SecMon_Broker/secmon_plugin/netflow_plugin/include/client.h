/*
#    Copyright (c) 2016 Intel Corporation.
#    All Rights Reserved.
#
#    Licensed under the Apache License ,  Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing ,  software
#    distributed under the License is distributed on an "AS IS" BASIS ,  WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND ,  either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
 */

#ifndef CLIENT_API
#define CLIENT_API

/** @file
 * header for client
 *
 */

#include <json/json.h>
#include "utils.h"
#include <arpa/inet.h>
#include "common.h"

#define PLUGINNAME          NETFLOW
#define PLUGINKEY           "plugin_name"
#define PLUGINASSOCIATION   "netflowassociation"
#define ENABLED             "enable"
#define DISABLED            "disable"
#define NETFLOW             "netflow"
#define IPV6                "ipv6_address"
#define ENCAP_PROTO         "encapsulation_protocol"
#define SECMONDETAILS       "secmondetails"
#define NOSCOPE			    "noscope"
#define NOADDRESS		    "no address"

#define SDESTINATION        "destination"
#define SCOLLECTOR          "collector"
#define ASSOCIATION         "association"
#define SCONFIG             "config-params"
#define SMONITOR            "monitor"
#define SHOW                "show"
#define CLASSIFICATIONID    "classificationobject_id"
#define MATCH_FIELD         "match_fields"
#define COLLECT_FIELD       "collect_fields"
#define ACTIVE_TIMEOUT      "active_timeout"
#define INACTIVE_TIMEOUT    "inactive_timeout"
#define REFRESH_RATE        "refresh_rate"
#define TIMEOUT_RATE        "timeout_rate"
#define MAXFLOWS            "maxflows"
#define NOCOLLECTORID       "no collector id"

#define COLLECTOR           "collector"
#define SCOPE               "scope"
#define COLLECTORSET        "collectorset"
#define POLICY              "policy"
#define CLASSIFICATION      "classificationobject"
#define RULE                "ruleobject"
#define APPEND              "append"
#define ADDASSOCIATION      "add association"
#define STORE		        "store"
#define UPDATE		        "update"
#define ADD 		        "add"

#define CNAME               "collector_name"
#define NAME                "name"
#define UUID                "id"
#define POLICYID            "policy_id"
#define COLLECTORID         "collector_id"
#define COLLECTORSETID      "collector_set_id"
#define DIRECTION           "direction"
#define SCOPEID             "scope_id"
#define SCOPENAME           "scope_name"
#define MAC                 "mac_address"
#define UDP                 "UDP"
#define UDPPORT             "udp_port"
#define PORT                "port"
#define IP                  "ip_address"
#define SRCIP               "src_ip" 
#define DESTIP              "dst_ip" 
#define PROTOCOL            "protocol"
#define SRCSUBIP            "src_ip_subnet"
#define DESTSUBIP           "dst_ip_subnet"
#define MINSRCPORT          "minimum_src_port"
#define MAXSRCPORT          "maximum_src_port"
#define MINDESTPORT         "minimum_dst_port"
#define MAXDESTPORT         "maximum_dst_port"
#define RULEID              "rule_id"
#define RULEIDS             "ruleobject_id"
#define COLLECTORIDS        "collector_ids"
#define LOAD_BALANCER_ALGO  "lb_algo" 
#define COLLECTOR_SET_ARRAY "collector_set_array"
#define PRIORITY            "priority"
#define STATUS              "netflowstatus"
#define SRCMAC              "src_mac"
#define DESTMAC             "dst_mac"
#define ACTION              "action"
#define TRUNC               "truncate_to_size"   
#define WEIGHT              "weight"
#define NETFLOWCONFIG       "netflowconfig"
#define NETFLOWMONITOR      "netflowmonitor"

#define NUMMATCHFILEDS      15
#define NUMCOLLECTFIELDS    15
#define FIELD_VALUE_SIZE    30
#define VLANNAME            "VLAN"
#define MACADDRESS          "MAC-ADDRESS"
#define ININTERFACE         "INPUT-INTERFACE"
#define DESTPORT            "DESTINATION-PORT"
#define SRCPORT             "SOURCE-PORT"
#define DSTADDRESS          "DESTINATION-ADDRESS"
#define SRCADDRESS          "SOURCE-ADDRESS"
#define MATCHPROTOCOL       "PROTOCOL"
#define TOS                 "TOS"

#define FLOWACESSTIME       "FLOW ACCESS TIMESTAMP"
#define COLLECTCOUNTER      "COLLECT COUNTER" 
#define COLLECNEXTHOPADD    "COLLECT NEXT-HOP-ADDRESS" 
#define COLLECTIPV4TTL      "COLLECT IPV4 TTL" 
#define COLLECTIPV4LEN      "COLLECT IPV4 TOTAL-LENGTH" 
#define COLLECTINTERFACE    "COLLECT INTERFACE" 
#define COLLECTFLOWDIR      "COLLECT FLOW DIRECTION" 
#define COLLEC_VLAN         "COLLECT VLAN" 
#define COLLEC_MAC          "COLLECT MAC"

enum
{
    COL=0,
    COLSET=1,
};

enum
{
    NEWASS=1,
    OLDASS=0,
};

struct Plugin
{
    uint8_t status[IP_SIZE];
    uint8_t root_url[URL_SIZE];
    uint8_t url[URL_SIZE];
    struct Scope *scope;
    struct Collector *collector;
    struct Policy *policy;
    struct Association *association;
    struct Collector_set *collector_set;
    struct Rules *ruleobj;
    struct Collector_object *Collec_rule;
    struct Netflow_Config *netconfig;
    struct Netflow_Monitor *netmonitor;
};

void get_json_value(json_object *,char*,char* );
void json_parse_array( json_object *, char *,char*,char*);
void json_parse_object(json_object *  , char*);
void parse_json_response(char*  , char*);

char* update_value(char *,char *,char []);

void store_policy(char*  , char* );
void store_rule_ids(char*  , char *);
void store_collector(char*  , char* ,bool);
void store_collector_set(char*  , char* );
void store_rule(char*  , char* );
void store_scope(char*  , char* );
void store_association(char*  , char* );
void store_collector_obj(struct Collector *);
void store_collector_set_obj(struct Collector *, bool is_first_collector);
void fetch_startup_configurations(char *,char *);
void fetch_scope_id(char *,char *);
void fetch_associations(char *  , char *);
void fetch_association_by_id(char*  , char*  , char *);
struct Collector *fetch_collector_by_id(char*  , char* ,bool );
void fetch_policy_by_id(char*  , char* );
void fetch_rule_obj_by_id(struct Policy *,char*  , char* );
void fetch_rule_by_id(struct Rules *,char*  , char *);
void fetch_all_configurations(char *,char *);
void fetch_all_policy_rules(struct Policy *,char *);
struct Collector_set *fetch_collector_set_by_id(char*  , char* );

struct Association* association_node_of_id(struct Association *,char* );
struct Collector* collector_node_of_id(struct Collector *,char* );
struct Policy* policy_node_of_id(struct Policy *,char* );
struct Classification_object* rule_node_of_id(struct Classification_object *,char* );
struct Rules* rule_id_node_of_id(struct Rules *,char* );
struct Collector_object* find_collector_by_rules(char *);
struct Collector_set* collector_set_node_of_id(struct Collector_set *,char* );
struct Collector_set* find_last_collector_set(struct Collector_set *);

void update_scope();

void add_association(char*  , char* );

struct Collector* find_last_collector(struct Collector *);
struct Association* find_last_association(struct Association *);
struct Classification_object* find_last_rule(struct Classification_object *);
struct Policy* find_last_policy(struct Policy *);
struct Collector_object* find_last_collector_obj(struct Collector_object *);
inline struct Collector_details* find_last_collector_details_obj(struct Collector_details *col_details);

struct Rules* find_last_rule_id(struct Rules *);
void find_collector_by_policy(char *,char *);
struct Collector_object* find_collector_obj_by_collector_id(char *);

void fetch_update_association(char* );
void fetch_update_collector(char *);
void fetch_update_collectorset(char* );
void fetch_update_policy(char* );
void fetch_update_rule(char * );
void fetch_update_rule_ids(char * );
void fetch_add_association(char* );
void store_by_id(char *,char *);
void store_collector_by_id(char *, char *);
void sort_acc_priority(struct Collector_object *,struct Classification_object *, char *);

void delete_association(char *);
void delete_collector(char *);
void delete_collector_obj(char *);
void delete_collector_set(char *);
void delete_policy(char *);
void delete_rule(char *);
void delete_rule_ids(char *);
void delete_all_configurations();

#ifdef SECMON_DEBUG_LOG
void print_configurations();
#endif

void upload_secmon_details(char *,char *,char *);
void free_configurations();

void netflow_api();
void store_netflow_config(char *,char *);
void store_netflow_monitor(char *,char *);
void fetch_netflow_config(char *);
void fetch_netflow_monitor(char *);

int generate_collect_field(char *values);
int generate_match_field(char *values);

void flush_netflow_hash_table();
void update_netflow_status(bool );

void delete_netflow_config();
void delete_netflow_monitor();
void update_netflow_config();
void update_netflow_monitor();
int add_netflow_destination(char *, uint32_t );
void delete_netflow_destination(char *ip ,  uint32_t port);

int add_netflow_monitor_params(int  ,  int );
int netflow_config(int  ,  int  ,  unsigned int  ,  unsigned int  ,  unsigned int );

extern struct Plugin plugin;
extern int col_set;
extern int new_association;

#endif
