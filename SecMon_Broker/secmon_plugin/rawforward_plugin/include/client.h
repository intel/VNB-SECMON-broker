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



#ifndef CLIENT_API
#define CLIENT_API

/** @file
 *  client header file
 */
#include <json/json.h>
#include "utils.h"
#include <arpa/inet.h>
#include "common.h"

#define PLUGINKEY           "plugin_name"               /**< Plugin key */
#define PLUGINNAME          RAWFORWARD                  /**< Plugin name */
#define PLUGINASSOCIATION   "rawforwardassociation"     /**< Plugin association name */
#define ENABLED             "enable"                    /**< Enable string */
#define DISABLED            "disable"                   /**< Disable string */
#define RAWFORWARD          "rawforward"                /**< Rawforward */
#define IPV6                "ipv6_address"              /**< For ipv6 comparison */
#define ENCAP_PROTO         "encapsulation_protocol"    /**< For encapsulation protocol comparison */
#define SECMONDETAILS       "secmondetails"             /**< SecMon Details */
#define NOSCOPE			    "noscope"                   /**< No Scope */  
#define NOADDRESS           "noaddress"                 /**< No Address */

#define SDESTINATION        "destination"               /**< Destination */
#define SCOLLECTOR          "collector"                 /**< Collector */
#define ASSOCIATION         "association"               /**< Association */
#define SCONFIG             "config-params"             /**< CONFIG */
#define SHOW                "show"                      /**< SHOW */
#define CLASSIFICATIONID    "classificationobject_id"   /**< Classification Object Id */
#define NOCOLLECTORID       "no collector id"           /**< No Collector Id */

#define COLLECTOR           "collector"                 /**< Collector */
#define SCOPE               "scope"                     /**< Scope */
#define COLLECTORSET        "collectorset"              /**< Collector Set */
#define POLICY              "policy"                    /**< Policy */
#define CLASSIFICATION      "classificationobject"      /**< Classification Object */
#define RULE                "ruleobject"                /**< Rule Object */
#define APPEND              "append"                    /**< Append */
#define ADDASSOCIATION      "add association"           /**< Add Association */
#define STORE		        "store"                     /**< Store */
#define UPDATE		        "update"                    /**< Update */
#define ADD 		        "add"                       /**< Add */

#define CNAME               "collector_name"            /**< Collector Name */
#define NAME                "name"                      /**< Name */
#define UUID                "id"                        /**< Id */
#define POLICYID            "policy_id"                 /**< Policy Id */
#define COLLECTORID         "collector_id"              /**< Collector Id */
#define COLLECTORSETID      "collector_set_id"          /**< Destination */
#define DIRECTION           "direction"                 /**< Direction */
#define SCOPEID             "scope_id"                  /**< Scope Id */
#define SCOPENAME           "scope_name"                /**< Scope Name */
#define MAC                 "mac_address"               /**< Mac Address */
#define UDP                 "UDP"                       /**< UDP */
#define UDPPORT             "udp_port"                  /**< UDP Port */
#define PORT                "port"                      /**< Port */
#define IP                  "ip_address"                /**< IP Address */
#define SRCIP               "src_ip"                    /**< Source IP */
#define DESTIP              "dst_ip"                    /**< Destination IP */
#define PROTOCOL            "protocol"                  /**< Protocol */
#define SRCSUBIP            "src_ip_subnet"             /**< Source IP Subnet */
#define DESTSUBIP           "dst_ip_subnet"             /**< Destination IP Subnet */
#define MINSRCPORT          "minimum_src_port"          /**< Minimum Source Port */
#define MAXSRCPORT          "maximum_src_port"          /**< Maximum Source Port */
#define MINDESTPORT         "minimum_dst_port"          /**< Minimum Destination Port */
#define MAXDESTPORT         "maximum_dst_port"          /**< Maximum Destination Port */
#define RULEID              "rule_id"                   /**< Rule ID */
#define RULEIDS             "ruleobject_id"             /**< Rule ID */
#define COLLECTORIDS        "collector_ids"             /**< Collector ID */
#define LOAD_BALANCER_ALGO  "lb_algo"                   /**< Load Balancing Algo */
#define COLLECTOR_SET_ARRAY "collector_set_array"       /**< Collector Set Array */
#define PRIORITY            "priority"                  /**< Priority */
#define STATUS              "rawforwardstatus"          /**< Status */
#define SRCMAC              "src_mac"                   /**< Source MAC */
#define DESTMAC             "dst_mac"                   /**< Destination MAC */
#define ACTION              "action"                    /**< Action */
#define TRUNC               "truncate_to_size"          /**< Truncate to size */
#define WEIGHT              "weight"                    /**< Weight */

/**
 *  Collector and Collector Set flags
 */
enum
{
    COL=0,
    COLSET=1,
};

/**
 *  New Association and Old Association flags
 */
enum
{
    NEWASS=1,
    OLDASS=0,
};

/**
 *  UDP Protocol and SFLOW Protocol flags
 */
enum
{
    UDP_PROC=0,
    SFLOW_PROC=1,
};

/**
 *  Struct containing Plugin information 
 */
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

void rawforward_api();

void print_configurations(void);

void upload_secmon_details(char *,char *,char *);
void free_configurations();
void update_scope();
void flush_hash_table();
void update_status(bool status);

extern struct Plugin plugin;
extern int col_set;             /**< Flag for checking collector set or not */
extern int new_association;     /**< New Association */

#endif


