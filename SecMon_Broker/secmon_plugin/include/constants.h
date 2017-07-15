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

#ifndef _CONSTANTS_H
#define _CONSTANTS_H

/** @file
 * contains constants
 *
 */

#define SLEEP_TIME              10
#define HASH_EXPIRY_TIME		1000*60   //in milliseconds

#define ETHER_ADDR_LEN          6
#define IPV6_ADDR_LEN           80
#define IPV4_ADDR_LEN           16
#define MAX_ID_LEN              80
#define MAX_IP_LEN              80
#define VLAN_HDR_EN             4
#define MAX_NAME_LEN            80

#define PORT_VALID_LOWER_VAL    0
#define PORT_VALID_UPPER_VAL    65535
#define DEFAULT_PROTOCOL_TYPE   0
#define IPV4_PACKET             0x0800
#define VLAN                    0x8100
#define IPV6_PACKET             0x86DD
#define ARP_PACKET              0x0806

#define PKT_BURST               32
#define PKT_PRINT_DEBUG         1000
#define SLEEP_TIMER             10           //10 seconds

#define TOTAL_TUPLE_FIELDS      7
#define MAX_PACKET_SIZE         2000

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define SUCCESS 0
#define FAILURE -1

#define HASH_SEED 0
#define HASH_TABLE_SIZE 65536


#endif
