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


#ifndef _PACKET_PARSER_H
#define _PACKET_PARSER_H

/** @file
 * header containing structures & function to parse packet
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "constants.h"

#define MAC_HDR_LEN 14
#define IPV4_HDR_LEN 20
#define IPV6_HDR_LEN 40
#define IPV4_L4_HDR_OFFSET MAC_HDR_LEN + IPV4_HDR_LEN
#define IPV6_L4_HDR_OFFSET MAC_HDR_LEN + IPV6_HDR_LEN
#define DEFAULT_PORT    1

enum
{
    PACKET_PARSE,
    PACKET_DROP,
};
/**
     * A structure that stores the mac address.
     */
struct hw_addr
{
    uint8_t addr[ETHER_ADDR_LEN];
} __attribute__((__packed__));

/**
     * A structure that stores Ethernet header information.
     */
struct ether_header
{
    struct hw_addr dst_mac;
    struct hw_addr src_mac;
    uint16_t ether_type;
} __attribute__((__packed__));

/**
     * A structure that stores IPv4 header information.
     */
struct ipv4_header
{
    uint8_t  version_ihl;       /**< version and header length */
    uint8_t  type_of_service;   /**< type of service */
    uint16_t total_length;      /**< length of packet */
    uint16_t packet_id;     /**< packet ID */
    uint16_t fragment_offset;   /**< fragmentation offset */
    uint8_t  time_to_live;      /**< time to live */
    uint8_t  next_proto_id;     /**< protocol ID */
    uint16_t hdr_checksum;      /**< header checksum */
    uint32_t src_addr;      /**< source address */
    uint32_t dst_addr;      /**< destination address */
} __attribute__((__packed__));

/**
     * A structure that stores IPv6 header information.
     */
struct ipv6_header
{
    uint32_t vtc_flow;
    uint16_t payload_len;
    uint8_t proto;
    uint8_t hop_limits;
    uint8_t src_addr[IPV6_ADDR_LEN];
    uint8_t dst_addr[IPV6_ADDR_LEN];
}__attribute__((__packed__));

struct tcp_header
{
    uint16_t src_port;  /**< TCP source port. */
    uint16_t dst_port;  /**< TCP destination port. */
    uint32_t sent_seq;  /**< TX data sequence number. */
    uint32_t recv_ack;  /**< RX data acknowledgment sequence number. */
    uint8_t  data_off;  /**< Data offset. */
    uint8_t  tcp_flags; /**< TCP flags */
    uint16_t rx_win;    /**< RX flow control window. */
    uint16_t cksum;     /**< TCP checksum. */
    uint16_t tcp_urp;   /**< TCP urgent pointer ,  if any. */
} __attribute__((__packed__));

struct icmp_header
{
    uint8_t  icmp_type;   /**< ICMP packet type. */
    uint8_t  icmp_code;   /**< ICMP packet code. */
    uint16_t icmp_cksum;  /**< ICMP packet checksum. */
    uint16_t icmp_ident;  /**< ICMP packet identifier. */
    uint16_t icmp_seq_nb; /**< ICMP packet sequence number. */
} __attribute__((__packed__));

struct udp_header {
    uint16_t src_port;    /**< UDP source port. */
    uint16_t dst_port;    /**< UDP destination port. */
    uint16_t dgram_len;   /**< UDP datagram length */
    uint16_t dgram_cksum; /**< UDP datagram checksum */
} __attribute__((__packed__));
/**
     * A structure that stores IP source and destination addresses.
     */
struct ipv4_addresses
{
    uint32_t src_addr;    /**< Source IP Address*/
    uint32_t dst_addr;    /**< Destination IP Address*/
} __attribute__((__packed__));

/**
     * A structure that stores IP source and destination addresses.
     */
struct ipv6_addresses
{
    struct in6_addr src_addr;   /**< Source IP Address*/
    struct in6_addr dst_addr;   /**< Destination IP Address*/
} __attribute__((__packed__));

/**
     * A structure that stores the fields values to be compared to identify the monitored packet.
     */
struct Tuple
{
    struct hw_addr src_mac;
    struct hw_addr dst_mac;
    union ip_family
    {
        struct ipv4_addresses ipv4;
        //struct ipv6_addresses ipv6;       /*for future ipv6 support*/
    }ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((__packed__));

/**
     * A structure that stores information about the tuple, collectors, action to be taken,
	 * size of packet and when was similar packet last seen.
     */
struct rule_hash
{
    struct Tuple *tuple;
    struct Collector_object *collectors;
    uint8_t encap_protocol;
    uint32_t truncate_to_size;
    struct rule_hash *next;
    unsigned long last_seen;
    bool action;
};

inline uint32_t find_hash(struct Tuple *tuple);
inline uint32_t __find_hash(const struct Tuple *tuple);
inline uint32_t murmur3(const void *key ,  const uint32_t len ,  const uint32_t seed);

#endif

