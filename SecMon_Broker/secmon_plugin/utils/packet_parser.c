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
 * 	contains functions to parse the packet ,  utility functions related to hash table ,
 * 	function to strip gtp header.
 */
#include <arpa/inet.h>
#include <rte_mbuf.h>

#include "common.h"

/** prints the packet in hex format
 * @param pkt
 *	pointer to the data packet
 * @param len
 * 	length of the packet
 * @returns void
 *
 */
void print_packet(char *pkt ,  int len)
{
  int i;

  for(i = 0;i<len;i++)
  {
    SECMON_DEBUG("%02x ",(unsigned char)pkt[i]);
    if(((i+1)%16)==0)
    {
      SECMON_DEBUG("\n");
    }
  }
}

/** parses the data packet to extract 7 tuple.
 * @param pkt
 * 	pointer to the packet
 * @param len
 *	length of the packet
 * @param tuple
 * 	tuple to be created out of the pkt
 * @return
 * 	0 - in case of ARP and non IP packet
 * 	1 - in case of IPV4 or IPV6
 */
int parse_packet(char **secmon_pkt ,  int len , struct Tuple *tuple)
{
  char *pkt;
  pkt=*secmon_pkt;
  int ret;
  struct ether_header *eth_hdr;
  struct ipv4_header *ipv4_hdr;
//  struct ipv6_header *ipv6_hdr;
  uint16_t etherType;
  eth_hdr  =  (struct ether_header *) pkt;

  /* temp variables to store tuple information, so that it can be easy to swap
     things around according to the src_addr greater or smaller than dst_addr
  */
  struct ipv4_addresses temp_ipv4;
  uint16_t temp_src_port;
  uint16_t temp_dst_port;

  etherType  =  htons(eth_hdr->ether_type);

  if(likely(etherType == VLAN))
  {
    /* VLAN Segment size in ethernet header is 4 bytes.*/
    pkt += VLAN_HDR_EN;

    /* recast eth_hdr to find the actual etherType */
    eth_hdr  =  (struct ether_header *) pkt;
    etherType  =  htons(eth_hdr->ether_type);

    if(etherType == IPV4_PACKET)
    {
      ipv4_hdr  =  (struct ipv4_header *) (pkt + MAC_HDR_LEN);

      temp_ipv4.src_addr  =  ipv4_hdr->src_addr;
      temp_ipv4.dst_addr  =  ipv4_hdr->dst_addr;
      tuple->protocol =  ipv4_hdr->next_proto_id;

      switch (tuple->protocol)
      {
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
        case IPPROTO_SCTP:
          {
            struct udp_header *udphdr;
            udphdr  =  (struct udp_header *)(pkt + IPV4_L4_HDR_OFFSET);
            temp_src_port  =  ntohs(udphdr->src_port);
            temp_dst_port  =  ntohs(udphdr->dst_port);
            ret = PACKET_PARSE;
          }
          break;
        case IPPROTO_TCP:
          {
            struct tcp_header *tcphdr;
            tcphdr  =  (struct tcp_header *)(pkt + IPV4_L4_HDR_OFFSET);
            temp_src_port  =  ntohs(tcphdr->src_port);
            temp_dst_port  =  ntohs(tcphdr->dst_port);
            ret = PACKET_PARSE;
          }
          break;
        case IPPROTO_ICMP:
          {
            temp_src_port  =  DEFAULT_PORT;
            temp_dst_port  =  DEFAULT_PORT;
            ret = PACKET_PARSE;
          }
          break;
      }

      // if source address is larger than dst address than store store reverse
      // entries otherwise store as it is
      pkt = *secmon_pkt;
      eth_hdr  =  (struct ether_header *) pkt;

      if (temp_ipv4.src_addr < temp_ipv4.dst_addr)
      {
        tuple->ip.ipv4.src_addr = temp_ipv4.src_addr;
        tuple->ip.ipv4.dst_addr = temp_ipv4.dst_addr;
        tuple->src_port = temp_src_port;
        tuple->dst_port = temp_dst_port;

        // now for mac addr calculation we have to recast pkt to ether_header
         memcpy(tuple->src_mac.addr , eth_hdr->src_mac.addr , ETHER_ADDR_LEN);
         memcpy(tuple->dst_mac.addr , eth_hdr->dst_mac.addr , ETHER_ADDR_LEN);
      }
      else
      {
        tuple->ip.ipv4.src_addr = temp_ipv4.dst_addr;
        tuple->ip.ipv4.dst_addr = temp_ipv4.src_addr;
        tuple->src_port = temp_dst_port;
        tuple->dst_port = temp_src_port;

        // now for mac addr calculation we have to recast pkt to ether_header
         memcpy(tuple->src_mac.addr , eth_hdr->dst_mac.addr , ETHER_ADDR_LEN);
         memcpy(tuple->dst_mac.addr , eth_hdr->src_mac.addr , ETHER_ADDR_LEN);
      }

    }
//  else if(etherType == IPV6_PACKET)
//    {
//      ipv6_hdr  =  (struct ipv6_header *) (pkt + MAC_HDR_LEN);
//
//      // NOTE: ipv6 information is not obtained here
//
//      tuple->protocol  =  ipv6_hdr->proto;
//
//      switch (tuple->protocol)
//      {
//        case IPPROTO_UDP:
//        case IPPROTO_UDPLITE:
//        case IPPROTO_SCTP:
//          {
//            struct udp_header *udphdr;
//            udphdr  =  (struct udp_header *)(pkt + IPV6_L4_HDR_OFFSET);
//            tuple->src_port  =  ntohs(udphdr->src_port);
//            tuple->dst_port  =  ntohs(udphdr->dst_port);
//            ret = PACKET_PARSE;
//          }
//          break;
//        case IPPROTO_TCP:
//          {
//            struct tcp_header *tcphdr;
//            tcphdr  =  (struct tcp_header *)(pkt + IPV6_L4_HDR_OFFSET);
//            tuple->src_port  =  ntohs(tcphdr->src_port);
//            tuple->dst_port  =  ntohs(tcphdr->dst_port);
//            ret = PACKET_PARSE;
//          }
//          break;
//        case IPPROTO_ICMP:
//          {
//
//            tuple->src_port  =  DEFAULT_PORT;
//            tuple->dst_port  =  DEFAULT_PORT;
//            ret = PACKET_PARSE;
//          }
//          break;
//      }
//
//      // store mac address in the tuple
//      pkt = *secmon_pkt;
//      eth_hdr  =  (struct ether_header *) pkt;
//
//       memcpy(tuple->src_mac.addr , eth_hdr->src_mac.addr , ETHER_ADDR_LEN);
//       memcpy(tuple->dst_mac.addr , eth_hdr->dst_mac.addr , ETHER_ADDR_LEN);
//    }
  }
  else if(etherType == IPV4_PACKET)
  {
    /* non vlan tagged ipv4_packet packet handling.
     * in case of taas ,  this case is most unlikely
     */
    ipv4_hdr  =  (struct ipv4_header*)(pkt + MAC_HDR_LEN);

    temp_ipv4.src_addr  =  ipv4_hdr->src_addr;
    temp_ipv4.dst_addr  =  ipv4_hdr->dst_addr;
    tuple->protocol  =  ipv4_hdr->next_proto_id;

    switch (tuple->protocol)
    {
      case IPPROTO_UDP:
      case IPPROTO_UDPLITE:
      case IPPROTO_SCTP:
        {
          struct udp_header *udphdr;
          udphdr  =  (struct udp_header*)(pkt + IPV4_L4_HDR_OFFSET);
          temp_src_port  =  ntohs(udphdr->src_port);
          temp_dst_port  =  ntohs(udphdr->dst_port);
          ret = PACKET_PARSE;
        }
        break;
      case IPPROTO_TCP:
        {
          struct tcp_header *tcphdr;
          tcphdr  =  (struct tcp_header *)(pkt + IPV4_L4_HDR_OFFSET);
          temp_src_port  =  ntohs(tcphdr->src_port);
          temp_dst_port  =  ntohs(tcphdr->dst_port);
          ret = PACKET_PARSE;
        }
        break;
      case IPPROTO_ICMP:
        {
          temp_src_port  =  DEFAULT_PORT;
          temp_dst_port  =  DEFAULT_PORT;
          ret = PACKET_PARSE;
        }
        break;
    }

    // if source address is larger than dst address than store storereverse
    // entries otherwise store as it is
    pkt = *secmon_pkt;
    eth_hdr  =  (struct ether_header *) pkt;

    if (temp_ipv4.src_addr < temp_ipv4.dst_addr)
    {
      tuple->ip.ipv4.src_addr = temp_ipv4.src_addr;
      tuple->ip.ipv4.dst_addr = temp_ipv4.dst_addr;
      tuple->src_port = temp_src_port;
      tuple->dst_port = temp_dst_port;

      // now for mac addr calculation we have to recast pkt to ether_header
       memcpy(tuple->src_mac.addr , eth_hdr->src_mac.addr , ETHER_ADDR_LEN);
       memcpy(tuple->dst_mac.addr , eth_hdr->dst_mac.addr , ETHER_ADDR_LEN);
    }
    else
    {
      tuple->ip.ipv4.src_addr = temp_ipv4.dst_addr;
      tuple->ip.ipv4.dst_addr = temp_ipv4.src_addr;
      tuple->src_port = temp_dst_port;
      tuple->dst_port = temp_src_port;

      // now for mac addr calculation we have to recast pkt to ether_header
       memcpy(tuple->src_mac.addr , eth_hdr->dst_mac.addr , ETHER_ADDR_LEN);
       memcpy(tuple->dst_mac.addr , eth_hdr->src_mac.addr , ETHER_ADDR_LEN);
    }

    // ret = PACKET_DROP;
  }
  else if(etherType == IPV6_PACKET)
  {
    /* non vlan tagged ipv6_packet packet handling.
     * in case of taas ,  this case is most unlikely
     */
    ret = PACKET_DROP;
  }
  else
  {
    /* arp and multicast packets */
    ret = PACKET_DROP;
  }
  return ret;
}

/** finds the hash for the given tuple.
 * hash value will be actual hash value modulo hash table size.
 * @param
 * 		tuple - tuple for which hash has to be calculated.
 * @returns
 * 		hash value for the tuple
 */
inline uint32_t find_hash(struct Tuple *tuple)
{
  uint32_t murmur_hash = __find_hash(tuple);

  return murmur_hash % HASH_TABLE_SIZE;
}

/** finds the hash for the given tuple.
 * @param
 * 		tuple - tuple for which hash has to be calculated.
 * @returns
 * 		hash value for the tuple
 */
inline uint32_t __find_hash(const struct Tuple *tuple)
{
  return murmur3(tuple ,  sizeof(struct Tuple), HASH_SEED);
}

/** compares mac address from rule with tuple's mac address
 * Here mac address can be either source mac or destination
 * mac.
 *
 * @param rule_mac
 *		mac address from the rule
 * @param tuple_mac
 * 		mac address from the tuple
 * @returns
 * 		1 if mac addresses are equal or 0 otherwise.
 *
 */
bool compare_mac(uint8_t *rule_mac , uint8_t *tuple_mac)
{
  int i;
  uint8_t bytes = 0;
  /* wildcard(*) matching for mac */
  for(i = 0;i<ETHER_ADDR_LEN;i++)
  {
    if(rule_mac[i]!=0)
      break;
    bytes++;
  }

  if(bytes == ETHER_ADDR_LEN)
    return TRUE;
  return (memcmp(rule_mac , tuple_mac , ETHER_ADDR_LEN) == 0);
}

/** compares ip address from rule with tuple's ip address
 * Here ip address can be either source ip or destination
 * ip.
 *
 * @param rule_ip
 *		ip address from the rule
 * @param ip_subnet
 *		ip_subnet address from the rule
 * @param tuple_ip
 * 		ip address from the tuple
 * @returns
 * 		1 if ip addresses are equal or 0 otherwise.
 *
 */
bool compare_ip(uint32_t rule_ip ,  uint8_t ip_subnet ,  uint32_t tuple_ip)
{
  bool found  =  FALSE;
  uint8_t subnet  =  0;

  subnet  =  ip_subnet;
  tuple_ip  =  ntohl(tuple_ip);
  rule_ip &= (0xffffffff << (32 - subnet));

  if(subnet)
  {
    tuple_ip &= (0xffffffff) << (32 - subnet);
  }
  else
  {
    tuple_ip  = 0;
  }

  if((rule_ip == tuple_ip) || rule_ip == 0)
    found  =  TRUE;

  return found;
}

/** compares port value from rule with tuple's port value
 * Here port value can be either source port or destination
 * port.
 *
 * @param min_port
 *		minimum value of the port from rule
 * @param tuple_port
 * 		maximum value of the port from rule
 * @param tuple_port
 * 		port_value from the tuple
 * @returns
 * 		1 if tuple port value falls within the range or 0 otherwise.
 *
 */
bool compare_port(uint16_t min_port ,  uint16_t max_port , uint16_t tuple_port)
{
  bool found  =  FALSE;
  if ((tuple_port >= min_port) && (tuple_port <= max_port)) {
    found  =  TRUE;
  }
  return found;
}

/** compares protocol from rule with tuple's protocol.
 * DEFAULT_PROTOCOL_TYPE then it is wildcard for protocol
 * and it is considered as a match.
 *
 * @param rule_protocol
 *		protocol from the rule
 * @param tuple_protocol
 * 		protocol from the tuple
 * @returns
 * 		1 if mac addresses are equal or 0 otherwise.
 *
 */
bool compare_protocol(uint8_t rule_protocol , uint8_t tuple_protocol)
{
  bool found  =  FALSE;
  if((rule_protocol == tuple_protocol) || \
      (rule_protocol == DEFAULT_PROTOCOL_TYPE))  //addes support for wildcard protocol(0)
      {
        found  =  TRUE;
      }

  return found;
}


/** compares 7 tuples(src mac ,  dst mac ,  src ip ,  dst ip ,
 * src port ,  dst port ,  protocol) of the packet with existing
 * rules
 * @returns void
 *
 */
bool compare7tuple(struct Classification_object *rule ,  struct Tuple *tuple)
{
  uint16_t matched_fields = 0;
  do{
    /* compare source mac and destination mac*/
    if(compare_mac(rule->src_mac ,  tuple->src_mac.addr) == FALSE)
      break;
    matched_fields++;

    if(compare_mac(rule->dst_mac ,  tuple->dst_mac.addr) == FALSE)
      break;
    matched_fields++;

    /* compare source ip subnet and destination ip subnet*/
    if(compare_ip(rule->src_ip ,  rule->src_ip_subnet ,  tuple->ip.ipv4.src_addr) == FALSE)
      break;
    matched_fields++;

    if(compare_ip(rule->dst_ip ,  rule->dst_ip_subnet ,  tuple->ip.ipv4.dst_addr) == FALSE)
      break;
    matched_fields++;

    /* compare source port and destination port */
    if(compare_port(rule->min_src_port ,  rule->max_src_port ,  tuple->src_port) == FALSE)
      break;
    matched_fields++;

    if(compare_port(rule->min_dst_port ,  rule->max_dst_port ,  tuple->dst_port) == FALSE)
      break;
    matched_fields++;

    /* compare the protocol*/
    if(compare_protocol(rule->protocol , tuple->protocol) == FALSE)
      break;
    matched_fields++;

    /* all fields should match for rule matching.*/
    if(matched_fields == TOTAL_TUPLE_FIELDS)
      return TRUE;

  }while(0);

  return FALSE;
}
