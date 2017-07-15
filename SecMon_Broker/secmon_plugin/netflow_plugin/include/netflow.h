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


#ifndef _NETFLOW_H
#define _NETFLOW_H

/** @file
 *  netflow header file
 */

#include <unistd.h>
#include "utils.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <rte_mbuf.h>
#include <rte_errno.h>

#include "utils.h"
#include "timehelper.h"


#define NETFLOW_RING "netflow_ring"
#define IPHDR_MAXSIZE       (4 * 15)
#define IPV6_PACKET         0x86DD
#define IPV4_PACKET         0x0800
#define LOCK_CNT          (1<<8)   //256
#define LOCK_CNT_MASK     (LOCK_CNT-1) //255
#define VLAN_VID_MASK       0x0fff /* VLAN Identifier */
#define VLAN_PRIO_MASK      0xe000
#define VLAN_PRIO_SHIFT     13



#define TCP_FIN_RST         0x05

#define STAT_INTERVAL	    (1*60)
#define SYSINFO_INTERVAL    (5*60)

#define HASH_SEED           0
#define PAD_SIZE            4                  /* rfc prescribes flowsets to be padded */

#define TEMPLATES_HASH_SIZE	    (1<<8)
#define METRIC_DFL              100
#define MAX_QUEUE_NAME_LEN      128



#define NEXTHDR_HOP                     0       /* Hop-by-hop option header. */
#define NEXTHDR_ROUTING                 43      /* Routing header. */
#define NEXTHDR_FRAGMENT                44      /* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH                    51      /* Authentication header. */
#define NEXTHDR_NONE                    59      /* No next header */
#define NEXTHDR_DEST                    60      /* Destination options header. */
#define MAX_ID_LEN  		            80
#define PDUDATASIZE 			        1300

#define MAX_NETFLOW_DESTINATIONS        4
#define IF_NAME_SZ	                    IFNAMSIZ
#define IF_DESC_SZ	                    32
#define ETH_ADDR_LEN                    6

#define MATCH_IPV4_MASK                 0x00000001
#define MATCH_TOS_MASK                  0x00000002
#define MATCH_PROTOCOL_MASK             0x00000004
#define MATCH_SOURCE_ADDR_MASK          0x00000008
#define MATCH_DEST_ADDR_MASK            0x00000010
#define MATCH_SOURCE_PORT_MASK          0x00000020
#define MATCH_DEST_PORT_MASK            0x00000040
#define MATCH_INPUT_INTF_MASK           0x00000080
#define MATCH_MAC_MASK                  0x00000100
#define MATCH_VLAN_MASK                 0x00000200

#define MATCH_TCP_FLAGS_MASK            0x00000400
#define MATCH_IPOPTIONS_MASK            0x00000800
#define MATCH_TCPOPTIONS_MASK           0x00001000

#define COLLECT_COUNTER_MASK            0x00000001
#define COLLECT_TIMESTAMP_MASK          0x00000002
#define COLLECT_MAC_MASK                0x00000004
#define COLLECT_VLAN_MASK               0x00000008
#define COLLECT_FLOW_DIRECTION_MASK     0x00000010
#define COLLECT_INTERFACE_MASK          0x00000020
#define COLLECT_IPV4_TOTAL_LEN_MASK     0x00000040
#define COLLECT_IPV4_TTL_MASK           0x00000080
#define COLLECT_NEXT_HOP_MASK           0x00000100

static unsigned int TEMPLATE_FNF_MASK = 0;

/* Data Templates */
#define BASE_TEMPL_BASE9	0x00000001	/* netflow base stat */
#define BASE_TEMPL_IP4	0x00000004	/* IPv4 */
#define BASE_TEMPL_MASK4	0x00000008	/* Aggregated */
#define BASE_TEMPL_PORTS	0x00000010	/* UDP&TCP */
#define BASE_TEMPL_IP6	0x00000020	/* IPv6 */
#define BASE_TEMPL_ICMP9	0x00000040	/* ICMP (for V9) */
#define BASE_TEMPL_ICMPX4	0x00000080	/* ICMP IPv4 (for IPFIX) */
#define BASE_TEMPL_ICMPX6	0x00000100	/* ICMP IPv6 (for IPFIX) */
#define BASE_TEMPL_IGMP	0x00000200	/* IGMP */
#define BASE_TEMPL_LABEL6	0x00001000	/* IPv6 flow label */
#define BASE_TEMPL_MAC	0x00010000	/* MAC addresses */
#define BASE_TEMPL_VLAN9	0x00020000	/* outer VLAN for v9 */
#define BASE_TEMPL_VLANX	0x00040000	/* outer VLAN for IPFIX */
#define BASE_TEMPL_VLANI	0x00080000	/* inner VLAN (IPFIX) */
#define BASE_TEMPL_ETHERTYPE	0x00100000	/* ethernetTyp */
#define BASE_TEMPL_DIRECTION	0x00200000	/* flowDirection */
#define BASE_TEMPL_SELECTORID	0x00800000	/* selectorId (IPFIX) */
#define ADD_MASK(haystack_mask, needle_mask) (haystack_mask |= needle_mask)  //add needle to haystack

#define BASE_TEMPL_OPTION	0x80000000	/* Options Template */
#define BASE_TEMPL_MAX	32
/* Options Templates */
#define OPTION_TEMPL(x) (BASE_TEMPL_OPTION | x)
#define OPTION_TEMPL_SYSITIME	OPTION_TEMPL(1)		/* systemInitTimeMilliseconds */
#define OPTION_TEMPL_STAT	OPTION_TEMPL(2)		/* The Metering Process Statistics (rfc5101) */
#define OPTION_TEMPL_MPRSTAT	OPTION_TEMPL(3)		/* The Metering Process Reliability Statistics */
#define OPTION_TEMPL_EPRSTAT	OPTION_TEMPL(4)		/* The Exporting Process Reliability Statistics */
#define OPTION_TEMPL_SAMPLER	OPTION_TEMPL(5)		/* Flow Sampler for v9 */
#define OPTION_TEMPL_SEL_RAND	OPTION_TEMPL(6)		/* Random Flow Selector for IPFIX */
#define OPTION_TEMPL_SEL_COUNT	OPTION_TEMPL(7)		/* Systematic count-based Flow Selector for IPFIX */
#define OPTION_TEMPL_SEL_STAT	OPTION_TEMPL(8)		/* rfc7014 */
#define OPTION_TEMPL_SEL_STATH	OPTION_TEMPL(9)		/* OPTION_TEMPL_SEL_STAT ,  except selectorIDTotalFlowsObserved */
#define OPTION_TEMPL_IFNAMES	OPTION_TEMPL(10)
/* Flexible Netflow Templates */
#define FNF_BASE_TEMPL_IP_SRC_ADDR  0x00000001
#define FNF_BASE_TEMPL_IP_DEST_ADDR 0x00000002
#define FNF_BASE_TEMPL_IP_PROTOCOL  0x00000004
#define FNF_BASE_TEMPL_IP_TOS       0x00000008
#define FNF_BASE_TEMPL_IP_SRC_PORT  0x00000010
#define FNF_BASE_TEMPL_IP_DEST_PORT 0x00000020
#define FNF_BASE_TEMPL_INPUT_INTF   0x00000040
#define FNF_BASE_TEMPL_COUNTER      0x00000080
#define FNF_BASE_TEMPL_TIMESTAMP    0x00000100
#define FNF_BASE_TEMPL_MAC          0x00000200
#define FNF_BASE_TEMPL_VLAN         0x00000400
#define FNF_BASE_TEMPL_TCP_FLAGS    0x00000800
#define FNF_BASE_TEMPL_IPOPTIONS    0x00000800
#define FNF_BASE_TEMPL_TCPOPTIONS   0x00000800


#define one_elem(id ,  name ,  len) name  =  id ,
#define two_elem(id ,  a ,  b ,  len)		\
    one_elem(id ,  a ,  len)	\
one_elem(id ,  b ,  len)
#define Elements \
    two_elem(1 ,    IN_BYTES ,  octetDeltaCount ,  4) \
two_elem(2 ,    IN_PKTS ,  packetDeltaCount ,  4) \
two_elem(4 ,    PROTOCOL ,  protocolIdentifier ,  1) \
two_elem(5 ,    TOS ,  ipClassOfService ,  1) \
two_elem(6 ,    TCP_FLAGS ,  tcpControlBits ,  1) \
two_elem(7 ,    L4_SRC_PORT ,  sourceTransportPort ,  2) \
two_elem(8 ,    IPV4_SRC_ADDR ,  sourceIPv4Address ,  4) \
two_elem(9 ,    SRC_MASK ,  sourceIPv4PrefixLength ,  1) \
two_elem(10 ,   INPUT_SNMP ,  ingressInterface ,  2) \
two_elem(11 ,   L4_DST_PORT ,  destinationTransportPort ,  2) \
two_elem(12 ,   IPV4_DST_ADDR ,  destinationIPv4Address ,  4) \
two_elem(13 ,   DST_MASK ,  destinationIPv4PrefixLength ,  1) \
two_elem(14 ,   OUTPUT_SNMP ,  egressInterface ,  2) \
two_elem(15 ,   IPV4_NEXT_HOP ,  ipNextHopIPv4Address ,  4) \
two_elem(21 ,   LAST_SWITCHED ,  flowEndSysUpTime ,  4) \
two_elem(22 ,   FIRST_SWITCHED ,  flowStartSysUpTime ,  4) \
two_elem(27 ,   IPV6_SRC_ADDR ,  sourceIPv6Address ,  16) \
two_elem(28 ,   IPV6_DST_ADDR ,  destinationIPv6Address ,  16) \
two_elem(31 ,   IPV6_FLOW_LABEL ,  flowLabelIPv6 ,  3) \
two_elem(32 ,   ICMP_TYPE ,  icmpTypeCodeIPv4 ,  2) \
two_elem(33 ,   MUL_IGMP_TYPE ,  igmpType ,  1) \
two_elem(40 ,   TOTAL_BYTES_EXP ,  exportedOctetTotalCount ,  8) \
two_elem(41 ,   TOTAL_PKTS_EXP ,  exportedMessageTotalCount ,  8) \
two_elem(42 ,   TOTAL_FLOWS_EXP ,  exportedFlowRecordTotalCount ,  8) \
two_elem(48 ,   FLOW_SAMPLER_ID ,  samplerId ,  1) \
two_elem(49 ,   FLOW_SAMPLER_MODE ,  samplerMode ,  1) \
two_elem(50 ,   FLOW_SAMPLER_RANDOM_INTERVAL ,  samplerRandomInterval ,  2) \
two_elem(56 ,   SRC_MAC ,  sourceMacAddress ,  6) \
two_elem(57 ,   DST_MAC ,  postDestinationMacAddress ,  6) \
two_elem(58 ,   SRC_VLAN ,  vlanId ,  2) \
two_elem(61 ,   DIRECTION ,  flowDirection ,  1) \
two_elem(62 ,   IPV6_NEXT_HOP ,  ipNextHopIPv6Address ,  16) \
two_elem(64 ,   IPV6_OPTION_HEADERS ,  ipv6ExtensionHeaders ,  2) \
two_elem(70 ,   MPLS_LABEL_1 ,   mplsTopLabelStackSection ,  3) \
two_elem(71 ,   MPLS_LABEL_2 ,   mplsLabelStackSection2 ,    3) \
two_elem(72 ,   MPLS_LABEL_3 ,   mplsLabelStackSection3 ,    3) \
two_elem(73 ,   MPLS_LABEL_4 ,   mplsLabelStackSection4 ,    3) \
two_elem(74 ,   MPLS_LABEL_5 ,   mplsLabelStackSection5 ,    3) \
two_elem(75 ,   MPLS_LABEL_6 ,   mplsLabelStackSection6 ,    3) \
two_elem(76 ,   MPLS_LABEL_7 ,   mplsLabelStackSection7 ,    3) \
two_elem(77 ,   MPLS_LABEL_8 ,   mplsLabelStackSection8 ,    3) \
two_elem(78 ,   MPLS_LABEL_9 ,   mplsLabelStackSection9 ,    3) \
two_elem(79 ,   MPLS_LABEL_10 ,  mplsLabelStackSection10 ,   3) \
one_elem(80 ,   destinationMacAddress ,  6) \
two_elem(82 ,   IF_NAME ,  interfaceName ,  IF_NAME_SZ) \
two_elem(83 ,   IF_DESC ,  interfaceDescription ,  IF_DESC_SZ)

enum {
    Elements
};
#undef one_elem
#undef two_elem

enum {
    FLOWSET_TEMPLATE  =  0 ,
    FLOWSET_OPTIONS  =  1 ,
    IPFIX_TEMPLATE  =  2 ,
    IPFIX_OPTIONS  =  3 ,
    FLOWSET_DATA_FIRST  =  256 ,
};

enum {				            /* v9 scopes */
    SCOPE_SYSTEM  =  1 ,
    SCOPE_INTERFACE  =  2 ,
    SCOPE_LINECARD  =  3 ,
    SCOPE_CACHE  =  4 ,
    SCOPE_TEMPLATE  =  5 ,
};

/* linked lists structures */
struct list_head {
    struct list_head *next ,  *prev;
};

struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next ,  **pprev;
};


struct flowset_template {
    uint16_t	flowset_id;
    uint16_t	size;		    /* (bytes) */
    uint16_t	template_id;
    uint16_t	field_count;	/* (items) */
} __attribute__ ((packed));

struct flowset_data {
    uint16_t	flowset_id;	    /* corresponds to template_id */
    uint16_t	size;		    /* (bytes) */
} __attribute__ ((packed));

struct flowset_opt_tpl_v9 {
    uint16_t	flowset_id;
    uint16_t	size;
    uint16_t	template_id;
    uint16_t	scope_len;	    /* (bytes) */
    uint16_t	opt_len;	    /* (bytes) */
} __attribute__ ((packed));



/* NetFlow v9 packet. */
struct netflow9_pdu {
    uint16_t		version;
    uint16_t		nr_records;	/* (items) */
    uint32_t		sys_uptime_ms;
    uint32_t		export_time_s;
    uint32_t		seq;
    uint32_t		source_id;	/* Exporter Observation Domain */
    uint8_t		data[PDUDATASIZE];
} __attribute__ ((packed));

struct collector_pdu
{
    unsigned int pdu_data_records;
    unsigned int pdu_flow_records;
    unsigned int pdu_tpl_records;
    unsigned int pdu_needs_export;
    struct flowset_data *pdu_flowset;
    long long pdu_packets;
    long long pdu_traf;
    unsigned long pdu_ts_mod;
    uint8_t *pdu_data_used;
    unsigned int pdu_seq ;
    unsigned int pdu_count;
    uint8_t *pdu_high_wm;
    unsigned long ts_stat_last;
    unsigned long ts_sysinf_last;
    unsigned long ts_ifnames_last ;
    struct sockaddr_in collector_addr;

    union
    {
        uint16_t version;
        struct netflow9_pdu v9;
    } pdu;

    struct collector_pdu *next;
};



/* Maximum bytes flow can have ,  after it's reached flow will become
 * not searchable and will be exported soon. */
#define FLOW_FULL_WATERMARK 0xffefffff

#define MAX_VLAN_TAGS	2

#define IS_DUMMY_FLOW(nf) 0
#define IP_OFFSET 0x1fff

union nf_inet_addr
{
    uint32_t all[4];
    uint32_t ip;
    uint32_t ip6[4];
    struct in_addr  in;
};
/* hashed data which identify unique flow */
struct netflow_tuple {
    uint16_t		s_port;  /* Network byte order*/
    uint16_t		d_port;
    uint16_t		i_ifc;
    union nf_inet_addr src;
    union nf_inet_addr dst;
    uint16_t		tag[MAX_VLAN_TAGS]; /* Network byte order (outer tag first)*/
    uint8_t		protocol;
    uint8_t		tos;
    uint8_t		l3proto;
    uint8_t		h_dst[ETH_ADDR_LEN];
    uint8_t		h_src[ETH_ADDR_LEN];
} __attribute__ ((packed));


struct netflow_flow {
    struct hlist_node hlist; /*hashtable search chain*/

    /* unique per flow data (hashed ,  NETFLOW_TUPLE_SIZE) */
    struct netflow_tuple tuple;

    /* volatile data */
    uint32_t nh;
    uint32_t collector_hash;

    uint16_t		ethernetType; /* Network byte order */
    uint16_t		o_ifc;
#ifdef ENABLE_PHYSDEV
    uint16_t		i_ifphys;
    uint16_t		o_ifphys;
#endif
    uint8_t		s_mask;
    uint8_t		d_mask;
    uint8_t		tcp_flags; /* `OR' of all tcp flags */
    uint8_t		flowEndReason;
#ifdef ENABLE_DIRECTION
    uint8_t		hooknumx; /* hooknum + 1 */
#endif
    /* flow statistics */
    uint32_t	nr_packets;
    uint32_t	nr_bytes;
    union {
        struct {
            unsigned long first;
            unsigned long last;
        } ts;
        time_t	ts_obs;
    } _ts_un;
#define nf_ts_first _ts_un.ts.first
#define nf_ts_last  _ts_un.ts.last
#define nf_ts_obs   _ts_un.ts_obs
    uint32_t	flow_label; /* IPv6 */
    uint32_t	options; /* IPv4(16) & IPv6(32) Options */
    uint32_t	tcpoptions;
    struct list_head list; /* all flows in netflow_list */
};


static inline int netflow_tuple_equal(const struct netflow_tuple *t1 ,
        const struct netflow_tuple *t2)
{
    return (!memcmp(t1 ,  t2 ,  sizeof(struct netflow_tuple)));
}


struct netflow_socket{
    struct list_head list;
    int sockfd;
    struct sockaddr_in addr;
    int wmem_peak;
    uint64_t bytes_exp;			/* bytes -"-*/
    uint64_t bytes_exp_old;		/* for rate calculation*/
};

#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)

#define INC_NETFLOW_STAT(count)     netflow_stat.count++
#define ADD_NETFLOW_STAT(count , val) netflow_stat.count += (unsigned long long) val
#define SET_NETFLOW_STAT(count , val) netflow_stat.count  =  (unsigned long long) val
#define TS_NETFLOW_STAT(count)      \
    do {                            \
        time_t kts   =  time(NULL);       \
        if(! netflow_stat.count.first ) \
        netflow_stat.count.first  =  kts; \
        netflow_stat.count.last  =  kts;   \
    }while(0);


#define   ETHER_TYPE_VLAN   0x8100

struct vlan_header
{
    uint16_t vlan_tci;              /** Tag control information */
    uint16_t vlan_net_proto;        /** Encapsulated protocol */
} __attribute__ (( packed ));

#define CONF_FILE 	"/opt/secmon/plugins/config/conf_params.cfg"
#define FLOWDUMP	"/opt/secmon/plugins/flow_dump.txt"
#define MAXFLOW     2000000
#define AC_TM_OUT   1 * 60  //1min i.e 300 secs
#define INAC_TM_OUT 2 * 60  //2min i.e 300 secs

#define MAX_MATCH_FIELD  0xffffffff
#define MAX_COLLECT_FIELD 0xffffffff
#define TM_RATE          30
#define NETFLOW_PROTOCOL 9
#define REFRESH_RATE    20
#define NETFLOW_VERSION_SIZE    39
#define NETFLOW_VERSION_LEN     128

struct duration {
    unsigned long first;
    unsigned long last;
};

/* statistics */
struct netflow_stat {
    uint64_t searched;
    uint64_t found;
    uint64_t notfound;
    uint64_t  pkt_total;		/* total packets */
    uint64_t traf_total;		/* total traffic */
    unsigned int alloc_err;		/* allocation failure error (drop & lost)*/
    struct duration drop;
    unsigned int send_success;
    unsigned int send_failed;
    unsigned int sock_cberr;
    unsigned int truncated;		/* stat (drop)*/
    unsigned int frags;		    /* stat (drop)*/
    unsigned int maxflows_err;	/* maxflows limit error (drop)*/
    unsigned int exported_rate;
    uint64_t exported_pkt;
    uint64_t exported_flow;
    uint64_t exported_traf;
    uint64_t exported_trafo;
    uint64_t  pkt_total_prev;
    uint32_t  pkt_total_rate;
    uint64_t  pkt_lost;			/* packets not sent */
    uint64_t traf_lost;			/* traffic not sent */
    uint64_t  pkt_drop;			/* packets not considered */
    uint64_t traf_drop;			/* traffic not considered */
    uint64_t flow_lost;			/* flows not sent */
    struct duration lost;
    uint64_t old_searched;		/* previous stat*/
    uint64_t old_found;
    uint64_t old_notfound;
    uint64_t  pkt_out;			/* packets out */
    uint64_t traf_out;			/* traffic out */
    int metric;
};

struct ip_addr
{
    unsigned char byte1;
    unsigned char byte2;
    unsigned char byte3;
    unsigned char byte4;
};

struct option_field
{
    unsigned char opt_type;
    unsigned char opt_size;
    unsigned char opt_data[38];
};


struct frag_hdr
{
    unsigned char  nexthdr;
    unsigned char reserved;
    uint16_t  frag_off;
    uint32_t  identification;
};


int init(void);
int receive_data();
void deinit(void *arg);

#ifdef USE_RING
void netflow_get_packets(void *args);
#endif
int config();
void delete_netflow_monitor_params(void);
uint8_t rte_eth_dev_count(void);
void *configurations(void *arg);
void fetch_all_config(void);
struct collector_pdu *find_pdu_by_collector(struct sockaddr_in);
void netflow_exit(void *);

void *get_configurations(void *arg);
void print_netflow_packet(char *pkt , int len);

void apply_filters(struct Tuple *tuple ,  uint32_t hash_code , bool *found);

struct Collector_object *append_collectors(struct Collector_object *cobj ,  uint32_t hash_code ,
        struct Collector_object *cobj_head);

inline bool hash_entry_available(uint32_t value);

void initialize_hash_table(void);

void add_configurations(void);
void print_pdu_details(struct collector_pdu *);
void remove_hash_entry(int );
bool delete_not_need_pdu(struct sockaddr_in );
void decrement_session(struct Collector_object *collec_obj);
void remove_netflow_hash_entry(unsigned int i);


#endif
