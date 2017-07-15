/*    Copyright (c) 2016 Intel Corporation.
 *    All Rights Reserved.
 *
 *    Licensed under the Apache License ,  Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by a  pplicable law or agreed to in writing ,  software
 *    distributed under the License is distributed on an "AS IS" BASIS ,  WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND ,  either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */

#define _GNU_SOURCE
/**
 * @file
 *
 *   Netflow Feature Implementation
 *
 *   This File contains all the APIs and protocol logic to implement Netflow
 *   Protocol.  Netflow is working as a thread inside DPDK SecMon Application ,
 *   receiving data packets ,  parsing and creating the netflow records.
 *
 *   These flow records shall be analyzed against various timeouts(refer RFC 3954)
 *   for exportability in every 1 Sec.

 *   Flexible Netflow is also supported with limited scope of Match and Collect
 *   Fields.
 */

#include "netflow.h"

/* Hash list macros */

#define container_of(member_ptr, containing_type, member)       \
     ((containing_type *)                       \
      ((char *)(member_ptr)                     \
       - offsetof(containing_type, member)))

#define NULL1  ((void *) 0x00100100)
#define NULL2  ((void *) 0x00200200)



#define INIT_HLIST_HEAD(ptr) ((ptr)->first  =  NULL)

#define HLIST_ADD_HEAD( n ,  h) 				\
do {											\
    struct hlist_node *first  =  (h)->first;	\
    (n)->next  =  first;						\
    if (first)									\
        (first)->pprev  =  &((n)->next);		\
    (h)->first  =  n;							\
    (n)->pprev  =  &((h)->first);				\
} while(0)

#define HLIST_DELETE(n)							\
do {											\
	struct hlist_node *next  =  (n)->next;		\
    struct hlist_node **pprev  =  (n)->pprev;	\
    *pprev  =  next;							\
    if (next)									\
        (next)->pprev  =  pprev;				\
	(n)->next  =  NULL1;						\
    (n)->pprev  =  NULL2;						\
} while(0)

/* end of HLIST macros */

/* List helpers */

#define _LIST_HEAD(name) \
    struct list_head name  =  { &(name), &(name) }

#define INIT_LIST_HEAD(list)					\
	do {										\
		(list)->next = list;					\
		(list)->prev = list;					\
	} while(0)			

static inline void list_add_end(struct list_head *n, struct list_head *h)
{
	struct list_head *prev = h->prev;
	struct list_head *next = h;
    next->prev  =  n;
    n->next  =  next;
    n->prev  =  prev;
    prev->next  =  n;	
}

static inline void list_displace_tail(struct list_head *l, struct list_head *h)
{
	l->prev->next = l->next;
	l->next->prev = l->prev;
	list_add_end(l, h);
}


static inline void list_add(struct list_head *n, struct list_head *h)
{
	struct list_head *prev = h;
	struct list_head *next = h->next;
    next->prev  =  n;
    n->next  =  next;
    n->prev  =  prev;
    prev->next  =  n;	
}

static inline void list_move(struct list_head *l, struct list_head *h)
{
	l->prev->next = l->next;
	l->next->prev = l->prev;
	list_add(l, h);
}

static inline void list_del(struct list_head *n)
{
	n->prev->next = n->next;
	n->next->prev = n->prev;
	n->next = NULL1;
	n->prev = NULL2;
}

/* end of List helpers */

pthread_t netflow_configurations_tid;
pthread_t hash_timer_tid;
pthread_mutex_t hash_lock;

/* if we are using dpdk ring to enqueue packets */
#ifdef USE_RING
pthread_t netflow_get_packets_tid;
struct rte_ring *r;
#endif

unsigned long start_jiffies  =  0;
bool netflow_plugin_enabled  =  FALSE;

static char netflow_version[NETFLOW_VERSION_LEN];
static int  netflow_version_len  =  NETFLOW_VERSION_SIZE;
timer_t gtimer_id; //netflow_examine_n_transmit timer
timer_t stat_timer_id;
int flush  =  0;
static int nf_hash_table_size;
/*configurable timeouts */
static int nf_max_pkt_flows  =  MAXFLOW; /** < netflow maximum packet flows*/
static int pdu_active_timeout  =  AC_TM_OUT;  //5min i.e 300 secs
static int pdu_inactive_timeout  =  INAC_TM_OUT;  //5min i.e. 300 secs

#ifdef SECMON_DEBUG_LOG
#endif

/* Flexible Netflow Support Added */
static char fnf  =  0;
static int match_fields  =  MAX_MATCH_FIELD;
static int collect_fields  =  MAX_COLLECT_FIELD;

static int netflow_count = 0;

//Global Stats
struct netflow_stat netflow_stat;

static unsigned int pdu_timeout_rate  =  TM_RATE;
static int template_ids  =  FLOWSET_DATA_FIRST;
static int templates_count; /* how much active templates */
static struct hlist_head templates_hash_list[TEMPLATES_HASH_SIZE];

static struct hlist_head *nf_tuple_hash_table; /* hash table memory */
static unsigned int nf_tuple_hash_table_size; /* buckets */

struct netflow_entry {
    struct list_head list; /* list for export */
    pthread_spinlock_t lock; /* hash table stripe & list above */
};
static struct netflow_entry nf_hash_table_stripes[LOCK_CNT];
static unsigned int wk_count;  /* how much is scanned */
static unsigned int wk_trylock;


//configuration variables
static int protocol  =  NETFLOW_PROTOCOL;

static unsigned int scan_max;
static unsigned int refresh_rate  =  REFRESH_RATE;


static pthread_mutex_t sock_lock  =  PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t netflow_hash_lock;

struct collector_pdu *pdu_list = NULL;
int *netflow_rule_futex;

static _LIST_HEAD(sock_list);
static int engine_id; /* Observation Domain */

struct data_template *get_flexible_flowtemplate(const unsigned int tmask);
inline int export_active(const struct netflow_flow *nf ,  const unsigned long a_timeout , const unsigned long j);
inline int export_inactive(const struct netflow_flow *nf ,  const unsigned long i_timeout , const unsigned long j);
void netflow_dump_packet(union sigval sigv);
void netflow_examine_n_transmit(union sigval sigv);
void netflow_receive(void);
void dump_hashtable(void);
static void fill_dtls_n_export_pdu(struct collector_pdu *coll_pdu);
static inline int is_zero_ether_addr(const struct hw_addr *ea);




inline unsigned long get_time()
{
    struct timeval tv;
    unsigned long ms;
    gettimeofday(&tv , NULL);
    ms  =  tv.tv_sec * 1000;
    return  ms;
}


/**
 *   check time less than current or not
 *   @returns
 *      response        response from server
 *
 */
int time_is_before(unsigned long a)
{
    unsigned long now  =  get_time(); //timespec now();
    if (a <= now)
        return SUCCESS;
    else
        return FAILURE;
}

/**
 *   check time greater than current or not
 *   @returns
 *      response        response from server
 *
 */
int time_is_after(unsigned long a)
{
    unsigned long now  =  get_time(); //timespec now();
    if (a >= now)
        return SUCCESS;
    else
        return FAILURE;
}

inline unsigned long  get_currentTime()
{
    struct timeval tv;
    unsigned long ms;
    gettimeofday(&tv , NULL);
    ms  =  tv.tv_sec * 1000;
    return  ms;
}



static void create_fnf_templ_mask()
{
  if(match_fields & MATCH_SOURCE_ADDR_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_IP_SRC_ADDR);
  }
  if(match_fields & MATCH_DEST_ADDR_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_IP_DEST_ADDR);
  }
  if(match_fields & MATCH_TOS_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_IP_TOS);
  }
  if(match_fields & MATCH_PROTOCOL_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_IP_PROTOCOL);
  }
  if(match_fields & MATCH_SOURCE_PORT_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_IP_SRC_PORT);
  }
  if(match_fields & MATCH_DEST_PORT_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_IP_DEST_PORT);
  }
  if(match_fields & MATCH_INPUT_INTF_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_INPUT_INTF);
  }
  if(match_fields & MATCH_MAC_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_MAC);
  }
  if(match_fields & MATCH_VLAN_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_VLAN);
  }

  if(match_fields & MATCH_TCP_FLAGS_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK,  FNF_BASE_TEMPL_TCP_FLAGS);
  }
  if(match_fields & MATCH_IPOPTIONS_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_IPOPTIONS);
  }
  if(match_fields & MATCH_TCPOPTIONS_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_TCPOPTIONS);
  }

  if(collect_fields & COLLECT_COUNTER_MASK )
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_COUNTER);
  }
  if(collect_fields & COLLECT_TIMESTAMP_MASK)
  {
      ADD_MASK(TEMPLATE_FNF_MASK, FNF_BASE_TEMPL_TIMESTAMP);
  }
}

static unsigned int create_nf_templ_mask(struct netflow_flow *nf)
{
  int template_mask = BASE_TEMPL_BASE9;

  if ( (nf->tuple.l3proto == AF_INET))
   {
       ADD_MASK(template_mask, BASE_TEMPL_IP4);
   }
   else
   {
       ADD_MASK(template_mask, BASE_TEMPL_IP6);
       if ( (nf->flow_label))
           ADD_MASK(template_mask, BASE_TEMPL_LABEL6);
   }
   if ( (nf->tcpoptions))
	   
   if ( (nf->s_mask || nf->d_mask))
       ADD_MASK(template_mask, BASE_TEMPL_MASK4);
   if ( (nf->tuple.protocol == IPPROTO_TCP ||
               nf->tuple.protocol == IPPROTO_UDP ||
               nf->tuple.protocol == IPPROTO_SCTP ||
               nf->tuple.protocol == IPPROTO_UDPLITE))
       ADD_MASK(template_mask, BASE_TEMPL_PORTS);
   else if (nf->tuple.protocol == IPPROTO_ICMP ||
           nf->tuple.protocol == IPPROTO_ICMPV6) {
       if (protocol == 9)
           ADD_MASK(template_mask, BASE_TEMPL_ICMP9);
       else if ( (nf->tuple.l3proto == AF_INET))
           ADD_MASK(template_mask, BASE_TEMPL_ICMPX4);
       else
           ADD_MASK(template_mask, BASE_TEMPL_ICMPX6);
   }
   else if (nf->tuple.protocol == IPPROTO_IGMP)
       ADD_MASK(template_mask, BASE_TEMPL_IGMP);
   struct hw_addr eas;
   struct hw_addr ead;
   memcpy(eas.addr , nf->tuple.h_src , ETH_ADDR_LEN);
   memcpy(ead.addr , nf->tuple.h_dst , ETH_ADDR_LEN);

   if (!is_zero_ether_addr(&eas) || !is_zero_ether_addr(&ead))
       ADD_MASK(template_mask, BASE_TEMPL_MAC);
   if (nf->tuple.tag[0]) {
       if (protocol == 9)
           ADD_MASK(template_mask, BASE_TEMPL_VLAN9);
       else {
           ADD_MASK (template_mask, BASE_TEMPL_VLANX);
           if (nf->tuple.tag[1])
               ADD_MASK(template_mask, BASE_TEMPL_VLANI);
       }
   }
   if (nf->ethernetType)
       ADD_MASK(template_mask, BASE_TEMPL_ETHERTYPE);
#ifdef ENABLE_DIRECTION
   if (nf->hooknumx)
       ADD_MASK(template_mask, BASE_TEMPL_DIRECTION);
#endif
return template_mask;
}


enum {
    DONT_FLUSH ,  AND_FLUSH
};

/* global table of sizes of template field types */
#define two_elem(id ,  a ,  b ,  len)	[id]  =  len ,
#define one_elem(id ,  a ,  len)		[id]  =  len ,
static uint8_t tpl_element_sizes[]  =  {
    Elements
};
#undef two_elem
#undef one_elem

static struct duration start_ts; /* ts of module start (time_t) */
struct data_template {
    struct hlist_node hlist;
    unsigned int tpl_key;

    char options;	/* is it Options Template */
    short size;	/* number of elements in template */
    short tpl_size;	/* whole size of template itself (with header), for alloc */
    short rec_size;	/* size of one template record (w/o header) */
    int template_id_n; /* uassigned from template_ids ,  network order. */
    int		exported_cnt;
    unsigned long	exported_ts; /* last exported (jiffies) */
    uint16_t fields[]; /* {type ,  size} pairs */
} __attribute__ ((packed));


struct base_template {
    int size; /* number of elements in template */
    uint16_t types[]; /* {type ,  size} pairs */
};

static struct base_template template_v9 = {
  .types = {
    TOTAL_BYTES_EXP,
    TOTAL_PKTS_EXP,
    TOTAL_FLOWS_EXP,
    0
  },
  .size = 3
};

static struct base_template template_base_9  =  {
    .types  =  {
        INPUT_SNMP ,
        OUTPUT_SNMP ,
        IN_PKTS ,
        IN_BYTES ,
        FIRST_SWITCHED ,
        LAST_SWITCHED ,
        PROTOCOL ,
        TOS ,
        0
    },
    .size = 8
};


static struct base_template template_vlan_v9  =  {
    .types  =  { SRC_VLAN ,  0 },
    .size = 1
};

#ifdef ENABLE_DIRECTION
static struct base_template template_direction  =  {
    .types  =  { DIRECTION ,  0 }
};
#endif

#define TPL_FIELD_NSIZE 4 /* one complete template field's network size */


static struct base_template template_ipv4  =  {
    .types  =  {
        IPV4_SRC_ADDR ,
        IPV4_DST_ADDR ,
        IPV4_NEXT_HOP ,
        0
    },
    .size = 3
};

static struct base_template template_ipv4_mask  =  {
    .types  =  {
        SRC_MASK ,
        DST_MASK ,
        0
    },
    .size = 2
};

static struct base_template template_ports  =  {
    .types  =  {
        L4_SRC_PORT ,
        L4_DST_PORT ,
        TCP_FLAGS ,
        0
    },
    .size = 3
};

static struct base_template template_icmp_v9  =  {
    .types  =  {
        L4_SRC_PORT , 	/* dummy (required by some collector(s) to
                           recognize ICMP flows) */
        L4_DST_PORT , 	/* actually used in V9 world instead of
                           ICMP_TYPE(32), disregarding docs */
        0
    },
    .size = 2
};
static struct base_template template_icmp_ipv4  =  {
    .types  =  { icmpTypeCodeIPv4 ,  0 },
    .size = 1
};

static struct base_template template_igmp  =  {
    .types  =  { MUL_IGMP_TYPE ,  0 },
    .size = 1
};


static struct {
    uint64_t		ms;	 /* this much abs milliseconds */
    unsigned long	jiffies; /* is that much jiffies */
} time_base;

/* structures defined in get_flexible_flow_template */
static struct base_template bt_src_addr  =  {
    .types  =  {IPV4_SRC_ADDR , 0},
    .size = 1
};

static struct base_template bt_dst_addr  =  {
    .types  =  {IPV4_DST_ADDR , 0},
    .size = 1
};

static struct base_template bt_tos  =  {
    .types  =  {TOS , 0},
    .size = 1
};

static struct base_template bt_proto  =  {
    .types  =  {PROTOCOL , 0},
    .size = 1
};

static struct base_template bt_src_port  =  {
    .types  =  {L4_SRC_PORT , 0},
    .size = 1
};

static struct base_template bt_dst_port  =  {
    .types  =  {L4_DST_PORT , 0},
    .size = 1
};

static  struct base_template bt_input_intf  =  {
    .types  =  {INPUT_SNMP , 0},
    .size = 1
};


static struct base_template bt_vlan  =  {
    .types  =  {SRC_VLAN , 0},
    .size = 1
};

static  struct base_template bt_tcp_flags  =  {
    .types  =  {TCP_FLAGS , 0},
    .size = 1
};

static  struct base_template bt_counter  =  {
    .types  =  {IN_PKTS , IN_BYTES , 0},
    .size = 2
};

static struct base_template bt_timestamp  =  {
    .types  =  {FIRST_SWITCHED ,  LAST_SWITCHED ,  0},
    .size = 2
};

/* end of get_flexible_flow_template structures */



static void set_time_base(void)
{
    struct timespec time;

    /* try to get them atomically */
    time_base.jiffies  =  get_currentTime();
    clock_gettime(CLOCK_REALTIME,&time);
    time_base.ms  =  time_base.jiffies;
}



/* cache timeout_rate in jiffies
 *    @returns void
 *
 */
static inline unsigned long timeout_rate_j(void)
{
    static unsigned int t_rate  =  0;
    static unsigned long t_rate_j  =  0;

    if ( (pdu_timeout_rate != t_rate)) {

        t_rate  =  pdu_timeout_rate;
    }
    return t_rate_j;
}



static inline uint32_t find_hash_nf_tuple(const struct netflow_tuple *tuple);

/**
 *  This is the internal wrapper function used to call the underlying hashing api.
 *  We are using murmur3 hashing algorithm.
 *
 * @param tuple
 *      netflow tuple for which hash need to be calculated
 * @return
 *      calculated hash for incoming tuple
 */
static inline uint32_t __find_hash_nf_tuple(const struct netflow_tuple *tuple)
{
    return murmur3(tuple ,  sizeof(struct netflow_tuple), HASH_SEED);
}

/**
 *  Wrapper function for calculating hash value by taking the modulus from
 *  nf_tuple_hash_table_size.
 *
 * @param tuple
 *      netflow tuple for which hash need to be calculated
 * @return
 *      calculated hash for incoming tuple
 */
static inline u_int32_t find_hash_nf_tuple(const struct netflow_tuple *tuple)
{
    return __find_hash_nf_tuple(tuple) % nf_tuple_hash_table_size;
}

/**
 *  Function for hash table allocation ,  this hash table shall be used to
 *  store the flow records created based on the received data traffic.
 *   This is implemented as hlist.
 * @param size
 *      hash table size to be allocated
 * @return
 *      pointer to the allocated hash list head.
 */
static struct hlist_head *alloc_tuple_hash_table(const int size)
{
    struct hlist_head *hash;
    SECMON_DEBUG("NETFLOW: allocating hashtable with size=%d\n",size);
    hash  =  (struct hlist_head*) malloc(sizeof(struct hlist_head) * size);
    if (hash) {
        int i;
        for (i  =  0; i < size; i++)
            INIT_HLIST_HEAD(&hash[i]);
    } else
    {
        SECMON_CRITICAL("ERROR: NETFLOW: unable to malloc hash table.\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
    return hash;
}

/**
 *  Function to clear the netflow stats
 * @return void
 *
 */

static void clear_netflow_stats(void)
{
    memset(&netflow_stat ,  0 ,  sizeof(netflow_stat));
    netflow_stat.metric  =  METRIC_DFL;
}


/*******************************************************************************************
 *******************************************************************************************
 SOCKET CODE FOR CONNECTING WITH NETFLOW COLLECTOR
 ********************************************************************************************
 *******************************************************************************************/
/**
 *  Socket comparison function based on the sockaddr values. This function shall compare the
 *  two sockasddr ,  if they are created for same remote IP Address.
 *  @param sa1
 *      sockaddr 1 for comparison
 *  @param sa2
 *      sockaddr2 for comparison
 * @return
 *      true: if both sockets have same IP address
 *      false: otherwise.
 */
static int sockaddr_match_ipaddr4(const struct sockaddr *sa1 ,  const struct sockaddr *sa2)
{
    const struct sockaddr_in *sin1  =  (const struct sockaddr_in *)sa1;
    const struct sockaddr_in *sin2  =  (const struct sockaddr_in *)sa2;

    return sin1->sin_addr.s_addr == sin2->sin_addr.s_addr;
}

/**
 *  Socket comparison function based on the sockaddr values. This function shall compare the
 *  two sockasddr ,  if they are created for same remote IP Address and Port.
 *  @param sa1
 *      sockaddr 1 for comparison
 *  @param sa2
 *      sockaddr2 for comparison
 * @return
 *      true: if both sockets have same IP address and Port
 *      false: otherwise.
 */
static int sockaddr_cmp_ip4(const struct sockaddr *sa1 ,  const struct sockaddr *sa2)
{
    const struct sockaddr_in *sin1  =  (const struct sockaddr_in *)sa1;
    const struct sockaddr_in *sin2  =  (const struct sockaddr_in *)sa2;

    return sockaddr_match_ipaddr4(sa1 ,  sa2) &&
        (sin1->sin_port == sin2->sin_port);
}

/**
 *  Function to store details stored in sock address in char array & returns it
 * @param ss
 *      contain the pointer to sockaddress object contain details
 * @return
 *			buf		contain the details stored in sock address
 *
 */

static char *cnvrt_sockaddr_to_array(const struct sockaddr_in *ss)
{
    static char buf[64];
    char str[INET_ADDRSTRLEN];
    inet_ntop(ss->sin_family ,  &ss->sin_addr , str ,  INET_ADDRSTRLEN);

    snprintf(buf ,  sizeof(buf), "%s:%u",
            str , ntohs(((const struct sockaddr_in *)ss)->sin_port));

    return buf;
}

/**
 *  Function finds pdu exists or not in pdu_list with the supplied collector details
 *	if exists return it otherwise create new pdu ,  add to pdu list and returns it
 * @param collector_address
 *      contain the collector details
 * @return
 *      temp  contains pdu for collector
 *
 */

struct collector_pdu *find_pdu_by_collector(struct sockaddr_in collector_address)
{
    struct collector_pdu *last,*temp;

    last = NULL;
    temp = pdu_list;
    SECMON_DEBUG("NETFLOW: %s called ", __func__);
    while(temp!=NULL)
    {
        if (sockaddr_cmp_ip4((struct sockaddr *)&temp->collector_addr,(struct sockaddr *)&collector_address))
        {
            return temp;
        }

        last = temp;
        temp = temp->next;
    }

    /*create pdu and return*/
    temp=(struct collector_pdu *) malloc(sizeof(struct collector_pdu));

    memset(temp,'\0',sizeof(struct collector_pdu));
    temp->pdu_data_used = temp->pdu.v9.data;

    temp->pdu_flowset  =  NULL;
    temp->pdu_high_wm        =  (unsigned char *)&temp->pdu+ sizeof(temp->pdu.v9);
    temp->pdu.version  =  htons(protocol);
    temp->pdu.v9.version = temp->pdu.version;

    temp->pdu.v9.version = temp->pdu.version;

    /*add collector socket details to pdu*/
    temp->collector_addr.sin_family  =  AF_INET;
    temp->collector_addr.sin_port  =  collector_address.sin_port;
    temp->collector_addr.sin_addr = collector_address.sin_addr;

    /*add psu to list*/
    if(last==NULL)
    {
        pdu_list = temp;
    }
    else
    {
        last->next = temp;
    }

    return temp;
}

/**
 *  Function print the details store in pdu supplied
 * @param temp
 *      contain pdu to be printed
 * @return void
 *
 */
void print_pdu_details(struct collector_pdu *temp)
{
    SECMON_DEBUG("\n\n\npdu details\n");
    SECMON_DEBUG("flow records=%d\n",temp->pdu_flow_records);
    SECMON_DEBUG("tpl records=%d\n",temp->pdu_tpl_records);
    SECMON_DEBUG("needs export=%d\n",temp->pdu_needs_export);
    if(temp->pdu_flowset!=NULL)
        SECMON_DEBUG("flowset id=%d len=%d\n",temp->pdu_flowset->flowset_id , temp->pdu_flowset->size);
    else
        SECMON_DEBUG("flowset is null\n");

    SECMON_DEBUG("packets=%llu\n",temp->pdu_packets);
    SECMON_DEBUG("traf=%llu\n",temp->pdu_traf);
    SECMON_DEBUG("ts mod=%ld\n",temp->pdu_ts_mod);
    SECMON_DEBUG("pdu data used=%p\n",temp->pdu_data_used);
    SECMON_DEBUG("pdu seq=%d\n",temp->pdu_seq);

    SECMON_DEBUG("\n collector addr =%s\n",cnvrt_sockaddr_to_array(&temp->collector_addr));
    SECMON_DEBUG("pdu high vm=%p\n",temp->pdu_high_wm);
    SECMON_DEBUG("pdu version=%d\n",temp->pdu.v9.version);
    SECMON_DEBUG("pdu loc=%p\n",temp->pdu.v9.data);
    SECMON_DEBUG("pdu rcrds=%d\n",temp->pdu.v9.nr_records);
    fflush(stdout);

}


/**
 *  Socket creation function which wraps the unix socket api(), and open
 *  UDP socket for netflow destination.
 *  @param addr
 *      sockaddr value for opening the UDP Socket
 *  @param user_data
 *      user data
 *  @return
 *      buffer containing the converted socket parameters into char buffer
 *
 */
static int create_nf_socket(const struct sockaddr_in *addr ,  void *user_data)
{
    int sockfd;
    if(user_data == NULL)
    {
        SECMON_CRITICAL("ERROR: No user data provided..\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
    if ((sockfd  =  socket(addr->sin_family ,  SOCK_DGRAM ,  IPPROTO_UDP)) < 0) {
        return errno;
    }

    return sockfd;
}

/**
 *  open socket if created then print its details otherwise give error log
 *  @param socket
 *      will contain open socket
 *	@param sendmsg
 *			contain 1 to check in error conditions
 *  @return void
 *
 */
static void connect_nf_socket(struct netflow_socket *socket ,  const int sendmsg)
{
    socket->sockfd  =  create_nf_socket(&socket->addr ,  socket);
    if (socket->sockfd > 0)
    {
        SECMON_DEBUG("NETFLOW: connected %s\n",cnvrt_sockaddr_to_array(&socket->addr));
    }
    else
    {
        SECMON_CRITICAL("ERROR: NETFLOW: connect to %s failed%s.\n",
                cnvrt_sockaddr_to_array(&socket->addr),
                (sendmsg)? " (pdu lost)" : "");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
    socket->wmem_peak = 0;
}

/**
 *  Socket close function which wraps the unix socket api close()
 *  @param usock
 *      sockaddr value for close the UDP Socket
 *	@returns void
 *
 */
static void close_n_free_nf_socket(struct netflow_socket *usock)
{
    SECMON_DEBUG("NETFLOW: removed destination %s\n",
            cnvrt_sockaddr_to_array(&usock->addr));
    close(usock->sockfd);
    free(usock);
}

/**
 *  This function is used to add the open/connected socket to the destination
 *  socket list. This list is used to maintain multiple netflow collectors.
 *  Each node in the list represent the individual collector and its parameters.
 *
 *  @param uscok
 *      netflow_socket pointer to be added in the destination list.
 *	@returns void
 */
static void add_nf_socket(struct netflow_socket *usock)
{
    struct netflow_socket *sk;

    pthread_mutex_lock(&sock_lock);
    /* don't need duplicated sockets */
	for (sk  =  container_of((&sock_list)->next ,  typeof(*sk), list);
            &sk->list != &sock_list;
            sk  =  container_of(sk->list.next ,  typeof(*sk), list))
    {
        if (sockaddr_cmp_ip4((struct sockaddr *)&sk->addr,(struct sockaddr *)&usock->addr))
        {
            SECMON_DEBUG("Socket with same IP/Port exist!!!\n");
            pthread_mutex_unlock(&sock_lock);
            close_n_free_nf_socket(usock);
            return;
        }
    }

    list_add_end(&usock->list ,  &sock_list);
    SECMON_DEBUG("NETFLOW: added destination %s%s\n",cnvrt_sockaddr_to_array(&usock->addr)
            ,(!usock->sockfd)? " (unconnected)" : "" );


#ifdef SECMON_DEBUG_LOG
    int i = 0;
	for (sk  =  container_of((&sock_list)->next ,  typeof(*sk), list);
		&sk->list != &sock_list;
		sk  =  container_of(sk->list.next ,  typeof(*sk), list))
    {
        SECMON_DEBUG("Destination %d: %s \n",i++,cnvrt_sockaddr_to_array(&sk->addr));
    }
#endif
    pthread_mutex_unlock(&sock_lock);
}

/**
 *  This function sends the netflow pdu to the all the configured destinations.
 *  It iterates over the destination list and send the created netflow pdu to all
 *  destination node.
 *
 *  @param buffer
 *      buffer to sent on socket
 *  @param len
 *      buffer length
 *	@returns void
 *
 */
static void send_netflow_pdus_to_tools(void *buffer ,  const int len , struct collector_pdu *coll_pdu)
{
    int count = 0;
    struct collector_pdu *temp;
    temp = pdu_list;
    while(temp!=NULL)
    {
        count++;
        temp = temp->next;
    }

    SECMON_DEBUG("\n\n\t\t........no of pdu=%d......\n",count);
    int retok  =  0 ,  ret;
    int snum  =  0;
    struct netflow_socket *usock  =  NULL;

    pthread_mutex_lock(&sock_lock);
	for (usock  =  container_of((&sock_list)->next ,  typeof(*usock), list);
		&usock->list != &sock_list;
		usock  =  container_of(usock->list.next ,  typeof(*usock), list))
    {
        SECMON_DEBUG("curr_pdu coll details =%d:%d\n",(usock->addr.sin_addr).s_addr , usock->addr.sin_port);
        if (sockaddr_cmp_ip4((struct sockaddr *)&usock->addr,(struct sockaddr *)&coll_pdu->collector_addr))
        {
            usock->bytes_exp += len;
            if (usock->sockfd <=0)
                connect_nf_socket(usock ,  1);
            if (usock->sockfd <=0 )
            {
                INC_NETFLOW_STAT(send_failed);
                continue;
            }
            ret  =  sendto(usock->sockfd,(char *)buffer , len , 0,(struct sockaddr *)&usock->addr , sizeof(struct sockaddr_in));
            if (ret < 0)
            {
                SECMON_CRITICAL("ERROR: Error in sending msg...%d\n",errno);
                perror("Error occurs. Please check /var/log/secmon.log file for error\n");

                char *suggestion  =  "";
                INC_NETFLOW_STAT(send_failed);
                if (ret == -EAGAIN)
                {
                    suggestion  =  ": increase sndbuf!";
                }
                else
                {
                    if (ret == -ENETUNREACH)
                    {
                        suggestion  =  ": network is unreachable.";
                    }
                    else if (ret == -EINVAL)
                    {
                        close_n_free_nf_socket(usock);
                        suggestion  =  ": will reconnect.";
                    }
                }
                SECMON_CRITICAL("error: %s", suggestion);
            }
            else
            {
                SECMON_DEBUG("Sent!!! ret =%d to %d:%d\n",ret,(usock->addr.sin_addr).s_addr , usock->addr.sin_port);

                SECMON_DEBUG("NETFLOW: sendmsg[%d] error %d: data loss %llu pkt ",snum ,  ret ,  coll_pdu->pdu_packets);
                INC_NETFLOW_STAT(exported_pkt);
                ADD_NETFLOW_STAT(exported_traf ,  ret);
                retok++;
            }

            break;
        }//check for collector
        else
        {
            SECMON_DEBUG("collector not matched\n");
        }
        snum++;
    }
    pthread_mutex_unlock(&sock_lock);
    if (retok == 0)
    {
        /* not least one send succeded ,  account stat for dropped packets */
        ADD_NETFLOW_STAT(pkt_lost ,  coll_pdu->pdu_packets);
        ADD_NETFLOW_STAT(traf_lost ,  coll_pdu->pdu_traf);
        ADD_NETFLOW_STAT(flow_lost ,  coll_pdu->pdu_flow_records);
        TS_NETFLOW_STAT(lost);
    } else {
        ADD_NETFLOW_STAT(exported_flow ,  coll_pdu->pdu_flow_records);
    }
}

/**
 *  This function is used to delete the particular netflow destination from the
 *  configured destination list when delete destination request is received from
 *  GUI.  For deletion-
 *     - It close the socket towards the destination to be deleted.
 *     - Deletes the node from the destination list
 *  @param ip
 *      ip address of the destination to be deleted
 *  @param port
 *      UDP port number of the destination to be deleted
 *  @returns void
 */
void delete_netflow_destination(char *ip , uint32_t port)
{

    struct netflow_socket *sk;
    int succ  = 0;
    SECMON_DEBUG("NETFLOW: in delte_netflow_destination...%s:%d\n",ip , port);

    struct sockaddr_in sin;
    memset(&sin ,  0 ,  sizeof(sin));

    sin.sin_family  =  AF_INET;
    sin.sin_port  =  htons(port);
    succ  =  inet_pton(sin.sin_family , ip ,  &sin.sin_addr);
    if (!succ)
    {
        SECMON_CRITICAL("NETFLOW: can't parse destination to sockaddr\n");
    }

    pthread_mutex_lock(&sock_lock);
    /* don't need duplicated sockets */
	for (sk  =  container_of((&sock_list)->next ,  typeof(*sk), list);
		&sk->list != &sock_list;
		sk  =  container_of(sk->list.next ,  typeof(*sk), list))
    {
        if (sockaddr_cmp_ip4((struct sockaddr *)&sk->addr,(struct sockaddr *)&sin))
        {
            pthread_mutex_unlock(&sock_lock);
            list_del(&sk->list);
            close_n_free_nf_socket(sk);
            break;
        }
    }

#ifdef SECMON_DEBUG_LOG
    int i = 0;
	for (sk  =  container_of((&sock_list)->next ,  typeof(*sk), list);
		&sk->list != &sock_list;
		sk  =  container_of(sk->list.next ,  typeof(*sk), list))
    {
        SECMON_DEBUG("Destination %d: %s \n",i++,cnvrt_sockaddr_to_array(&sk->addr));
    }
    SECMON_DEBUG("temp i value =%d\n",i);
#endif
    pthread_mutex_unlock(&sock_lock);


}

/**
 *  This function is used to add the particular netflow destination in the
 *  configured destination list when add destination request is received from
 *  GUI.  For Addition-
 *     - It opens the socket towards the destination to be added.
 *     -  add the node at tail in the destination list
 *  @param ptr
 *      ip address of the destination to be added
 *  @param port
 *      UDP port number of the destination to be added
 *  @returns
 *      0 on success Error otherwise
 *
 */
int add_netflow_destination(char *ptr ,  uint32_t port)
{
    struct sockaddr_in sin;
    struct netflow_socket *sock;
    int succ  =  0;

    memset(&sin ,  0 ,  sizeof(sin));

    sin.sin_family  =  AF_INET;
    sin.sin_port  =  htons(port);
    succ  =  inet_pton(sin.sin_family , ptr ,  &sin.sin_addr);

    if (!succ)
    {
        SECMON_CRITICAL("ERROR: NETFLOW: can't parse destination\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
    else
    {
        SECMON_DEBUG("NETFLOW: Adding destination with %s",cnvrt_sockaddr_to_array(&sin));
    }
    if (!(sock  =  (struct netflow_socket *)malloc(sizeof(struct netflow_socket)))) {
        SECMON_CRITICAL("ERROR: NETFLOW: can't malloc socket\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
        return -ENOMEM;
    }

    memset(sock ,  0 ,  sizeof(struct netflow_socket));

    sock->addr  =  sin;
    add_nf_socket(sock);
    return SUCCESS;
}

/**
 *  config function called in starting
 *  @returns
 *				0  for success
 *
 */
int config()
{
    SECMON_DEBUG("Entering config function\n");
    SECMON_DEBUG("Exiting config function\n");
    return SUCCESS;
}


/* Socket Code Close*/
/**************************************************************************************
  SOCKET CODE ENDS
 ***************************************************************************************/


/**
 *  This is the configuration function used receive and configure the following netflow
 *  parameters-
 *    pdu_active_timeout , pdu_inactive_timeout ,  refresh_rate ,  pdu_timeout_rate ,  maximum_flows
 *    For details of the parameters ,  pl refer to RFC 3954.
 *  @param a_to
 *      flow pdu_active_timeout in seconds
 * @param i_to
 *      flow pdu_inactive_timeout in seconds
 * @param r_rate
 *      template refresh rate ,  this is number of packets.
 * @param t_rate
 *      template refresh time_out rate.
 * @param max_flows
 *      maximum number of flow that can be created at any point of time
 *      in netflow context.
 *  @returns
 *      0 on success
 */
int netflow_config(int a_to ,  int i_to ,  unsigned int r_rate ,  unsigned int t_rate ,  unsigned int max_flows)
{
    pdu_active_timeout  =  a_to;
    pdu_inactive_timeout  =  i_to;
    refresh_rate  =  r_rate;
    pdu_timeout_rate  =  t_rate;
    nf_max_pkt_flows  =  max_flows;
    return SUCCESS;
}

/**
 *  This is the configuration function used receive and configure  flexible netflow
 *  configuration parameters-
 *    Match and Collect Fields
 *
 *  @param match
 *      integer representing the bitmask for match fields ,  here each bit corresponds
 *      to one match fields ,  If 1 then that field is consider as flow record key
 *      field.
 * @param collect
 *       integer representing the bitmask for collect fields ,  here each bit corresponds
 *      to one collect field ,  If 1 then that field is consider as flow record non-key
 *      field.
 *  @returns
 *      0 on success
 */
int add_netflow_monitor_params(int match ,  int collect)
{
    if((match==1) && (collect ==0))
    {
        fnf = 0;
    }
    else
    {
        fnf = 1;
        match_fields  =  match;
        collect_fields  =  collect;
        create_fnf_templ_mask();
    }
    return SUCCESS;
}


/**
 * function to de initialize netflow and exit
 * @returns void
 *
 */
void  deinit(void *arg)
{
    SECMON_DEBUG("Entering deinit function\n");
    netflow_exit(arg);
    SECMON_DEBUG("Exiting deinit function\n");
}


/**
 *  This is the configuration function used delete the flexible netflow configuration
 *  parameters-
 *    Match and Collect Fields
 *  Traditional Netlfow shall continue to work once flexible netflow conf params are
 *  deleted.
 *	@returns void
 *
 */
void delete_netflow_monitor_params(void)
{
    fnf  = 0;
    match_fields  =  0xffffffff;
    collect_fields  =  0xffffffff;
}


/** \brief  Function to compute flexible flowset template
 *           and flowset template
 *
 * \param   const unsigned int
 *           template mask
 * \return
 *           pointer to allocated data template which get generated based on the
 *          input tmask
 */
static struct data_template *get_flowtemplate(const unsigned int tmask)
{
    struct base_template *tlist[BASE_TEMPL_MAX];
    struct data_template *tpl;
    int tnum;
    int length;
    int i ,  j ,  k;
    struct hlist_node *pos;
    int hash  =  0;

	for (pos  =  (&templates_hash_list[hash])->first; 
		pos && (tpl  =  container_of(pos ,  typeof(*tpl), hlist)); 
        pos  =  pos->next)
        if (tpl->tpl_key == tmask)
            return tpl;

    tnum  =  0;

    if(fnf)
    {
        SECMON_DEBUG("FNF enabled ,  calling get_flexible_flowtemplate...\n");
        if (tmask & BASE_TEMPL_OPTION)
        {
         if (OPTION_TEMPL_STAT == tmask)
          tlist[tnum++]  =  &template_v9;
        }
        else
        {
            if (tmask & FNF_BASE_TEMPL_IP_SRC_ADDR)
            {
                tlist[tnum++]  =  &bt_src_addr;
            }
            if (tmask & FNF_BASE_TEMPL_IP_DEST_ADDR)
            {
                tlist[tnum++]  =  &bt_dst_addr;
            }
            if (tmask & FNF_BASE_TEMPL_IP_TOS)
            {
                tlist[tnum++]  =  &bt_tos;
            }
            if (tmask & FNF_BASE_TEMPL_IP_PROTOCOL)
            {
                tlist[tnum++]  =  &bt_proto;
            }
            if (tmask & FNF_BASE_TEMPL_IP_SRC_PORT)
            {
                tlist[tnum++]  =  &bt_src_port;
            }
            if (tmask & FNF_BASE_TEMPL_IP_DEST_PORT)
            {
                tlist[tnum++]  =  &bt_dst_port;
            }
            if (tmask & FNF_BASE_TEMPL_INPUT_INTF)
            {
                tlist[tnum++]  =  &bt_input_intf;
            }
			
            if(tmask & FNF_BASE_TEMPL_VLAN)
            {
                tlist[tnum++]  =  &bt_vlan;
            }
            if (tmask & FNF_BASE_TEMPL_TCP_FLAGS)
            {
                tlist[tnum++]  =  &bt_tcp_flags;
            }
			
            if (tmask & FNF_BASE_TEMPL_COUNTER)
            {
                tlist[tnum++]  =  &bt_counter;
            }
            if (tmask & FNF_BASE_TEMPL_TIMESTAMP)
            {
                tlist[tnum++]  =  &bt_timestamp;
            }
        } /* !BASE_TEMPL_OPTION */

    }
    /* non flexible flowset template */
    else
    {
        if (tmask & BASE_TEMPL_OPTION)
        {
         if (OPTION_TEMPL_STAT == tmask)
          tlist[tnum++]  =  &template_v9;
        }
        else
        {
            if (tmask & BASE_TEMPL_IP4) {
                tlist[tnum++]  =  &template_ipv4;
                if (tmask & BASE_TEMPL_MASK4)
                    tlist[tnum++]  =  &template_ipv4_mask;
                if (tmask & BASE_TEMPL_ICMPX4)
                    tlist[tnum++]  =  &template_icmp_ipv4;
            }

            if (tmask & BASE_TEMPL_PORTS)
                tlist[tnum++]  =  &template_ports;
            else if (tmask & BASE_TEMPL_ICMP9)
                tlist[tnum++]  =  &template_icmp_v9;
            if (tmask & BASE_TEMPL_BASE9)
                tlist[tnum++]  =  &template_base_9;
            if (tmask & BASE_TEMPL_IGMP)
                tlist[tnum++]  =  &template_igmp;

            if (tmask & BASE_TEMPL_VLAN9)
                tlist[tnum++]  =  &template_vlan_v9;
				
    #ifdef ENABLE_DIRECTION
            if (tmask & BASE_TEMPL_DIRECTION)
                tlist[tnum++]  =  &template_direction;
    #endif
        } /* !BASE_TEMPL_OPTION */

    }

    length  =  0;
    for (i  =  0; i < tnum; i++) {
        length += tlist[i]->size;
    }
    /* elements are [type ,  len] pairs + one terminator */
    tpl  =  (struct data_template *) malloc(sizeof(struct data_template) + (length * 2 + 1) * sizeof(uint16_t));

    if (!tpl) {
        SECMON_DEBUG("NETFLOW: unable to kmalloc template (%#x).\n", tmask);
        return NULL;
    }
    tpl->tpl_key  =  tmask;
    tpl->options  =  (tmask & BASE_TEMPL_OPTION) != 0;
    if (tpl->options)
        tpl->tpl_size  =  sizeof(struct flowset_opt_tpl_v9); /* ipfix is of the same size */
    else
        tpl->tpl_size  =  sizeof(struct flowset_template);
    tpl->size  =  length;
    tpl->rec_size  =  0;
    tpl->template_id_n  =  htons(template_ids++);
    tpl->exported_cnt  =  0;
    tpl->exported_ts  =  0;

    /* construct resulting data_template and fill lengths */
    j  =  0;
    if (tpl->options) 
    {
  	tpl->fields[0] = SCOPE_SYSTEM;
  	tpl->fields[1] = 4;
  	j = 2;
  	tpl->rec_size += 4;
  	tpl->tpl_size += 4;
  	tpl->size += 1;
    }
    for (i  =  0; i < tnum; i++) {
        struct base_template *btpl  =  tlist[i];

        for (k  =  0; k < btpl->size; k++) {
            SECMON_DEBUG("type  =  btpl->type[k]%d\n",btpl->types[k]);
            int size;
            int type  =  btpl->types[k];

            tpl->fields[j++]  =  type;
            size  =  tpl_element_sizes[type];
            SECMON_DEBUG("size  =  %d\n",tpl_element_sizes[type]);
            tpl->fields[j++]  =  size;
            tpl->rec_size += size;
            SECMON_DEBUG("tpl_recsize  =  %d\n",tpl->rec_size);
        }
        tpl->tpl_size += btpl->size * TPL_FIELD_NSIZE;
    }
    SECMON_DEBUG("in get_flowtemplate ,  tpl->tp_size=%d tpl->rec_size  =  %d\n",tpl->tpl_size ,  tpl->rec_size);
    tpl->fields[j++]  =  0;

	HLIST_ADD_HEAD(&tpl->hlist, &templates_hash_list[hash]);
    templates_count++;

    return tpl;
}


/**
 *  This is the inline function for finding whether the currently created
 *  netflow pdu have space for 'size' bytes.
 *
 *  @param size
 *      number of bytes to check whether pdu have this much of free space
 *      available.
 *  @return
 *      0 - if netflow pdu does not have 'size' bytes free
 *      1 - otherwise
 */
static inline int check_pdu_have_space(const size_t size , struct collector_pdu *coll_pdu)
{
    return ((coll_pdu->pdu_data_used + size) <= coll_pdu->pdu_high_wm);
}

/**
 *  This is the inline function for move the 'size' bytest in the currently
 *  allocated netflow pdu ,  and move the pdu_data_used pointer to size bytes
 *
 *  @param size
 *      number of bytes to move pdu_data_used ptr
 *      available.
 *  @return
 *      pointer at which the next flow set need to be added in the current
 *      pdu.
 */
static inline unsigned char *pdu_grab_space(const size_t size , struct collector_pdu *coll_pdu)
{
    unsigned char *ptr  =  coll_pdu->pdu_data_used;
    coll_pdu->pdu_data_used += size;
    return ptr;
}

/**
 *  This is the inline function to allocate data space in pdu ,
 *  or export (reallocate) and fail.
 *  @param size
 *      number of bytes to allocate data space in the pdu
 *
 *  @return
 *      pointer at which the next flow set need to be added in the current
 *      pdu.
 */
static inline unsigned char *pdu_alloc_fail_export(const size_t size , struct collector_pdu *coll_pdu)
{
    if ( (!check_pdu_have_space(size , coll_pdu)))
    {
        fill_dtls_n_export_pdu(coll_pdu);
        return NULL;
    }
    return pdu_grab_space(size , coll_pdu);
}



/**
 *  This function is used to allocate data space in pdu ,
 *  doesn't fail ,  but can provide empty pdu.
 *  @param size
 *      number of bytes to allocate data space in the pdu
 *
 *  @return
 *      pointer at which the next flow set need to be added in the current
 *      pdu.
 */
static unsigned char *alloc_space_in_pdu(const size_t size , struct collector_pdu *coll_pdu)
{
    return pdu_alloc_fail_export(size , coll_pdu) ? : pdu_grab_space(size , coll_pdu);
}

/**
 *  This inline function is used to move the pdu_data_used ptr
 *  to backward for 'size' bytes.
 *
 *  @param size
 *      number of bytes to move pdu_data_space ptr back ,  so that the 'size'
 *      bytest can be used again for next template.
 *	@returns void
 *
 */
static inline void remove_space_from_pdu(const size_t size , struct collector_pdu *coll_pdu)
{
    coll_pdu->pdu_data_used -= size;
}


/**
 *  This function is used to add template of any type and version 9.
 *   Based on the template mask data_template get created which is filled
 *   here with actual field code values define  in RFC 3984.
 *
 *   @param tpl
 *      pointer to allocated data_template
 *	 @returns void
 *
 */

static void add_template_to_pdu(struct data_template *tpl , struct collector_pdu *coll_pdu)
{
    uint8_t *ptr;
    struct flowset_template *ntpl;
    uint16_t *sptr;
    uint16_t *fields;
    size_t added_size  =  0;
    
	/* check if enough space for option template with flowset header */
    if (tpl->options)
        added_size  =  sizeof(struct flowset_data) + tpl->rec_size;

    ptr  =  alloc_space_in_pdu(tpl->tpl_size + added_size , coll_pdu);
    remove_space_from_pdu(added_size , coll_pdu);
    ntpl  =  (void *)ptr;
    if(ntpl==NULL)
    {
        SECMON_DEBUG("ntpl is null\n");
    }

    if (tpl->options)
        ntpl->flowset_id  = htons(FLOWSET_OPTIONS);
    else
    {
        fflush(stdout);
        ntpl->flowset_id  = htons(FLOWSET_TEMPLATE);
    }
    ntpl->size	   =  htons(tpl->tpl_size);
    ntpl->template_id  =  tpl->template_id_n;

    if (tpl->options)
    {
			/* template should have scope as first field */
            struct flowset_opt_tpl_v9 *otpl  =  (void *)ptr;

            otpl->scope_len    =  htons(TPL_FIELD_NSIZE);
            otpl->opt_len      =  htons((tpl->size - 1) * TPL_FIELD_NSIZE);

            ptr += sizeof(struct flowset_opt_tpl_v9);

    } else {

        ntpl->field_count  =  htons(tpl->size);
        ptr += sizeof(struct flowset_template);
    }

    sptr  =  (uint16_t *)ptr;
    fields  =  tpl->fields;
    if (tpl->options)
    {
        *sptr   =  htons(*fields++);
        sptr++;
        *sptr  =  htons(*fields);
        sptr++; fields++;
    }
    for (;;)
    {

        const int type  =  *fields++;
        if (!type)
        {
            break;
        }
        *sptr  =  htons(type);
        sptr++;
        *sptr  =  htons (*fields++);
        sptr++;
    }

    tpl->exported_cnt  =  coll_pdu->pdu_count;
    tpl->exported_ts  =  get_currentTime();

    coll_pdu->pdu_flowset  =  NULL;
    coll_pdu->pdu_tpl_records++;
}

/* return buffer where to write records data
 * @returns void
 *
 */
static unsigned char *add_tpl_alloc_rcrd_space(struct data_template *tpl , struct collector_pdu *coll_pdu)
{
    unsigned char *ptr = NULL;

	/* check if space available in pdu, if available we add in same record otherwise we need to reallocate */
    /*ptr is tell where to store in pdu*/
    if (!coll_pdu->pdu_flowset ||
            (coll_pdu->pdu_flowset)->flowset_id != tpl->template_id_n ||
            !(ptr  =  pdu_alloc_fail_export(tpl->rec_size , coll_pdu)))
    {
        /* add 4 bytes of padding if previous data template present */
        if (coll_pdu->pdu_flowset)
        {
            int padding  =  (PAD_SIZE - ntohs(coll_pdu->pdu_flowset->size) % PAD_SIZE) % PAD_SIZE;
            if (padding && (ptr  =  pdu_alloc_fail_export(padding , coll_pdu))) {
                coll_pdu->pdu_flowset->size  =  htons(ntohs(coll_pdu->pdu_flowset->size) + padding);
                for (; padding; padding--)
                    *ptr++  =  0;
            }
        }

        if (!tpl->exported_ts ||
                coll_pdu->pdu_count > (tpl->exported_cnt + refresh_rate)  || !(time_is_before(tpl->exported_ts + timeout_rate_j())))
        {
            add_template_to_pdu(tpl , coll_pdu);
        }

        fflush(stdout);

        ptr  =  alloc_space_in_pdu(sizeof(struct flowset_data) + tpl->rec_size , coll_pdu);

        coll_pdu->pdu_flowset		 =  (struct flowset_data *)ptr;
        coll_pdu->pdu_flowset->flowset_id  =  tpl->template_id_n;
        coll_pdu->pdu_flowset->size	 =  htons(sizeof(struct flowset_data));
        ptr += sizeof(struct flowset_data);
    }
    return ptr;
}


/**
 *  This function is the outer function to allocate template and data
 *  template which inturn calls get_flowtemplate and add_tpl_alloc_rcrd_space api.
 *  @param t_key
 *      bitmask con
 *
 *  @return
 *      pointer at which the next flow set need to be added in the current
 *      pdu.
 */
static unsigned char *get_n_add_template_to_pdu(const unsigned int t_key ,  struct data_template **ptpl , struct collector_pdu *coll_pdu)
{
    struct data_template *tpl;

    tpl  =  get_flowtemplate(t_key);
    if ( (!tpl)) {
        SECMON_DEBUG("NETFLOW: template %#x allocation failed.\n", t_key);
        INC_NETFLOW_STAT(alloc_err);
        return NULL;
    }
    *ptpl  =  tpl;
    return add_tpl_alloc_rcrd_space(tpl , coll_pdu);
}

/**
 *  To free the allocated netflow instance once that flow is exported.
 *
 *  @param nf
 *      pointer to the netflow instance.
 */
static void free_netflow_tuple(struct netflow_flow *nf)
{
    if(!nf)
    {
        return;
    }
    if (IS_DUMMY_FLOW(nf))
        return;
    --netflow_count;
    free(nf);
}

/**
 *  This function is encode one field (data records only) based on the
 *  generated tpl mask.
 *  @param ptr
 *      ptr to which the data records is be filed from nf. This is the position
 *      in the current netflow pdu's  'pdu_data_used' location.
 *  @param type
 *      fields type whose value need to be filled from incoming nf.
 *  @param nf
 *     actual netflow record which is getting exported
 */


static inline void fill_tpl_filed_acc_tuple(uint8_t *ptr ,  const int type ,  const struct netflow_flow *nf)
{
    uint32_t nrbytes  = 0;
    uint32_t nrpackets = 0;
    unsigned long nftsfirst  =  0;
    unsigned long nftslast  =  0;


    if(!nf)
    {
        return;
    }

    switch (type)
    {
        case IN_BYTES:
            nrbytes  =  htonl(nf->nr_bytes);
            memcpy(ptr,&nrbytes ,  sizeof(nf->nr_bytes));
            break;
        case IN_PKTS:
            nrpackets  =  htonl(nf->nr_packets);
            memcpy(ptr,&nrpackets ,  sizeof(nf->nr_packets));
            break;
        case FIRST_SWITCHED:
            nftsfirst  =  htonl(nf->nf_ts_first);
            memcpy(ptr,&nftsfirst , sizeof(nf->nf_ts_first));
            break;
        case LAST_SWITCHED:
            nftslast  =  htonl(nf->nf_ts_last);
            memcpy(ptr,&nftslast , sizeof(nf->nf_ts_last));
            break;
        case IPV4_SRC_ADDR:  memcpy((uint32_t *)ptr,&nf->tuple.src ,  sizeof(nf->tuple.src)); break;
        case IPV4_DST_ADDR:  memcpy((uint32_t *)ptr,&nf->tuple.dst ,  sizeof(nf->tuple.dst)); break;
        case IPV4_NEXT_HOP:  memcpy((uint32_t *)ptr,&nf->nh ,  sizeof(nf->nh)); break;
        case L4_SRC_PORT:    memcpy((uint16_t *) ptr ,  &nf->tuple.s_port ,  sizeof(nf->tuple.s_port)); break;
        case L4_DST_PORT:    memcpy((uint16_t *) ptr ,  &nf->tuple.d_port ,  sizeof(nf->tuple.d_port)); break;
        case INPUT_SNMP:     memcpy(ptr,&nf->tuple.i_ifc ,  sizeof(nf->tuple.i_ifc)); break;
        case OUTPUT_SNMP:    memcpy(ptr,&nf->o_ifc  ,  sizeof(nf->o_ifc)); break;

#define EXTRACT_VLAN_PRIO(tag) ((ntohs(tag) & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT)

        case SRC_VLAN:
        case sourceMacAddress:	    memcpy(ptr ,  &nf->tuple.h_src ,  ETH_ADDR_LEN); break;

#ifdef ENABLE_DIRECTION
        case DIRECTION:		       *ptr  =  hook2dir(nf->hooknumx - 1); break;
#endif
        case PROTOCOL:	               *ptr  =  nf->tuple.protocol; break;
        case TCP_FLAGS:	               *ptr  =  nf->tcp_flags; break;
        case TOS:	               *ptr  =  nf->tuple.tos; break;
        case SRC_MASK:	               *ptr  =  nf->s_mask; break;
        case DST_MASK:	               *ptr  =  nf->d_mask; break;
        case icmpTypeCodeIPv4:	/*FALLTHROUGH*/
        case MUL_IGMP_TYPE:            *ptr  =  nf->tuple.d_port; break;
        default:
                                       SECMON_DEBUG("NETFLOW:Warning!! Unknown Element id %d\n", type);
                                       memset(ptr ,  0 ,  tpl_element_sizes[type]);
    }
}


/**
 *  check if ether address is 0 if at least one value is non-zero
 *	returns 0 otherwise 1
 *	@returns
 *			1			if ether address is 0
 *			0			otherwise
 *
 */
static inline int is_zero_ether_addr(const struct hw_addr *ea)
{
    int i;
    for (i  =  0; i < ETHER_ADDR_LEN; i++)
        if (ea->addr[i] != 0x00)
            return SUCCESS;
    return FAILURE;
}

/**
 *  Flexible netflow template generation function.
 *
 *  @param nf
 *      pointer to the netflow node which need to be exported ,  template_mask
 *      is generated based values in the nf instance
 *  @returns void
 *
 */
static void create_n_fill_pdu(struct netflow_flow *nf)
{
    struct Collector_object *collectorobj_list,*temp;
    unsigned char *ptr;
    struct data_template *tpl;
    unsigned int tpl_mask;
    struct collector_pdu *curr_pdu;
    int i;

    SECMON_DEBUG("NETFLOW: %s called ", __func__);
    if (NULL == nf || NULL == netflow_rule_hash_table[nf->collector_hash])
    {
        return;
    }

    collectorobj_list =(netflow_rule_hash_table[nf->collector_hash])->collectors;
    if(fnf)
      tpl_mask = TEMPLATE_FNF_MASK;
    else
      {
        tpl_mask = create_nf_templ_mask(nf);
      }

      temp = collectorobj_list;
      while(temp!=NULL)
      {
          /*allocation according to collector id*/
          curr_pdu = find_pdu_by_collector(temp->server_address);

        if(curr_pdu==NULL)
        {
            return;
        }

        /*ptr contains pdu*/
        ptr  =  get_n_add_template_to_pdu(tpl_mask ,  &tpl , curr_pdu);
        if ( (!ptr))
        {
            ADD_NETFLOW_STAT(pkt_lost ,  nf->nr_packets);
            ADD_NETFLOW_STAT(traf_lost ,  nf->nr_bytes);
            INC_NETFLOW_STAT(flow_lost);
            TS_NETFLOW_STAT(lost);
            free_netflow_tuple(nf);
            return;
        }

        /* encode all fields */
        for (i  =  0; ; )
        {
            int type  =  tpl->fields[i++];
            if (!type)
                break;
            fill_tpl_filed_acc_tuple(ptr ,  type ,  nf);
            ptr += tpl->fields[i++];
        }

        curr_pdu->pdu_data_records++;
        curr_pdu->pdu_flow_records++;
        curr_pdu->pdu_flowset->size  =  htons(ntohs(curr_pdu->pdu_flowset->size) + tpl->rec_size);

        curr_pdu->pdu_packets += nf->nr_packets;
        curr_pdu->pdu_traf    += nf->nr_bytes;
        curr_pdu->pdu_ts_mod  =  get_currentTime();

        temp = temp->next;
    }

    free_netflow_tuple(nf);
}


/**
 *  The outer function which is creating and exporting netflow pdu.
 *  Pdu is initially blank ,  export current pdu ,  and prepare next for filling.
 *  It fills the basic Netlfow V9 header and mark the pdu_data_used pointer
 *  at the start of the pdu. 'pdu_data_used' pointer shall then be moved/updated
 *  as and when templates and data_templates are filled in this pdu.
 *  @returns
 *
 */
static void fill_dtls_n_export_pdu(struct collector_pdu *coll_pdu)
{
    struct timeval tv;
    int pdusize;

    SECMON_DEBUG("NETFLOW: %s called ", __func__);
    if (coll_pdu->pdu_data_used <= coll_pdu->pdu.v9.data)
    {
        return;
    }

    coll_pdu->pdu.v9.version		 =  htons(9);
    coll_pdu->pdu.v9.nr_records	 =  htons(coll_pdu->pdu_data_records + coll_pdu->pdu_tpl_records);
    coll_pdu->pdu.v9.sys_uptime_ms	 =   htonl(get_currentTime());

    gettimeofday(&tv , NULL);
    coll_pdu->pdu.v9.export_time_s	 =   htonl(tv.tv_sec);
    coll_pdu->pdu.v9.seq		 =  htonl(coll_pdu->pdu_seq);
    coll_pdu->pdu.v9.source_id	 =  engine_id;

    pdusize  =  coll_pdu->pdu_data_used - (unsigned char *)&(coll_pdu->pdu.v9);
    send_netflow_pdus_to_tools(&(coll_pdu->pdu.v9), pdusize , coll_pdu);

    coll_pdu->pdu_packets  =  0;
    coll_pdu->pdu_traf     =  0;

    coll_pdu->pdu_seq++;
    coll_pdu->pdu_count++;
    coll_pdu->pdu_flow_records  =  coll_pdu->pdu_data_records  =  coll_pdu->pdu_tpl_records  =  0;
    coll_pdu->pdu_data_used  =  coll_pdu->pdu.v9.data;
    coll_pdu->pdu_flowset  =  NULL;
}

/**
 *  Function to free the allocate template from the exported the template list
 *  @returns
 *
 */
static void free_templates(void)
{

    int i;
    struct hlist_node *tmp;
    struct hlist_node *pos;
    struct collector_pdu *temp;

    for (i  =  0; i < TEMPLATES_HASH_SIZE; i++)
    {
        struct hlist_head *thead  =  &templates_hash_list[i];
        struct data_template *tpl;

		for (pos  =  (thead)->first;
            pos && 
			(tmp  =  pos->next) &&
            (tpl  =  container_of(pos ,  typeof(*tpl), hlist));
            pos  =  tmp)
            free(tpl);
        INIT_HLIST_HEAD(thead);
    }
    templates_count  =  0;

    /* reinitialize template timeouts */
    temp = pdu_list;
    while(temp!=NULL)
    {
        temp->ts_sysinf_last  =  temp->ts_stat_last  =  0;
        temp = temp->next;
    }
}

/**
 *  To switch the netflow supporting protocol. As of now only V9 is supported.
 *  @param ver
 *        the netflow version to switch
 *  @returns
 *
 */
/**
 * Extract all L2 header data ,  Parse eth header , then vlans.
 * Data is extracted based on the DPDK provided APIs.
 *  @param mbuf
 *      pointer the received DPDK mbuf packet
 *  @param tuple
 *       netflow_tuple instance where the extracted L2 header values
 *       are stored.
 *  @returns
 *
 */
static void parse_l2_header(char *mbuf ,  struct netflow_tuple *tuple)
{


#define ENABLE_L2
    struct ether_header *eth_hdr;
    eth_hdr  =  (struct ether_header *)mbuf;

    int tag_num  =  0;
    struct vlan_header *vlan_hdr;

    if(match_fields & MATCH_VLAN_MASK)
    {
        if (ETHER_TYPE_VLAN == htons(eth_hdr->ether_type))
        {
            vlan_hdr  =  (struct vlan_header *)(eth_hdr + 1);
            tuple->tag[tag_num++]  =  vlan_hdr->vlan_tci;
        }
    }




    if(match_fields & MATCH_MAC_MASK)
    {
        tuple->h_dst[0]  =  eth_hdr->dst_mac.addr[0];
        tuple->h_dst[1]  =  eth_hdr->dst_mac.addr[1];
        tuple->h_dst[2]  =  eth_hdr->dst_mac.addr[2];
        tuple->h_dst[3]  =  eth_hdr->dst_mac.addr[3];
        tuple->h_dst[4]  =  eth_hdr->dst_mac.addr[4];
        tuple->h_dst[5]  =  eth_hdr->dst_mac.addr[5];

        tuple->h_src[0]  =  eth_hdr->src_mac.addr[0];
        tuple->h_src[1]  =  eth_hdr->src_mac.addr[1];
        tuple->h_src[2]  =  eth_hdr->src_mac.addr[2];
        tuple->h_src[3]  =  eth_hdr->src_mac.addr[3];
        tuple->h_src[4]  =  eth_hdr->src_mac.addr[4];
        tuple->h_src[5]  =  eth_hdr->src_mac.addr[5];
    }

}

/**
 * To allocate netflow_flow instance for the received packet if this is
 * the new data flow and its flow records is not created earlier..
 *
 *  @param tuple
 *      pointer to the unique netflow_tuple for which netflow_flow need
 *      to be allocated.
 *  @return
 *       allocated netflow_flow instance.
 */
static struct netflow_flow *
create_netflow_tuple(const struct netflow_tuple *tuple)
{
    struct netflow_flow *nf;

    nf  =  (struct netflow_flow *)malloc(sizeof(struct netflow_flow));
    if (!nf) {
        SECMON_DEBUG("NETFLOW: Can't allocate flow.\n");
        return NULL;
    }

    memset(nf ,  0 ,  sizeof(*nf));
    nf->tuple  =  *tuple;

    ++netflow_count;

    return nf;
}

/**
 * Function used to find whether the flow records for incomming packet
 * is already existing. It iterate the hash list and check based on the
 * netflow_tuple (unique key values)
 *
 *  @param tuple
 *      pointer to the unique netflow_tuple for which netflow_flow need
 *      to be find.
 *  @param hash
 *     calculated murmur3 hash for tuple.
 *  @return
 *       the pointer to the found netflow_flow record.
 */
static struct netflow_flow *
check_nf_tuple_exists(const struct netflow_tuple *tuple ,  const unsigned int hash)
{

    struct netflow_flow *nf;
    struct hlist_node *pos;
    int ret=-1;

	for (pos  =  (&nf_tuple_hash_table[hash])->first; 
		pos && (nf  =  container_of(pos ,  typeof(*nf), hlist)); 
        pos  =  pos->next)
    {
        ret =   netflow_tuple_equal(tuple,&nf->tuple);
        if(ret && nf->nr_bytes < FLOW_FULL_WATERMARK)
        {
            INC_NETFLOW_STAT(found);
            return nf;
        }
        INC_NETFLOW_STAT(searched);
    }
    INC_NETFLOW_STAT(notfound);
    return NULL;
}

/**
 *  Check whether the input nf (flow record) is active for pdu_active_timeout
 *  and need to be exported.
 *
 *  @param nf
 *      pointer to the netflow_flow flow record .
 *  @param a_timeout
 *      active timeout.
 *  @param j
 *     current system time
 *
 *  @return
 *       1 if flow record need to be exported
 *       0 otherwise
 */
inline int export_active(const struct netflow_flow *nf ,  const unsigned long a_timeout ,
        const unsigned long j)
{
    return ((j - nf->nf_ts_first) > a_timeout) ||
        nf->nr_bytes >= FLOW_FULL_WATERMARK;
}

/**
 *  Check whether the input nf (flow record) is inactive for pdu_inactive_timeout
 *  and need to be exported. This is called from need_export_rec() to check whether
 *  particular flow need to be exported.
 *  i_timeout == 0 is flush
 *
 *  @param nf
 *      pointer to the netflow_flow flow record .
 *  @param a_timeout
 *      inactive timeout.
 *  @param j
 *     current system time
 *
 *  @return
 *       positive number if flow record need to be exported
 *       0 otherwise
 */
inline int export_inactive(const struct netflow_flow *nf ,  const unsigned long i_timeout ,
        const unsigned long j)
{
    if ( (i_timeout))
    {
        if ( ((j - nf->nf_ts_last) > i_timeout))
        {
            if (nf->tuple.protocol == IPPROTO_TCP &&
                    (nf->tcp_flags & TCP_FIN_RST))
            {
                return 0x03; /* end of Flow detected */
            }
            else
            {
                return 0x01; /* idle timeout */
            }
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 0x04; /* forced end */
    }
}

/**
 *  Check whether the input nf (flow record) is need to be exported either
 *  active or inactive. This inturn calls export_active and inactive_needs
 *  export api.
 *
 *  @param nf
 *      pointer to the netflow_flow flow record .
 *  @param a_timeout
 *      active timeout.
 *  @param i_timeout
 *      pdu_inactive_timeout
 *  @param j
 *     current system time
 *
 *  @return
 *       1 if flow record need to be exported
 *       0 otherwise
 */
static inline int tuple_needs_export(struct netflow_flow *nf ,  const long i_timeout ,
        const long a_timeout ,  const unsigned long j)
{
    int reason  =  export_inactive(nf ,  i_timeout ,  j);
    if (!reason && export_active(nf ,  a_timeout ,  j))
    {
        reason  =  0x02; 
    }
    return (nf->flowEndReason  =  reason);
}


/**
 *  This is debugging function to print the dpdk received complete packet..
 *
 *  @param msg
 *      pointer to the mbuf packet
 *  @param len
 *      packet length
 *  @returns
 *
 */
void print_netflow_packet(char *msg ,  int len)
{
    /*for future to print packet*/
    /*
       int i = 0;
       struct ether_header *eth_hdr;
       struct ipv4_header *ipv4_header;
       SECMON_DEBUG("********************************************\n");

       SECMON_DEBUG("packet data len:%d\n",len);
       for(i  = 0;i<len;i++)
       {
       SECMON_DEBUG("%x ",msg[i]);
       }

       eth_hdr  =  (struct ether_header *)msg;
       ipv4_header  =  (struct ipv4_header *)(msg + sizeof(struct ether_header));

       SECMON_DEBUG("Extracted Packet Data:");
       SECMON_DEBUG("Ether Header: D_ADDR:%x:%x:%x:%x:%x:%x ",eth_hdr->dst_mac.addr[0],eth_hdr->dst_mac.addr[1],
       eth_hdr->dst_mac.addr[2],eth_hdr->dst_mac.addr[3],eth_hdr->dst_mac.addr[4],eth_hdr->dst_mac.addr[5]);

       SECMON_DEBUG("Ether Header ,  S_ADDR:%x:%x:%x:%x:%x:%x ",eth_hdr->src_mac.addr[0],eth_hdr->src_mac.addr[1],
       eth_hdr->src_mac.addr[2],eth_hdr->src_mac.addr[3],eth_hdr->src_mac.addr[4],eth_hdr->src_mac.addr[5]);
       SECMON_DEBUG("Ether Type:%x \n",eth_hdr->ether_type);
       SECMON_INFO("Ether Type:%x \n",eth_hdr->ether_type);

       SECMON_DEBUG("IP Header:");
       SECMON_DEBUG("IPv4 Header , version_ihl=%0x   , tos=%0x   , total_length=%0x   ,  packet_id=%0x   , fragment_offset=%0x   ,  ttl=%0x   ,  protocol=%0x   ,  chksum=%x   , src_add=%0x   , dst_add=%0x\n",ipv4_header->version_ihl , ipv4_header->type_of_service , ipv4_header->total_length , ipv4_header->packet_id , ipv4_header->fragment_offset , ipv4_header->time_to_live , ipv4_header->next_proto_id , ipv4_header->hdr_checksum , ipv4_header->src_addr , ipv4_header->dst_addr);

       SECMON_INFO("IPv4 Header , version_ihl=%0x   , tos=%0x   , total_length=%0x   ,  packet_id=%0x   , fragment_offset=%0x   ,  ttl=%0x   ,  protocol=%0x   ,  chksum=%x   , src_add=%0x   , dst_add=%0x\n",ipv4_header->version_ihl , ipv4_header->type_of_service , ipv4_header->total_length , ipv4_header->packet_id , ipv4_header->fragment_offset , ipv4_header->time_to_live , ipv4_header->next_proto_id , ipv4_header->hdr_checksum , ipv4_header->src_addr , ipv4_header->dst_addr);

       SECMON_DEBUG("********************************************\n");
     */
}


/**
 *  Debugging function to dump the current state of flow hash table.
 *  @returns
 *
 */
void dump_hashtable(void)
{
    long i = 0;
    struct netflow_flow *nf;
    struct hlist_node *pos;

    for(i = 0;i < 655360;i++)
    {
        if(!((&nf_tuple_hash_table[i])->first))
			for (pos  =  (&nf_tuple_hash_table[i])->first; 
				pos && (nf  =  container_of(pos ,  typeof(*nf), hlist)); 
				pos  =  pos->next)
            {
                SECMON_DEBUG("HASH KEY =  %ld\n",i);SECMON_DEBUG("\n");
                if(nf != NULL)
                {
                    SECMON_DEBUG("HASH KEY =  %ld\n",i);SECMON_DEBUG("\n");
                    SECMON_DEBUG("src_ip :%d.%d.%d.%d ,  ", nf->tuple.src.ip & 0xff000000 ,  nf->tuple.src.ip & 0x00ff0000 ,                                      nf->tuple.src.ip & 0x0000ff00 , nf->tuple.src.ip & 0x000000ff);fflush(stdout);
                    SECMON_DEBUG("src_ip :%d.%d.%d.%d ,  ", nf->tuple.src.ip & 0xff000000 ,  nf->tuple.src.ip & 0x00ff0000 ,                                      nf->tuple.src.ip & 0x0000ff00 , nf->tuple.src.ip & 0x000000ff);fflush(stdout);
                }
                else
                {
                    SECMON_DEBUG("No entry for hash key %ld ,  \n",i);fflush(stdout);
                }
            }
    }
}


/**
 *  convert the host to network byte order
 *  @param x
 *       value in host byte order
 *  @returns
 *			x 	contains value in network byte order
 *
 */
uint64_t htonll(uint64_t x)
{
    char *ptr  =  (char*)&x  ,  ch;
    int index  =  0;

    while(index < 4)
    {
        ch  =  ptr[index];
        ptr[index]  =  ptr[7 - index];
        ptr[7 - index]  =  ch;
        index++;
    }

    return x;
}

#define TCPHDR_MAXSIZE (4 * 15)


#define SetNBit(n) (0x8000 >> (n))

/** traverses the hash_table(cache) of the tuples
 * to check timer expiry. If any timer expires
 * for an entry ,  then action for that particular
 * tuple is changed to DROP.
 * @param arg
 *    argument to pass to thread.
 * @return
 *    void
 */
void *hash_timer(void *arg)
{
    unsigned int i;
    while(1)
    {
        sleep(SLEEP_TIME);
        for(i = 0; i<HASH_TABLE_SIZE; i++)
        {
          fwait(netflow_rule_futex);
            if(netflow_rule_hash_table[i] != NULL)
            {
                unsigned long present  =  get_currentTime();

                /* In this version the default timeout value for
                 * all hash entries is 3 minute.
                 */
                if(unlikely((present - netflow_rule_hash_table[i]->last_seen) > HASH_EXPIRY_TIME))
                {
                    SECMON_DEBUG("time expired for hash entry=%d of netflow plugin ,  removing it\n",i);
                    SECMON_DEBUG("acquiring lock\n");

                    remove_netflow_hash_entry(i);

                }
            }
          fpost(netflow_rule_futex);
        }
    }

}

/**
 *  remove hash entry from netflow_rule_hash_table
 *  @param i
 *        contains hash entry
 *  @returns void
 *
 */
void remove_netflow_hash_entry(unsigned int i)
{
    struct rule_hash *hash_entry = netflow_rule_hash_table[i];
    decrement_session(hash_entry->collectors);
    free(hash_entry);
    netflow_rule_hash_table[i]  =  NULL;
}

/**
 *  flush netflow_rule_hash_table and delete pdu list
 *  @returns void
 *
 */
void flush_netflow_hash_table()
{
    unsigned int i;

    SECMON_DEBUG("flushing all the entries in netflow_hash_table\n");
    for(i = 0;i<HASH_TABLE_SIZE;i++)
    {
        if(netflow_rule_hash_table[i]!= NULL)
            remove_netflow_hash_entry(i);
    }

    struct collector_pdu *collec_pdus = pdu_list;
    struct collector_pdu *temp = NULL;
    while (collec_pdus != NULL)
    {
        temp = collec_pdus->next;
        free(collec_pdus);
        collec_pdus = temp;
    }
    pdu_list = NULL;

    SECMON_DEBUG("Successfully flushed all the netflow hash entries\n");
}

/**
 *  This is the Packet Receiver and Parser function for DPDK
 *  mbuf.  It does the following-
 *    - extract and parse the mbuf for l2 l3 and l4 headers
 *   - create unique netflow_tuple and flow record
 *   - update/add the flow_record in Flow Hash table
 *   - check whether any of the flow records need to be exported.
 *  @param msg
 *      pointer to dpdk mbuf
 *  @param len
 *      packet len
 *  @param hash_code
 *      hash code of packet
 *	@returns void
 *
 */
static void parse_pkt_n_crt_nftuple(char *msg , int len, uint32_t hash_code)
{
    struct ether_header *eth_hdr;
    struct ipv4_header *ip_hdr;

    uint32_t hash;
    struct netflow_tuple tuple; //netflow tuple
    struct netflow_flow *nf;
    uint8_t tcp_flags  = 0;
    uint8_t s_mask  = 0;
    uint8_t d_mask  = 0;
    uint16_t fragment;
    uint32_t pkt_len;
    uint16_t etherType;

    int curr_len  =  0;
    int ip_hdr_len  =  0;
    int tcp_header_len  =  0;
    int options  =  0;
    int tcpoptions  =  0;
    struct netflow_entry *stripe;

    memset(&tuple ,  0 ,  sizeof(struct netflow_tuple));

    eth_hdr  =  (struct ether_header *) msg;
    etherType  =  ntohs(eth_hdr->ether_type);

    parse_l2_header(msg ,  &tuple);

    if(! (match_fields & MATCH_IPV4_MASK))
    {
        SECMON_DEBUG("Not matching IPV4 packets");
        return;
    }

    if(etherType == VLAN)
    {
        msg += 4;
        eth_hdr  =  (struct ether_header *) msg;
        etherType  =  ntohs(eth_hdr->ether_type);

    }

    if (IPV4_PACKET == etherType)
    {
        ip_hdr  =  (struct ipv4_header *) (msg + sizeof(struct ether_header ));

        tuple.l3proto  =  AF_INET;
        fragment	 =   (ip_hdr->fragment_offset & htons(IP_OFFSET));
        pkt_len		 =    ntohs(ip_hdr->total_length);
        if(match_fields & MATCH_SOURCE_ADDR_MASK)
        {
            tuple.src  =  (union nf_inet_addr)(ip_hdr->src_addr);
        }
        if(match_fields & MATCH_DEST_ADDR_MASK)
        {
            tuple.dst  =  (union nf_inet_addr)(ip_hdr->dst_addr);
        }
        if(match_fields & MATCH_TOS_MASK)
        {
            tuple.tos	 =  ip_hdr->type_of_service;
        }
        if(match_fields & MATCH_INPUT_INTF_MASK)
        {
            tuple.i_ifc	 =  0;
        }
        tuple.protocol	 =   ip_hdr->next_proto_id;
        //Parsing IP header options fields

        ip_hdr_len  =  (ip_hdr -> version_ihl & 0x0f) * 4;
        curr_len  =  sizeof(struct ether_header) +  ip_hdr_len;
    }
    else
    {
        SECMON_DEBUG("invalid packet\n");
        return;
    }

    if(match_fields & MATCH_PROTOCOL_MASK)
    {
        if (fragment) {
            INC_NETFLOW_STAT(frags);
        }
        else
        {
            switch (tuple.protocol)
            {
                case IPPROTO_TCP:
                    {
                        struct tcp_header *tcphdr;

                        if ((tcphdr  =  (struct tcp_header *)(msg + curr_len)))
                        {
                            if(match_fields & MATCH_SOURCE_PORT_MASK)
                            {
                                tuple.s_port  =  /*rte_be_to_cpu_16*/(tcphdr->src_port);
                            }
                            if(match_fields & MATCH_DEST_PORT_MASK)
                            {
                                tuple.d_port  =  /*rte_be_to_cpu_16*/(tcphdr->dst_port);
                            }

                            tcp_flags  =  tcphdr->tcp_flags;

                            tcp_header_len  =  ((tcphdr -> data_off) >> 4)*4;
/*                             tcpoptions  =   tcp_opts(tcphdr); */
                            curr_len += tcp_header_len;
                        }
                        break;
                    }
                case IPPROTO_UDP:
                case IPPROTO_UDPLITE:
                case IPPROTO_SCTP:
                    {
                        struct udp_header *udphdr;
                        if ((udphdr  =  (struct udp_header *)(msg + sizeof(struct ether_header) + sizeof(struct ipv4_header))))
                        {

                            if(match_fields & MATCH_SOURCE_PORT_MASK)
                                tuple.s_port  =   (udphdr->src_port);

                            if(match_fields & MATCH_DEST_PORT_MASK)
                                tuple.d_port  =  (udphdr->dst_port);
                        }
                        break;
                    }
                case IPPROTO_ICMP:
                    {
                        struct icmp_header *icmphdr;
                        if ((icmphdr  =  (struct icmp_header *)(msg + sizeof(struct ether_header) + sizeof(struct ipv4_header))))
                        {
                            if(match_fields & MATCH_DEST_PORT_MASK)
                            {
                                tuple.d_port  =  ntohs((icmphdr->icmp_type));
                            }
                        }
                        break;
                    }
                default:
                    {
                        return ;
                    }
            }
        } /* not fragmented */
    } /*end of MATCH_PROTOCOL_MASK */


    hash  =  find_hash_nf_tuple(&tuple);
    stripe  =  &nf_hash_table_stripes[hash & LOCK_CNT_MASK];
    pthread_spin_lock(&stripe->lock);

    nf  =  check_nf_tuple_exists(&tuple ,  hash);
    if (!nf)
    {
        if ((nf_max_pkt_flows > 0 && netflow_count >= nf_max_pkt_flows))
        {
            INC_NETFLOW_STAT(maxflows_err);
            INC_NETFLOW_STAT(pkt_drop);
            ADD_NETFLOW_STAT(traf_drop ,  pkt_len);
            TS_NETFLOW_STAT(drop);
            goto unlock_return;

        }

        nf  =  create_netflow_tuple(&tuple);
        if (!nf )
        {
            INC_NETFLOW_STAT(alloc_err);
            INC_NETFLOW_STAT(pkt_drop);
            ADD_NETFLOW_STAT(traf_drop ,  pkt_len);
            TS_NETFLOW_STAT(drop);
            goto unlock_return;
        }
        HLIST_ADD_HEAD(&nf->hlist ,  &nf_tuple_hash_table[hash]);
        nf->nf_ts_first  =  get_currentTime();
        nf->tcp_flags  =  tcp_flags;
        nf->s_mask  =  s_mask;
        nf->d_mask  =  d_mask;


        nf->ethernetType  =  (eth_hdr->ether_type);


        nf->options  =  0;
        nf->tcpoptions  =  0;
    }

    nf->collector_hash = hash_code;
    nf->nr_packets++;
    nf->nr_bytes += pkt_len;
    nf->nf_ts_last  =  get_currentTime();
    nf->tcp_flags |= tcp_flags;
    nf->options |= options;
    if (tuple.protocol == IPPROTO_TCP)
        nf->tcpoptions |= tcpoptions;
    INC_NETFLOW_STAT(pkt_total);
    ADD_NETFLOW_STAT(traf_total ,  pkt_len);


    if ((export_active(nf ,  pdu_active_timeout * HZ ,  get_currentTime())))
    {
        /* bubble it to the tail */
        if (!(&nf->list)->next)
            list_add_end(&nf->list ,  &stripe->list);
        else
            list_displace_tail(&nf->list ,  &stripe->list);
    }
    else
    {
        /* most recently accessed flows go to the head ,  old flows remain at the tail */
        if (!(&nf->list)->next)
        {
            list_add(&nf->list ,  &stripe->list);
        }
        else
        {
            list_move(&nf->list ,  &stripe->list);
        }
    }

unlock_return:
    pthread_spin_unlock(&stripe->lock);
}

/*if we are using dpdk ring, the implementation of receiving packets get changed*/
#ifdef USE_RING

/**
 *  receive packet from secmon agent and enqueue it in
 *  dpdk ring
 *  @param  m
 *      pointer to packet
 *  @returns void
 */
void receive_from_secmon(struct rte_mbuf *m)
{
    rte_ring_enqueue(r , m);
#ifdef SECMON_DEBUG_LOG
    netflow_numpkts_enqueued++;
    if(netflow_numpkts_enqueued==PKT_PRINT_DEBUG)
    {
        SECMON_DEBUG("%d packets received from secmon\n",PKT_PRINT_DEBUG);
        netflow_numpkts_enqueued = 0;
    }
#endif
}

/**
 *  Dequeue packet from dpdk ring and check if rule for these packets
 *  are defined to forward if yes than forward them otherwise drop them
 *  @param  args
 *      arguments passed from thread invocation
 *  @returns void
 */
void netflow_get_packets(void *args)
{
    int packet_len = 0;

    uint16_t rx_pkts = PKT_BURST;
    void *pkts[PKT_BURST]={NULL};
    struct rte_mbuf *m;
    int i;

    uint32_t hash_code;
    int retval=0;
    bool found  =  FALSE;
    struct Tuple *rule_tuple;   //rule tuple

    if(likely(r!=NULL))
    {
        while(1)
        {
            /* read from dpdk ring 0.
             * pointer to rte_mbuf packets are written to this ring
             * by main process whenever SecMon Agent calls the
             * receive_from_secmon API.
             */
            if(!rte_ring_dequeue_bulk(r , pkts , rx_pkts))
            {
#ifdef SECMON_DEBUG_LOG
                netflow_numpkts_dequeued += rx_pkts;
                if((netflow_numpkts_dequeued/PKT_PRINT_DEBUG) > 0)
                {
                    SECMON_DEBUG("%d packets dequeued from ring\n",PKT_PRINT_DEBUG);
                    netflow_numpkts_dequeued = 0;
                }
#endif
                for(i = 0; i< rx_pkts; i++)
                {
                    m  =  (struct rte_mbuf *)pkts[i];
                    char *pkt  =  (char *)rte_pktmbuf_mtod(m , char *);

                    packet_len  =  m->pkt_len;
                    if(likely(netflow_plugin_enabled == TRUE))
                    {
                        rule_tuple  =  (struct Tuple *)malloc(sizeof(struct Tuple));
                        memset(rule_tuple ,  0 ,  sizeof(struct Tuple));

                        retval  =  parse_packet(&pkt , packet_len , rule_tuple);
                        if(retval == PACKET_PARSE)
                        {
                            /*hash fo rule*/
                            hash_code  =  find_hash(rule_tuple);

                            fwait(netflow_rule_futex);

                            /*hash entry is already there*/
                            if(hash_entry_available(hash_code) == TRUE)
                            {
                                found = TRUE;
                                netflow_rule_hash_table[hash_code]->last_seen = get_currentTime();
                            }
                            else
                            {
                                /*add tools in hash table acc to hash_code*/
                                apply_filters(rule_tuple , hash_code,&found);
                            }

                            if(found == TRUE)
                            {
                                parse_pkt_n_crt_nftuple(pkt , packet_len, hash_code);
                            }

                            fpost(netflow_rule_futex);
                        }
                    }
                    /* free the indirect buffers */
                    rte_pktmbuf_free(pkts[i]);
                }
            }
        }
    }

}

/*if we are not using dpdk ring*/
#else
/*  Receive packet from secmon and check if match with
 *  any rule or not and process packet according to that
 *
 *  @param m
 *      contain packet from secmon
 *  @return void
 *
 */
void receive_from_secmon(struct rte_mbuf *m)
{
  if(likely(netflow_plugin_enabled == TRUE))
  {
    char *pkt  =  (char *)rte_pktmbuf_mtod(m , char *);
    int packet_len  =  m->pkt_len;

    struct Tuple rule_tuple;
    int retval  =  parse_packet(&pkt , packet_len , &rule_tuple);
    if(retval == PACKET_PARSE)
    {
      bool found  =  FALSE;
      /*hash fo rule*/
      uint32_t hash_code =  find_hash(&rule_tuple);

      fwait(netflow_rule_futex);

      /*hash entry is already there*/
      if(hash_entry_available(hash_code) == TRUE)
      {
        found = TRUE;
        netflow_rule_hash_table[hash_code]->last_seen = get_currentTime();
      }
      else
      {
        /*add tools in hash table acc to hash_code*/
        apply_filters(&rule_tuple , hash_code,&found);
      }

      if(found == TRUE)
      {
        parse_pkt_n_crt_nftuple(pkt , packet_len, hash_code);
      }

      fpost(netflow_rule_futex);
    }
    /*free(rule_tuple);*/
    /*rule_tuple = NULL;*/
  }
  /* free the indirect buffers */
  rte_pktmbuf_free(m);
}

/*end of dpdk ring ifdef preprocessor directive*/
#endif

/**
 *  Packet receiver function for Netflow feature. Once Netflow feature
 * is enabled it shall wait on the Netflow data message queue for data
 * packet. DPDK SecMon PacketReceiver thread shall write the data pacekts
 * to this message queue.
 * @returns
 *		0							if no error in creating thread
 *		error code		otherwise in creating thread
 *
 */
int receive_data()
{
    int ret;
    /* if we are using dpdk ring than we need one thread which will read packets from
     * dpdk ring
     */
#ifdef USE_RING
    ret  =  pthread_create(&netflow_get_packets_tid ,  NULL ,  (void *)netflow_get_packets ,  NULL);
    if(ret < 0 )
    {
        SECMON_DEBUG("pthread creation failed\n");
        return ret;
    }
#endif
    ret  =  pthread_create(&netflow_configurations_tid ,  NULL ,  (void *)configurations ,  NULL);
    if(ret < 0 )
    {
        SECMON_DEBUG("pthread creation failed\n");
        return ret;
    }

    ret  =  pthread_create(&hash_timer_tid ,  NULL ,  (void *)hash_timer ,  NULL);
    if(ret < 0 )
    {
        SECMON_CRITICAL("ERROR: pthread creation failed for hash_timer in netflow plugin\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
        return ret;
    }

    if (pthread_mutex_init(&netflow_hash_lock ,  NULL) != 0)
    {
        SECMON_DEBUG("\n mutex init failed\n");
        return ret;
    }


    SECMON_DEBUG("Exiting receive_data function\n");
    return SUCCESS;
}

/**
 * fetching configurations intailly through client
 * @param arg
 *			contain NULL
 * @returns void
 *
 */
void *configurations(void *arg)
{
    SECMON_DEBUG("fetching configurations...\n");
    fetch_all_config();
    return NULL;
}

static void export_stat_options(struct collector_pdu *coll_pdu, struct netflow_stat *st)
{
  unsigned char *ptr;
  struct data_template *tpl;
  int i;

    uint64_t exportedpkt  = 0;
    uint64_t exportedtraf  = 0;
    uint64_t exportedflow  = 0;
    ptr  =  get_n_add_template_to_pdu(OPTION_TEMPL_STAT ,  &tpl , coll_pdu);
    if ( (!ptr))
        return;

    /* encode all fields */
    for (i  =  0; ; )
    {
        int type  =  tpl->fields[i++];
        if (!type)
            break;
        switch (type)
        {
	  	  case SCOPE_SYSTEM:        memcpy(ptr,&engine_id , sizeof(engine_id)); 
                                            break;
          case TOTAL_PKTS_EXP:	  exportedpkt  =  htonll(st->exported_pkt);
                                  memcpy(ptr,&exportedpkt ,  sizeof(st->exported_pkt));
                                  break;
          case TOTAL_BYTES_EXP:	    exportedtraf  =  htonll(st->exported_traf);
                                    memcpy(ptr,&exportedtraf ,  sizeof(st->exported_traf));
                                    break;
          case TOTAL_FLOWS_EXP:    exportedflow  = htonll(st->exported_flow);
                                   memcpy(ptr,&exportedflow ,  sizeof(st->exported_flow));
                                   break;
          default: SECMON_DEBUG("WARN_ONCE NETFLOW: Unknown Element id %d\n", type);
        }
           ptr += tpl->fields[i++];
    }

    coll_pdu->pdu_data_records++;
    coll_pdu->pdu_flowset->size  =  htons(ntohs(coll_pdu->pdu_flowset->size) + tpl->rec_size);
    coll_pdu->pdu_ts_mod  =  get_currentTime();
}

static void export_options(void)
{
  struct collector_pdu *temp;
  temp = pdu_list;

  while(temp!=NULL) {
    if (!temp->ts_stat_last)
       temp->ts_stat_last  =  get_currentTime();

    if ((time_is_after_jiffies(temp->ts_stat_last + STAT_INTERVAL * HZ))) {
      export_stat_options(temp, &netflow_stat);
      temp->ts_stat_last  =  get_currentTime();
    }
    else
        return;
    temp->ts_stat_last  =  get_jiffies();
    temp->pdu_needs_export++;
    temp = temp->next;
  }
}


/**
 *  This the flow scanner timer function which is called in the export
 *  timer context in every 1 sec time.
 *
 *  @param sigv
 *      sival params for timer expiry.
 *  @returns void
 *
 */
void netflow_examine_n_transmit(union sigval sigv)
{
    fwait(netflow_rule_futex);

    const unsigned long i_timeout  =  sigv.sival_int? 0 : pdu_inactive_timeout * HZ;
    const unsigned long a_timeout  =  pdu_active_timeout * HZ;
    struct collector_pdu *temp,*obj;

    _LIST_HEAD(export_list);
    struct netflow_flow *nf ,  *tmp;
    int i;

    struct collector_pdu *temp_pdu,*pdu_obj;
    /*SECMON_DEBUG("%s called ..", __func__);*/
    if(likely(netflow_plugin_enabled==FALSE))

    {
      /*SECMON_DEBUG("%s called .., plugin disbaled", __func__);*/
        temp_pdu = pdu_list;
        while(temp_pdu!=NULL)
        {
            temp_pdu = temp_pdu->next;
            pdu_obj = temp_pdu;

            if(pdu_obj!=NULL)
            {
                free(pdu_obj);
                pdu_obj = NULL;
            }
        }
        pdu_list = NULL;

        fpost(netflow_rule_futex);

        return;
    }

    /*SECMON_DEBUG("NETFLOW: %s protocol[%d]", __func__, protocol);*/

    export_options();

    for (i  =  0; i < LOCK_CNT; i++)
    {
        struct netflow_entry *stripe  =  &nf_hash_table_stripes[i];
        if (pthread_spin_trylock(&stripe->lock))
        {
            ++wk_trylock;
            continue;
        }
		for (nf  =  container_of((&stripe->list)->prev ,  typeof(*nf), list),
            tmp  =  container_of(nf->list.prev ,  typeof(*nf), list);
            &nf->list != &stripe->list; 					\
            nf  =  tmp ,  tmp  =  container_of(tmp->list.prev ,  typeof(*tmp), list))
        {
            ++wk_count;
            if (tuple_needs_export(nf ,  i_timeout ,  a_timeout ,  get_currentTime()))
            {
                HLIST_DELETE(&nf->hlist);
                list_del(&nf->list);
                list_add(&nf->list ,  &export_list);
            }
            else
            {
                break;
            }
        }
        pthread_spin_unlock(&stripe->lock);
    }

    set_time_base();
	for (nf  =  container_of((&export_list)->next ,  typeof(*nf), list),
            tmp  =  container_of(nf->list.next ,  typeof(*nf), list);
            &nf->list != &export_list;
            nf  =  tmp ,  tmp  =  container_of(tmp->list.next ,  typeof(*tmp), list))
    {
        ADD_NETFLOW_STAT(pkt_out ,  nf->nr_packets);
        ADD_NETFLOW_STAT(traf_out ,  nf->nr_bytes);
        list_del(&nf->list);
        /*SECMON_DEBUG("%s calling netflow_create_pdu ..", __func__);*/
        create_n_fill_pdu(nf);
    }

    temp = pdu_list;

    /*SECMON_DEBUG("%s pdu_list %p ", __func__, temp);*/
    while(temp!=NULL)
    {
        obj = temp;
        temp = temp->next;

        /*SECMON_DEBUG("NETFLOW: %s jiffies[%lu] pdu_ts_mod[%lu] i_timeout[%lu], pdu_needs_export[%u]", __func__,get_currentTime(), obj->pdu_ts_mod, i_timeout, obj->pdu_needs_export );*/
        if ((get_currentTime() - obj->pdu_ts_mod) >= i_timeout || obj->pdu_needs_export)
        {
           /*if(delete_not_need_pdu(obj->collector_addr)==TRUE)*/
            {
               /*SECMON_DEBUG("%s calling export_netflow_pdu  ..", __func__);*/
                fill_dtls_n_export_pdu(obj);
                obj->pdu_needs_export  =  0;
            }
        }
    }
    /*SECMON_DEBUG("%s returning ", __func__);*/
    fpost(netflow_rule_futex);

}

/******************************************************************
  FLOWS DUMP START
 *******************************************************************/
/**
 *  Debug Function to dump the current hash table flow entries in a file.
 *  This also runs in a timer context in every 10sec timer expiry.
 *
 *  @param sigval
 *      timer expiry params.
 *  @returns void
 *
 */
void netflow_dump_packet(union sigval sigv)
{
    const long i_timeout  =  pdu_inactive_timeout * HZ;
    const long a_timeout  =  pdu_active_timeout * HZ;
    int i  =  0 , j  =  0;
    struct netflow_flow *mynf  =  NULL;
    FILE *g_dump_file_p  =  NULL;
    struct ip_addr* src_ip  =  NULL ,  *dst_ip  =  NULL ,  *nh_ip  =  NULL;
    g_dump_file_p  =  fopen(FLOWDUMP ,  "w");
    fprintf(g_dump_file_p ,  "# hash a dev:i , o"

            " mac:src , dst"

            " vlan"

            " type"

            " proto src:ip , port dst:ip , port nexthop"
            " tos , tcpflags , options , tcpoptions"
            " packets bytes ts:first , last\n");

    for (; i < LOCK_CNT; i++)
    {
        struct netflow_entry *stripe  =  &nf_hash_table_stripes[i];
        if (!((&stripe->list)->next == (&stripe->list)))
        {
			for (mynf  =  container_of((&stripe->list)->next ,  typeof(*mynf), list);
				&mynf->list != &stripe->list;
				mynf  =  container_of(mynf->list.next ,  typeof(*mynf), list))
            {
                j++;
                fprintf(g_dump_file_p ,  "%d %04x %x",
                        j ,
                        find_hash_nf_tuple(&mynf->tuple),
                        (!export_inactive(mynf ,  i_timeout ,  get_currentTime())) |
                        (export_active(mynf ,  a_timeout ,  get_currentTime()) << 1));

                fprintf(g_dump_file_p ,  " %hd,%hd",
                        mynf->tuple.i_ifc ,
                        mynf->o_ifc);

                fprintf(g_dump_file_p ,  " %0x:%0x:%0x:%0x:%0x:%0x,%0x:%0x:%0x:%0x:%0x:%0x ", mynf->tuple.h_src[0],mynf->tuple.h_src[1],mynf->tuple.h_src[2],mynf->tuple.h_src[3],mynf->tuple.h_src[4],mynf->tuple.h_src[5],mynf->tuple.h_dst[0],mynf->tuple.h_dst[1],mynf->tuple.h_dst[2],mynf->tuple.h_dst[3],mynf->tuple.h_dst[4],mynf->tuple.h_dst[5]);

                if (mynf->tuple.tag[0]) {
                    fprintf(g_dump_file_p ,  " %0x", ntohs(mynf->tuple.tag[0]));
                }

                fprintf(g_dump_file_p ,  " %04x", ntohs(mynf->ethernetType));

                fprintf(g_dump_file_p ,  " %u ",
                        mynf->tuple.protocol);
                if (mynf->tuple.l3proto == AF_INET) {

                    src_ip  =  (struct ip_addr*)&(mynf->tuple.src);
                    dst_ip  =  (struct ip_addr*)&(mynf->tuple.dst);
                    nh_ip  =   (struct ip_addr*)&(mynf->nh);
                    fprintf(g_dump_file_p ,  "%u.%u.%u.%u ,%u %u.%u.%u.%u ,%u %u.%u.%u.%u",
                            src_ip->byte1 ,  src_ip->byte2  , src_ip->byte3  , src_ip->byte4 ,
                            ntohs(mynf->tuple.s_port),
                            dst_ip->byte1 ,  dst_ip->byte2  , dst_ip->byte3  , dst_ip->byte4 ,
                            ntohs(mynf->tuple.d_port),
                            nh_ip->byte1 ,  nh_ip->byte2  , nh_ip->byte3  , nh_ip->byte4);


                } else if (mynf->tuple.l3proto == AF_INET6) {
                    fprintf(g_dump_file_p ,  "%pI6c,%u %pI6c,%u %pI6c",
                            &mynf->tuple.src ,
                            ntohs(mynf->tuple.s_port),
                            &mynf->tuple.dst ,
                            ntohs(mynf->tuple.d_port),
                            &mynf->nh);
                } else {
                    fprintf(g_dump_file_p ,  "?,? ?,? ?");
                }
                fprintf(g_dump_file_p ,  " %x,%x,%x,%x",
                        mynf->tuple.tos ,
                        mynf->tcp_flags ,
                        mynf->options ,
                        mynf->tcpoptions);

                fprintf(g_dump_file_p ,  " %u %u %lu,%lu\n",
                        mynf->nr_packets ,
                        mynf->nr_bytes ,
                        get_currentTime() - mynf->nf_ts_first ,
                        get_currentTime() - mynf->nf_ts_last);

            }
        }

    }
    fflush(stdout);
    fclose(g_dump_file_p);
}

/*******************************************************************
  FLOWS DUMP END
 *******************************************************************/
/**
 *  Flow dump timer creation function. This creates the 10sec timer
 *  to scan and dump the flow hash table memory in every 10sec in a file.
 *  @returns void
 *
 */
static void packet_dump_timer(void)
{

    struct sigevent sevp;
    struct itimerspec itimer;
    SECMON_DEBUG("Creating dump timer\n");
    SECMON_DEBUG("Starting Flow Dump timer to dump flows into file....\n");
    sevp.sigev_notify  =  SIGEV_THREAD;
    sevp.sigev_notify_attributes  =  NULL;
    sevp.sigev_notify_function  =  &netflow_dump_packet;
    sevp.sigev_value.sival_int  =  DONT_FLUSH;

    if((timer_create(CLOCK_REALTIME ,  &sevp ,  &stat_timer_id)) < 0)
    {
        SECMON_DEBUG("Error in creating timer...%d\n",errno);
    }
//    itimer.it_value.tv_sec  =  1;
    /* changed the initial expiration timer to 10sec */
    itimer.it_value.tv_sec  =  10;
    itimer.it_value.tv_nsec  =  0;
    itimer.it_interval.tv_sec  =  10;
    itimer.it_interval.tv_nsec  =  0;

    if((timer_settime(stat_timer_id , 0,&itimer , NULL)) < 0)
    {
        SECMON_DEBUG("Error in timer_settime..%d\n",errno);
    }

}


/**
 *   Flow Scan and export timer creation function. This creates the 1sec timer
 *  to scan and export the flow records from  flow hash table memory.
 *  @returns void
 *
 */
static void start_scan_and_export_timer()
{

    struct sigevent sevp;
    struct itimerspec itimer;
    SECMON_DEBUG("Starting 1 second scan and export timer....\n");
    sevp.sigev_notify  =  SIGEV_THREAD;
    sevp.sigev_notify_attributes  =  NULL;
    sevp.sigev_notify_function  =  &netflow_examine_n_transmit;
    sevp.sigev_value.sival_int  =  DONT_FLUSH;

    if((timer_create(CLOCK_REALTIME ,  &sevp ,  &gtimer_id)) < 0)
    {
        SECMON_DEBUG("Error in creating timer...%d\n",errno);
    }
    itimer.it_value.tv_sec  =  1;
    itimer.it_value.tv_nsec  =  0;
    itimer.it_interval.tv_sec  =  1;
    itimer.it_interval.tv_nsec  =  0;

    if((timer_settime(gtimer_id , 0,&itimer , NULL)) < 0)
    {
        SECMON_DEBUG("Error in timer_settime..%d\n",errno);
    }

}


/**
 *  The main netflow feature thread entry function. This gets called when
 * Netflow feature is enable from GUI and DPDK configuration thread creates
 * thread.
 *  @returns void
 *
 */
int init()
{
    int i;
    SECMON_DEBUG("Initializing NETFLOW version 9\n");

    memcpy(netflow_version,"netflow_v9_v1.0",11);;
    netflow_version_len  =  39;
    SECMON_DEBUG("Version String size=%d",netflow_version_len);


    scan_max  =  HZ / 10;
    start_ts.first  =  htonl(get_currentTime());

/* if we are using dpdk ring */
#ifdef USE_RING
    char qname[MAX_QUEUE_NAME_LEN];
    unsigned int socket_id;
    FILE *p_ring_file  =  NULL;                 /*pointer to ring_params file*/
    int temp_ring_size;
    unsigned int ringsize = temp_ring_size;

    p_ring_file  =  fopen(RING_FILE ,  "r");

    if(NULL == p_ring_file)
    {
        SECMON_DEBUG("Could not open the ring params file\n");
        ringsize=RINGSIZE;
    }
    else
    {
        fscanf(p_ring_file,"%d",&temp_ring_size);
        ringsize = temp_ring_size;

        fclose(p_ring_file);
    }

    socket_id  =  rte_socket_id();
    strncpy(qname,NETFLOW_RING,MAX_QUEUE_NAME_LEN);
    r  =  rte_ring_create(qname ,  ringsize ,  socket_id ,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if(r == NULL)
    {
        SECMON_DEBUG("Cannot create rx ring queue for netflow plugin err_no %s \n",rte_strerror(rte_errno));
        return FAILURE;
    }
/*end of dpdk use ring check*/
#endif

    netflow_rule_futex = (int *)malloc(sizeof(int));
    *netflow_rule_futex = 1;

    if (pthread_mutex_init(&hash_lock ,  NULL) != 0)
    {
        SECMON_DEBUG("\n mutex init failed\n");
        return FAILURE;
    }

    clear_netflow_stats();

    if (!nf_hash_table_size) {
        /* use 1/1024 of memory ,  1M for hash table on 1G box */

        unsigned long memksize  =  5 * 1024 * 1024;
        nf_hash_table_size  =  memksize / sizeof(struct hlist_head);
    }

    if (nf_hash_table_size < LOCK_CNT)
        nf_hash_table_size  =  LOCK_CNT;
    SECMON_DEBUG("NETFLOW: hash table size %u (%luK)\n", nf_hash_table_size , nf_hash_table_size * sizeof(struct hlist_head) / 1024);

    nf_tuple_hash_table_size  =  nf_hash_table_size;

    nf_tuple_hash_table  =  alloc_tuple_hash_table(nf_tuple_hash_table_size);
    if (!nf_tuple_hash_table) {
        SECMON_DEBUG("Unable to create neflow_hash\n");
        return  -1;
    }

    for (i  =  0; i < LOCK_CNT; i++) {
        pthread_spin_init(&nf_hash_table_stripes[i].lock , 0);
        INIT_LIST_HEAD(&nf_hash_table_stripes[i].list);
    }

    free_templates();
    flush   =  DONT_FLUSH;
    start_scan_and_export_timer();

    packet_dump_timer();
    SECMON_DEBUG("NETFLOW is started...\n");



    return SUCCESS;
}

/**
 *   The netflow exit function gets called when Netflow feature is
 * disable and thread stopped.
 *  @returns void
 *
 */
void netflow_exit(void *arg)
{
    SECMON_DEBUG("Cleaning Netflow...\n");
    if(arg == NULL)
        SECMON_DEBUG("arg null\n");
    timer_delete(gtimer_id);
    free_templates();
    free(nf_tuple_hash_table);
    SECMON_DEBUG("NETFLOW CLEANED...\n");
}

/**
 * update netflow plugin status
 *  @returns void
 *
 */
void update_netflow_status(bool status)
{
    if(status == TRUE)
    {
        SECMON_DEBUG("plugin enabled\n");
        netflow_plugin_enabled  =  TRUE;
    }
    else
    {
        SECMON_DEBUG("plugin disabled\n");
        netflow_plugin_enabled  =  FALSE;
    }
}

/**
 * delete the pdu if its not needed i.e if its of collector that not exits
 *  @returns
 *		TRUE 		if pdu is required
 *		FALSE		otherwise
 *
 */
bool delete_not_need_pdu(struct sockaddr_in pdu_addr)
{
    struct Collector_object *collectors_temp;
    struct collector_pdu *last,*temp;

    /*all collector_obj_head*/
    collectors_temp = collector_obj_head;
    SECMON_DEBUG("NETFLOW: %s called\n", __func__);
    while(collectors_temp!=NULL)
    {
        /*check pdu exist is required or not*/
        if (sockaddr_cmp_ip4((struct sockaddr *)&collectors_temp->server_address,(struct sockaddr *)&pdu_addr))
        {
            /*required pdu*/
            return TRUE;
        }
        collectors_temp = collectors_temp->next;
    }

    /*delete not required pdu*/
    last = NULL;
    temp = pdu_list;
    while(temp!=NULL)
    {
        if (sockaddr_cmp_ip4((struct sockaddr *)&temp->collector_addr,(struct sockaddr *)&pdu_addr))
        {

            if(last==NULL)
            {
                pdu_list = pdu_list->next;
            }
            else
            {
                last->next = temp->next;
            }

            if(temp!=NULL)
            {
                free(temp);
                temp = NULL;
            }

            return FALSE;
        }

        last = temp;
        temp = temp->next;
    }

    return FALSE;

}

