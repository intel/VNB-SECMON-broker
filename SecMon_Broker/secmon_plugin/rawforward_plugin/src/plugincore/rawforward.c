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
 *	Contains functions of rawforward_plugin (init)
 *  that are called from the SecMonAgent using function pointers ,  
 *  function to poll packets from the poll mode driver and  
 *  forwards them to tools.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <errno.h>
#include <rte_mbuf.h>

#include "rawforward.h"
/* #include "rawforward_sflow.h" */ /* uncomment if needed sflow plugin */
#include "utils.h"

#define RAWFORWARD_RING "rawforward_ring"     /**< Rawforward Ring */

#ifdef SECMON_DEBUG_LOG
static int numpkts_enqueued;
static int numpkts_dequeued;
#endif

int data_msg_key;
int conf_msg_key;
int msg_type;
bool plugin_enabled  =  FALSE;

pthread_t hash_timer_tid;
pthread_t configurations_tid;

int *rfutex_stripes[LOCK_COUNT], *iaddr;
int *raw_rule_futex;

#ifdef USE_RING

pthread_t get_packets_tid;
static struct rte_ring *r;

#endif

/** This API is called by SecMon Agent only once after 
 * the plugin gets loaded.This should return as soon as  
 * possible. If this returns failure SecMon Agent will not
 * call any other APIs. Any initialization task can be 
 * performed in this function like memory allocation ,logging, 
 * resource allocation etc.
 * 
 * @returns 
 * 		0 in case of SUCCESS ,  negative value otherwise.
 */
int init()
{
  SECMON_DEBUG("Entering init function...\n");
  /* char *iface_ip = NULL; */

// start of use ring
#ifdef USE_RING
	char qname[MAX_NAME_LEN];
	unsigned int socket_id;
	FILE *p_ring_file  =  NULL;                 /*pointer to ring_params file*/
	int temp_ring_size;
	unsigned int ringsize;

  p_ring_file  =  fopen(RING_FILE , "r");
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

  strncpy(qname , RAWFORWARD_RING , MAX_NAME_LEN);

  socket_id  =  rte_socket_id();
  r  =  rte_ring_create(qname ,  ringsize ,  socket_id , 
          RING_F_SP_ENQ | RING_F_SC_DEQ);
  if(unlikely(r == NULL))
  {
      SECMON_CRITICAL("ERROR: Cannot create rx ring queue for rawforward plugin\n");
      perror("Error occurs. Please check /var/log/secmon.log file for error\n");
      return -1;
  }
// end of use ring
#endif

  int i;

  iaddr = mmap(NULL, sizeof(int) * LOCK_COUNT, PROT_READ | PROT_WRITE,
      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  if (iaddr == MAP_FAILED)
    perror("mmap");

  for(i=0; i< LOCK_COUNT; i++)
  {
    rfutex_stripes[i] = &iaddr[i];
    *rfutex_stripes[i] = 1;
  }
  raw_rule_futex = (int *)malloc(sizeof(int));
  *raw_rule_futex = 1;

  /*
  if ((iface_ip = strdup(get_interface_ip())) == NULL)
  {
    iface_ip  =  (char *)malloc(sizeof(char) * MAX_IP_LEN);
    strncpy(iface_ip,"0.0.0.0", MAX_IP_LEN);   
  }
  */

  initialize_hash_table();

  /*
  init_sflow(iface_ip);
  free(iface_ip);
  */

  SECMON_DEBUG("Exiting init function...\n");
  return SUCCESS;
}

/** This API is called by SecMon Agent when the plugin  
 * has to be stopped. Any de-initializing task like memory freeing , 
 * file closing , socket closing should be performed in this function.
 * 
 * @return 
 * 		0 in case of SUCCESS  ,  negative value otherwise
 */
int deinit()
{
  SECMON_DEBUG("Entering deinit function\n");
  /* deinit_sflow(); */
  SECMON_DEBUG("Exiting deinit function\n");
  return SUCCESS;
}
/** function called from SecMon Agent just in case some plugin
 * requires configuration to be fetched from a file or some other means
 * apart from SecMon EMS
 * @returns 
 * 		always return SUCCESS
 */
int config()
{
  SECMON_DEBUG("Entering config function\n");

  SECMON_DEBUG("Exiting config function\n");
  return SUCCESS;
}

/** This API is called by SecMon Agent only once after the plugin
 * gets loaded. It will create threads to fetch configurations and listen to 
 * configuration changes ,  timer for hash removal on time-out.
 * Since this is an interface function ,  it should return as soon as possible.
 *
 * @returns 
 *		0 in case of success
 * 		negative value otherwise
 */
int receive_data()
{
  int ret;

#ifdef USE_RING
  ret  =  pthread_create(&get_packets_tid ,  NULL ,  (void *)get_packets ,  NULL);
  if(unlikely(ret < 0 ))
  {
      SECMON_CRITICAL("ERROR: pthread creation failed for get_packets in rawforward plugin\n");
      perror("Error occurs. Please check /var/log/secmon.log file for error\n");
      return ret;
  }
#endif

  ret  =  pthread_create(&hash_timer_tid ,  NULL ,  (void *)hash_timer ,  NULL);
  if(unlikely(ret < 0 ))
  {
    SECMON_CRITICAL("ERROR: pthread creation failed for hash_timer in rawforward plugin\n");
    perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    return ret;
  }

  ret  =  pthread_create(&configurations_tid ,  NULL ,  (void *)configurations ,  NULL);
  if(unlikely(ret < 0 ))
  {
    SECMON_CRITICAL("ERROR: pthread creation failed for configurations in rawforward plugin\n");
    perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    return ret;
  }

  return SUCCESS;
}

/** fetches configurations from the SecMon EMS.
 * It will fetch configurations related to rawforward plugin
 * based on the scope.
 * @param 
 *			arg - argument passed 
 * @returns 
 * 			void
 */
void *configurations(void *arg)
{
  SECMON_DEBUG("fetching client configurations for rawforward plugin...\n");   
  fetch_all_config(); 
  return NULL;
}

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
      fwait(rfutex_stripes[i & LOCK_COUNT_MASK]);
      if(hash_table[i] != NULL)
      {
        unsigned long present  =  get_jiffies();

        /* In this version the default timeout value for 
         * all hash entries is 3 minute.
         */
        if(unlikely((present - hash_table[i]->last_seen) > HASH_EXPIRY_TIME))
        {
          SECMON_DEBUG("time expired for hash entry=%d of rawforward plugin ,  removing it\n",i);
          SECMON_DEBUG("acquiring lock\n");
          if(hash_table[i]!= NULL)
            remove_hash_entry(i);

          SECMON_DEBUG("time expired for hash entry=%d of rawforward plugin ,  removing it\n",i);

        }  
      }
      fpost(rfutex_stripes[i & LOCK_COUNT_MASK]);
    }
  }

}

/** flushes the hash table containing hash entries.
 * this function is called if someone flushes from the GUI.
 * @return
 * 	 void
 */

void flush_hash_table()
{
  SECMON_DEBUG("flush hash table for rawforward plugin\n");
  unsigned int i;
  for(i = 0; i<HASH_TABLE_SIZE; i++)
  {
    fwait(rfutex_stripes[i & LOCK_COUNT_MASK]);
    if(hash_table[i]!= NULL)
      remove_hash_entry(i);
    fpost(rfutex_stripes[i & LOCK_COUNT_MASK]);
  }
  SECMON_DEBUG("successfully flushed hash entries for rawforward plugin\n");
}

/** removes hash entry with the specified index 
 * @param 
 *	i - index of the hash to remove
 * @return 
 *	void
 *
 */
void remove_hash_entry(unsigned int i)
{
  struct rule_hash *hash_entry = hash_table[i];

  decrement_session(hash_entry->collectors);
  free(hash_entry);
  hash_table[i] = NULL;

}


/** updates the plugin status to TRUE or FALSE
 * @param 
 *	status - status to update 
 * @return 
 *	void
 */
void update_status(bool status)
{
  if(status == TRUE)
  {
    plugin_enabled  =  TRUE;
    SECMON_DEBUG("rawforward plugin is enabled\n");
  }
  else
  {
    plugin_enabled  =  FALSE;
    SECMON_DEBUG("rawforward plugin is disabled\n");
  }

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
int receive_from_secmon(struct rte_mbuf *m)
{
    if(likely(r!=NULL))
    {
        rte_ring_enqueue(r , m);
#ifdef SECMON_DEBUG_LOG
        numpkts_enqueued++;
        if(unlikely(numpkts_enqueued==PKT_PRINT_DEBUG))
        {
            SECMON_DEBUG("%d packets received from secmon\n",PKT_PRINT_DEBUG);
            numpkts_enqueued = 0;
        }
#endif
    }
    return SUCCESS;
}


/**
 *  Dequeue packet from dpdk ring and check if rule for these packets
 *  are defined to forward if yes than forward them otherwise drop them
 *  @param  args
 *      arguments passed from thread invocation
 *  @returns void
 */
void *get_packets(void *arg)
{
    int 		    retval = 0;
    unsigned int 	packet_len = 0;
    struct 		    Tuple *tuple;
    unsigned int 	hash_code;
    unsigned int	rx_pkts = PKT_BURST;
    bool 		    found = FALSE;
    void 		    *pkts[PKT_BURST];
    struct 		    rte_mbuf *m;
    int 		    i;

    tuple  =  (struct Tuple *)malloc(sizeof(struct Tuple));
    if(likely(r!= NULL))	/* r is rte ring*/
    {
        while(1)
        {
            /* read from dpdk ring 0.
             * pointer to rte_mbuf packets are written to this ring
             * by main process whenever SecMon Agent calls the packet 
             * receive API. 
             */
            if(!rte_ring_dequeue_bulk(r , pkts , rx_pkts))
            {   
#ifdef SECMON_DEBUG_LOG
                numpkts_dequeued += rx_pkts;
                if(unlikely((numpkts_dequeued/PKT_PRINT_DEBUG) > 0))
                {
                    SECMON_DEBUG("%d packets dequeued from ring\n",PKT_PRINT_DEBUG);
                    numpkts_dequeued = 0;
                }
#endif
                /* parse the packet to extract mbuf, calculate its tuple , find hash_value for the tuple is already
                 * available in hash table, send the packet to tools else 
                 * check what is required to be done for this packet.it is matching rules in filter
                 * configurations, handle it else discard it 
                 */
                for(i = 0; i< rx_pkts; i++)
                {
                    /* Extract mbuf from the received packet */
                    m  =  (struct rte_mbuf *)pkts[i];
                    char *pkt  =  (char *)rte_pktmbuf_mtod(m , char *);
                    packet_len  =  m->pkt_len;

                    if(likely(plugin_enabled == TRUE))
                    {
                        retval  =  parse_packet(&pkt , packet_len , tuple);
                        if(retval == PACKET_PARSE)
                        {
                            hash_code  =  find_hash(tuple);
                            fwait(raw_rule_futex);
                            fwait(rfutex_stripes[hash_code & LOCK_COUNT_MASK]);
                            if(hash_entry_available(hash_code) == TRUE)
                                send_to_tools(pkt, hash_code, packet_len);
                            else
                            {
                                /* match the tuple with existing filter rules */
                                apply_filters(tuple, hash_code, &found);
                                if(found == TRUE)
                                {
                                    send_to_tools(pkt, hash_code, packet_len); 
                                    SECMON_DEBUG("rules matched and hash =%d added to hash table with details successfully\n",hash_code);
                                }
                            }
                            fpost(rfutex_stripes[hash_code & LOCK_COUNT_MASK]);
                            fpost(raw_rule_futex);

                        }
                    }
                    /* free the direct buffer of rte_mbuf pointer */
                    rte_pktmbuf_free(pkts[i]);
                }
            }
        }
    }
    return NULL;
}
/*if we are not using dpdk ring*/
#else

/**  Receive packet from secmon and check if match with
 *  any rule or not and process packet according to that 
 *
 *  @param m
 *      contain packet from secmon
 *  @return void
 *
 */
void receive_from_secmon(struct rte_mbuf *m)
{
  if(likely(plugin_enabled == TRUE))
  {
    struct Tuple tuple;

    /* Extract mbuf from the received packet */
    char *pkt  =  (char *)rte_pktmbuf_mtod(m , char *);
    unsigned int 	packet_len = m->pkt_len;

    int retval  =  parse_packet(&pkt , packet_len , &tuple);
    if(retval == PACKET_PARSE)
    {
      unsigned int 	hash_code =  find_hash(&tuple);
      fwait(raw_rule_futex);
      fwait(rfutex_stripes[hash_code & LOCK_COUNT_MASK]);

      if(hash_entry_available(hash_code) == TRUE)
      {
        send_to_tools(pkt, hash_code, packet_len);
      }
      else
      {
        bool found = FALSE;

        /* match the tuple with existing filter rules */
        apply_filters(&tuple, hash_code, &found);
        if(found == TRUE)
        {
          send_to_tools(pkt, hash_code, packet_len); 
          SECMON_DEBUG("rules matched and hash =%d added to hash table with details successfully\n",hash_code);
        }
      }

      fpost(rfutex_stripes[hash_code & LOCK_COUNT_MASK]);
      fpost(raw_rule_futex);
    }
  }
  rte_pktmbuf_free(m);
}
// end of use ring
#endif