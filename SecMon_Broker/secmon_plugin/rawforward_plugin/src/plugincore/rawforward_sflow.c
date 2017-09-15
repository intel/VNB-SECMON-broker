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

/*
 * @file
 *		contains functions to add sflow header to the packet 
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/queue.h>
#include <rte_mbuf.h>
#include "rawforward_sflow.h"

/* sflow header structures */
static Sflow_datagram_header	*sflow_datagram_hdr;
static Sflow_sample 			*sflow_sample;
static Sflow_header 		    sflow_sample_header ;
static Sflow_sample_elt 	    *sflow_sample_element;

/** init function called once when the plugin loads
 * initializes the memory for the structures used to fill the sflow header
 * @param 
 * 		iface_ip - interface of sflow subagent
 * @returns 
 * 			void 
 */
void init_sflow(char *iface_ip)
{
    SECMON_DEBUG("Entering init sflow for rawforward plugin\n");
	
    unsigned int ip_v4_addr;
    inet_pton(AF_INET , iface_ip, &ip_v4_addr);     /* it should be taken from configuration */

    sflow_datagram_hdr  	            =  (Sflow_datagram_header *)    malloc(sizeof(Sflow_datagram_header));
    sflow_sample 			            =  (Sflow_sample *)             malloc(sizeof(Sflow_sample));
    sflow_sample_element	            =  (Sflow_sample_elt *)         malloc(sizeof(Sflow_sample_elt));

    /* most of the information are static */
    sflow_sample_element->tag  		    =  htonl(1);    /* packet header are sampled */
    sflow_datagram_hdr->num_rec  	    =  htonl(1);    /* number of records */
    sflow_datagram_hdr->ip_type  	    =  htonl(1);    /* IP type */
    sflow_datagram_hdr->agt_addr  	    =  ip_v4_addr;  /* Agent address */
    sflow_datagram_hdr->sub_agt_id	    =  htonl(3);    /* Sub Agent address */
    sflow_sample->src_id  		        =  htonl(22);   /* source id */
    sflow_sample->smp_rate  	        =  htonl(400);  /* Sampling rate */
    sflow_sample->smp_pool  		    =  htonl(24);   /* Sampling pool */
    sflow_sample->drops  			    =  htonl(2);    /* Packet drops */
    sflow_sample->input  			    =  htonl(3);    /* Input intf index */
    sflow_sample->output  			    =  htonl(3);    /* Output intf index */
    sflow_sample->num_elements  	    =  htonl(1);    /* Number of elements */
    sflow_datagram_hdr->version         =  htonl(5);    /* SFLow version 5 */
    sflow_sample_header.protocol        =  htonl(1);    /* Ethernet format of sampled header */
    sflow_sample->tag  				    =  htonl(1);    /* sflow sample */
    
    SECMON_DEBUG("Exiting init sflow for rawforward plugin\n");
}

/**
 * deinit function called once when the plugin unloads
 * frees the memory for the structures used to fill the sflow header
 * @param 
 * 			void
 * @returns 
 * 			void 
 */
void deinit_sflow(void)
{
    SECMON_DEBUG("Entering deinit sflow for rawforward plugin\n");
	
    free(sflow_datagram_hdr);
    free(sflow_sample);
    free(sflow_sample_element);
	
    SECMON_DEBUG("Exiting deinit sflow for rawforward plugin\n");
}

/**
 * populates the sflow header and adds the sflow header as payload of UDP
 * packet. The sflow  header contains the actual packet.
 * @param 
 * 	msg - pointer to the packet
 * @param 
 * 	len - address of length of the packet
 * @param 
 * 	iface_ip - interface ip of the agent
 * @return void
 * 	
 */
void write_sflow_pkt(char *msg, int len, struct Collector_object *tool)
{
    static uint32_t sequence_id;
    unsigned int FCS_bytes      = 4;
    unsigned short socket       = tool->socket;
    unsigned int server_length  = tool->server_length;
    struct sockaddr *destaddr   = (struct sockaddr *)&tool->server_address;
    
    sequence_id++;
    sflow_datagram_hdr->seq_num         =  htonl(sequence_id);
    sflow_datagram_hdr->uptime  		=  htonl(get_jiffies());

    uint32_t frame_length  				=  len;
    sflow_sample_header.frame_length  	=  htonl(frame_length+FCS_bytes);
    sflow_sample_header.stripped  		=  htonl(FCS_bytes);
    if(frame_length/4 != 0)
    {
        frame_length /= 4;
        frame_length *= 4;
    }
    sflow_sample_header.length          =  htonl(frame_length);

    /* enterprise  =  0 ,  format  =  1 */
    uint32_t sample_length  		    =  sizeof(Sflow_header) + (((frame_length + 3)/4)*4);
    sflow_sample_element->length  	    =  htonl(sample_length);
    sflow_sample_element->header  	    =  sflow_sample_header;

    /* enterprise  =  0 ,  format  =  1 */
    sflow_sample->len  			        =  htonl(sizeof(Sflow_sample) + sample_length);
    sflow_sample->seq_num  	            =  htonl(sequence_id);

    /* copy structure contents to sflow_raw_packet */
    sendto(socket, sflow_datagram_hdr, sizeof(Sflow_datagram_header), MSG_MORE, destaddr, server_length);
    sendto(socket, sflow_sample, sizeof(Sflow_sample), MSG_MORE, destaddr, server_length);
    sendto(socket, sflow_sample_element, sizeof(Sflow_sample_elt), MSG_MORE, destaddr, server_length);
    
    /* copy the actual packet to the sflow header datagram */
    sendto(socket, msg, len, 0, destaddr, server_length);
}

/** gets IP address from the interface name 
 * @param
 *     iface - name of the interface from where packets 
 * 			   are sent to tool machine
 * @returns 
 * 	   ip address in string format
 */
char *get_interface_ip()
{
    int fd;
    FILE *fp;
    int retval  =  0;
    struct ifreq ifr;
    char iface_name[MAX_IP_LEN];

    fd  =  socket(AF_INET ,  SOCK_DGRAM ,  0);
    if(fd <0)
    {
        SECMON_CRITICAL("ERROR: socket can be created to get ip from interface\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
        return NULL;
    }

    fp  =  fopen(CONF_FILE,"r");
    if(fp == NULL)
    {
        SECMON_CRITICAL("ERROR: cannot open conf_params file..."
                "please place conf_params.cfg at /opt/secmon/plugins/config directory.\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");	
    }
    else
    {
        retval  =  fscanf(fp,"%s ",iface_name);
    }
    if(retval == 0)
    {
        return NULL;
        fclose(fp);
    }
    /* Type of address to retrieve - IPv4 IP address */
    ifr.ifr_addr.sa_family  =  AF_INET;

    /* Copy the interface name in the ifreq structure */
    strncpy(ifr.ifr_name , iface_name , IFNAMSIZ-1);

    if( (ioctl(fd , SIOCGIFADDR , &ifr)) < 0)
    {
       SECMON_DEBUG("failure in ioctl\n");
        return NULL;
    }

    close(fd);
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
}


