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
#ifndef _SFLOW_H_
#define _SFLOW_H_


#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <timehelper.h>

#include "rawforward.h"

void write_sflow_pkt(char *msg , int len , struct Collector_object *tool);

#if defined(__cplusplus)
extern "C" {
#endif

    struct _Sflow_header {
        uint32_t protocol;                      /* (protocol header - Ethernet) */
        uint32_t frame_length;                  /* packet length before sampling */
        uint32_t stripped;                      /* sender stripped header/trailer bytes */
        uint32_t length;                        /* length of sampled header bytes to follow */
    } __attribute__((packed));

    typedef struct _Sflow_header Sflow_header;

    struct _Sflow_sample_elt {
        uint32_t tag;  /* type tag */
        uint32_t length;
        Sflow_header header;
    } __attribute__((packed));

    typedef struct _Sflow_sample_elt Sflow_sample_elt;

    struct _Sflow_sample {
        u_int32_t tag;                  /* sample tag -- enterprise  =  0 : format  =  1 */
        u_int32_t len;
        u_int32_t seq_num;      /* Incremented with each flow sample
                                           generated */
        u_int32_t src_id;            /* fsSourceId */
        u_int32_t smp_rate;        /* fsPacketSamplingRate */
        u_int32_t smp_pool;          /* Total number of packets that could have been
                                           sampled (i.e. packets skipped by sampling
                                           process + total number of samples) */
        u_int32_t drops;                /* Number of times a packet was dropped due to
                                           lack of resources */
        u_int32_t input;                /* SNMP ifIndex of input interface.
                                           0 if interface is not known. */
        u_int32_t output;               /* SNMP ifIndex of output interface ,
                                           0 if interface is not known.
                                           Set most significant bit to indicate
                                           multiple destination interfaces
                                           (i.e. in case of broadcast or multicast)
                                           and set lower order bits to indicate
                                           number of destination interfaces.
                                         */

        u_int32_t num_elements;
    } __attribute__((packed));

    typedef struct _Sflow_sample Sflow_sample;

    struct _Sflow_datagram_header {
        uint32_t version;               /* Sflow version 5 */

        uint32_t ip_type;               /* IP address of sampling agent */
        uint32_t agt_addr;              /* IP address of sampling agent */
        uint32_t sub_agt_id;            /* Used to distinguishing between datagram
                                           streams from separate agent sub entities
                                           within an device. */
        uint32_t seq_num;               /* Incremented with each sample datagram
                                           generated */
        uint32_t uptime;                /* Current time (in milliseconds since device
                                           last booted). Should be set as close to
                                           datagram transmission time as possible.*/
        uint32_t num_rec;               /* Number of tag-len-val flow/counter records to follow */
    }__attribute__((packed));

    typedef struct _Sflow_datagram_header Sflow_datagram_header;

    void deinit_sflow(void);

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_H */
