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

#ifndef	PLUGIN_UTIL_H
#define PLUGIN_UTIL_H

/** @file
 * Common header file for all 3 plugins
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <curl/curl.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/wait.h>
#include <errno.h>
#include "configurations.h"
#include "packet_parser.h"

#define IP_SIZE         21        /**< Size of IP */
#define URL_SIZE        300       /**< Size of URL */
#define ROOT_URL_SIZE   50        /**< Root URL Size */
#define PORT_SIZE       6         /**< Port Size */
#define SIZE            200       /**< Size */
#define VALUESIZE       300       /**< Value Size */
#define RINGSIZE        128       /**< Ring Size */

#define ETHER_ADDR_LEN  6         /**< Ethernet Address Length */
#define IPV6_ADDR_LEN   80        /**< IPv6 Address Length */
#define IPV4_ADDR_LEN   16        /**< IPv4 Address Length */
#define MAX_ID_LEN      80        /**< Maximum ID Length */
#define MAX_IP_LEN      80        /**< Minimum IP Length */
#define MAX_NAME_LEN    80        /**< Maximum Name Length */

#define ERROR           "error"         /**< Error */
#define HTTP            "http://"       /**< HTTP */
#define AGENT           "v1.0/secmon"   /**< Agent */
#define EXT             "/"             /**< Ext */
#define EXT1            ":"             /**< Ext1 */
#define CONFIGFILE      "/opt/secmon/plugins/config/EMS_config.ini"       /**< Path to config file */
#define RING_FILE       "/opt/secmon/plugins/config/dpdk_config.ini"      /**< Path to Ring config file */

#define LOCK_COUNT      (1<<8)            /**< Lock count */
#define LOCK_COUNT_MASK (LOCK_COUNT-1)    /**< Lock count mask */

#define INFO_LOG		1	          /**< Info Log flag */
#define DEBUG_LOG		2           /**< Debug Log flag */

#ifdef	SECMON_DEBUG_LOG
    #define SECMON_LOG_LEVEL	DEBUG_LOG    /**< Secmon Debug Log Level */
#elif	SECMON_INFO_LOG
    #define SECMON_LOG_LEVEL	INFO_LOG     /**< Secmon Info Log Level */
#endif

#define SECMON_CRITICAL(fmt , arg...) \
    syslog(LOG_CRIT|LOG_LOCAL0 , fmt,##arg) /**< Secmon critical log function */

#if (SECMON_LOG_LEVEL == DEBUG_LOG)
    #define SECMON_DEBUG(fmt , arg...) \
        syslog(LOG_DEBUG|LOG_LOCAL0 , fmt,##arg)  /**< Secmon debug log function */
#else
    #define SECMON_DEBUG(fmt , arg...)            /**< Secmond debug log function no defined */
#endif

#if (SECMON_LOG_LEVEL == WARN_LOG)
    #define SECMON_WARN(fmt , arg...) \
        syslog(LOG_WARNING|LOG_LOCAL0 , fmt,##arg)  /**< Secmon Warning log function */
#else
    #define SECMON_WARN(fmt , arg...)               /**< Secmond Warning log function not defined */
#endif


#if (SECMON_LOG_LEVEL == INFO_LOG)
    #define SECMON_INFO(fmt , arg...) \
        syslog(LOG_INFO|LOG_LOCAL0 , fmt,##arg)   /**< Secmon Info log function */
#else
    #define SECMON_INFO(fmt , arg...)             /**< Secmon Info log function not defined */
#endif

#define ONECONF        1    /**< One configurations */
#define NOCONF         0    /**< No configurations */
#define TWOTAGS        2    /**< Two tags */
#define THREETAGS      3    /**< Three tags */
#define EXIT0          0    /**< Exit status */
#define SERVER_MAC     "ff:ff:ff:ff:ff:ff"        /**< Server MAC Address */
#define ACCEPT_HDR     "Accept: application/json" /**< Accept header */
#define CONTENTTYPE_HDR "Content-Type: application/json"  /**< Content type header */
#define SUCCESS_REPLY   "success"     /**< Success reply */
#define HTTP_SUCCESS_CODE   200       /**< HTTP success code */
#define INVALID_RESPONSE_SIZE   1     /**< Invalid Response Size */

/**
 *  Struct containing information of Curl fetch result
 */
struct Curl_Fetch_St
{
    uint8_t *payload;
    uint32_t size;
};

char* HTTP_fetch_url(char* );
void generate_ems_base_url(char *,char *);
char* get_conf_from_ems(char *,char *  , int ,...);
void read_server_ip_port(char *,char *);
void store_ip_mask(char*  ,  uint32_t *,uint8_t);
void calculate_first_address(uint32_t *,uint8_t );
void store_ip(char*  ,  uint8_t *);

inline bool compare7tuple(struct Classification_object * ,  struct Tuple *);
inline bool compare_mac(uint8_t *rule_mac ,  uint8_t *tuple_mac);
inline bool compare_ip(uint32_t rule_ip ,  uint8_t subnet_mask ,  uint32_t tuple_ip);
inline bool compare_port(uint16_t rule_min_port ,  uint16_t rule_max_port ,  uint16_t tuple_port);
inline bool compare_protocol(uint8_t rule_protocol ,  uint8_t tuple_protocol);
void print_packet(char *pkt ,  int len);
int parse_packet(char **secmon_pkt , int len , struct Tuple *tuple);

/** 
 *  Function for creating futex
 *  
 *  @param  uaddr
 *      Point to futex word
 *  @param  futex_op
 *      Operation to perform
 *  @param  val
 *      Whose value depend on futex_op
 *  @param  timeout
 *      Timeout for the Operation
 *  @param  uaddr2
 *      Second futex word
 *  @param  val3
 *      Whose value depends on Operation
 *  @returns
 *      Return Positive value on success
 */
static int inline futex(int *uaddr, int futex_op, int val,
             const struct timespec *timeout, int *uaddr2, int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val,
                          timeout, uaddr, val3);
}

/** Lock the futex pointed to by 'futexp': if futex currently
 *  has the value 0 that wait for futex to Realease and if futex
 *  has value 1 than set it 0
 *  @param
 *    futexp    futex pointer variable to realease
 *  @returns
 *    void
 */      
static void inline fwait(int *futexp)
{
    int s;
    /* __sync_bool_compare_and_swap(ptr, oldval, newval) is a gcc
       built-in function.  It atomically performs the equivalent of:
 
          if (*ptr == oldval)
          *ptr = newval;

       It returns true if the test yielded true and *ptr was updated.
       The alternative here would be to employ the equivalent atomic
       machine-language instructions.  For further information, see
       the GCC Manual. */

    while (1) {

        /* Is the futex available? */

        if (__sync_bool_compare_and_swap(futexp, 1, 0))
         {
            break;      // Yes 
          }

        /* Futex is not available; wait */
        s = futex(futexp, FUTEX_WAIT, 0, NULL, NULL, 0);
        if (s == -1 && errno != EAGAIN)
            perror("futex-FUTEX_WAIT");
    }
}

/** Release the futex pointed to by 'futexp': if the futex currently
 *  has the value 0, set its value to 1 and the wake any futex waiters,
 *  so that if the peer is blocked in fpost(), it can proceed. 
 *  @param 
 *    futexp    futex pointer variable to release
 *  @returns 
 *    void
 */

static void inline fpost(int *futexp)
{
    int s;

  /* __sync_bool_compare_and_swap() was described in comments above */

    if (__sync_bool_compare_and_swap(futexp, 0, 1)) {

        s = futex(futexp, FUTEX_WAKE, 1, NULL, NULL, 0);
        if (s  == -1)
            perror("futex-FUTEX_WAKE");
    }
}

#endif

