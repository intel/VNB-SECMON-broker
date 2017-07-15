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

/** @file
 *  read server details (ip & port number) & scope
 *  specified in config file
 *
 */

#include "common.h"


/** read config file and take ip address ,  port number & scope
 *  of server 
 *  @param scope
 *      will contain scope of secmon
 *  @param address
 *      will contain address of server
 *  @returns void
 *
 */
void read_server_ip_port(char *scope , char *address)
{
    FILE *p_config_file  =  NULL;                 /*pointer to config file*/

    char ip[IPV4_ADDR_LEN],                     /*store ip address*/
         port[ETHER_ADDR_LEN],                  /*store port number*/
         temp_scope[MAX_ID_LEN];				/*store temp scope*/

    memset(ip,'\0',IPV4_ADDR_LEN);
    memset(port,'\0',ETHER_ADDR_LEN);
    memset(temp_scope,'\0',MAX_ID_LEN);
    memset(scope,'\0',MAX_ID_LEN);

    /*opening config file*/
    if((p_config_file  =  fopen(CONFIGFILE ,  "r"))==NULL)
    {
        SECMON_CRITICAL("ERROR: Could not open the config file\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
        return;            
    }

    memset(address,'\0',IP_SIZE);

    /*Read the Server Ip ,  Server Port Number & scope from the config file*/
    fscanf(p_config_file  ,  "%*[^0123456789]%[^\n] %*[^0123456789]%[^\n] %*[^:]%[^\n]",
            ip ,  port , temp_scope);

    memcpy(scope , temp_scope+1 , strlen(temp_scope));

    /*generate address of server*/
    strncpy(address , ip , strlen(ip));
    strncat(address , EXT1 , strlen(EXT));
    strncat(address , port , strlen(port));

    fclose(p_config_file);

}


/** calculate first address from ip and mask
 *  @param ip
 *      contains ip address
 *  @param  mask
 *      contains mask or subnet ip
 *  @returns void
 *
 */
void calculate_first_address(uint32_t *ip , uint8_t mask)
{
    *ip  =  ntohl(*ip);

    /*find first address*/
    (*ip) &= (0xffffffff << (32 - mask));
}

/** calculate ip and store it ,  if ip_address is * then ip & mask are 0
 *	otherwise binary form of ip_address
 *  @param ip_address
 *      contains ip address in configurations received from server
 *  @param ip
 *      will contains ip
 *  @param  mask
 *     will contains 0 if ip_address is *
 *  @returns void
 *
 */
void store_ip_mask(char* ip_address ,  uint32_t *ip , uint8_t mask)
{
    if(strcmp(ip_address,"*")==0) 
    {
        *ip  =  0;
        mask  =  0;
    }
    else 
    {
        inet_pton(AF_INET , ip_address,(void*)ip);
    }

    SECMON_DEBUG("ip=%d\n",*ip);
}

/** calculate ip and store it ,  if ip_address is * then ip is 0
 *  otherwise binary form of ip_address
 *  @param ip_address
 *      contains ip address in configurations received from server
 *  @param ip
 *      will contains ip
 *  @returns void
 *
 */
void store_ip(char* ip_address ,  uint8_t *ip)
{
    char *address;
    struct in_addr addr;
    if(strcmp(ip_address,"*")==0)
    {
        *ip  =  0;
    }
    else
    {
        inet_pton(AF_INET , ip_address,&addr.s_addr);
        address = inet_ntoa(addr);
        strcpy((char *)ip , address);
    }
}
