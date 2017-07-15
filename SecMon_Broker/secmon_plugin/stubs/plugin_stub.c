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
 *  stubs for plugin to handle configuration
 *
 */
#include "test.h"

/** flush hash table*/
void flush_hash_table()
{
    printf( "\n\tplugin stub api to flush hash table for rawforward plugin\n");
}

void flush_netflow_hash_table()
{
    printf( "\n\tplugin stub api to flush netflow hash table for netflow plugin\n");
}

void flush_sflow_hash_table()
{
    printf( "\n\tplugin stub api to flush sflow hash table for netflow plugin\n");
}

/** plugin to update status of plugin*/
void update_status(bool status)
{
    printf( "\n\tplugin stub api to update status in rawforward plugin\n");
}

void update_sflow_status(bool status)
{
    printf( "\n\tplugin stub api to update status in sflow plugin\n");
}

void update_netflow_status(bool status)
{
    printf( "\n\tplugin stub api to update status in netflow plugin\n");
}


/** stub to process config */
int process_conf_params(char *add ,  uint32_t agent_subid ,  uint32_t sampling_rate , int truncate_to_size)
{
    printf("process configuration to update sflow\n");
    return SUCCESS;
}

/** stub for adding collector to sflow plugin*/
int add_sflow_collector(char *ptr ,  uint32_t port)
{
    printf("add collector to sflow plugin\n");
    return SUCCESS;	
}
/** stub to add netflow params*/
int add_netflow_monitor_params(int match ,  int collect)
{
    printf("add monitor params to netflow plugin\n");
    return SUCCESS;
}

/** stub to add collector as destination in netflow plugin*/
int add_netflow_destination(char *ptr ,  uint32_t port)
{
    printf("add collector details to destination list in netflow plugin\n");
    return SUCCESS;
}

/** stub to add collector as destination in netflow plugin*/
void delete_netflow_destination(char *ptr ,  uint32_t port)
{
    printf("delete collector details from destination list in netflow plugin\n");
}

/** change config of netflow plugin*/
int netflow_config(int a_to ,  int i_to ,  unsigned int r_rate ,  unsigned int t_rate ,  unsigned int max_flows)
{
    printf("change configuration of netflow plugin as per data supplied\n");
    return SUCCESS;
}

