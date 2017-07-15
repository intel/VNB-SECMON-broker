/*
#    Copyright (c) 2016 Intel Corporation.
#    All Rights Reserved.
#
#    Licensed under the Apache License  ,   Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing  ,   software
#    distributed under the License is distributed on an "AS IS" BASIS  ,   WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND  ,   either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
 */

/** @file
 *  contain netflow api to fetch configuration for netflow plugin
 *
 */

#include "client.h"
#include "server.h"
#include <stdbool.h>

char EMS_Address[IP_SIZE];

struct Collector_object *collector_obj_head = NULL;
struct Plugin plugin;
int col_set = COL;
int new_association = OLDASS;


/* Client API exposed to plugin. 
 * 
 * This Function is invoked by plugin at init time
 * to fetch all configurations from EMS.
 *
 * @returns void
 *
 */
void fetch_all_config()
{
    netflow_api();
    /*start server and handle updated notifications*/
    handle_ems_notifications();
}

bool is_ems_available()
{
    return (strcmp(EMS_Address, NOADDRESS) != 0);
}

/* Registers the plugin with EMS and starts server 
 * for handling configurations for netflow plugin
 *
 * @returns void
 */
void netflow_api()
{
    char     scope_name[MAX_ID_LEN],	    /*store scope name*/             
             root_url[ROOT_URL_SIZE];       /*contain root url*/

    char store_add[IP_SIZE],				/*temp to store address*/
         *token , 							/*token to store ip address*/
         *delimitor  =  ":\n";				/*de-limitor*/

    memset(EMS_Address,'\0',IP_SIZE);

    /*take EMS_Address of server & scope name*/
    strncpy(EMS_Address  ,  NOADDRESS , strlen(NOADDRESS));
    read_server_ip_port(scope_name , EMS_Address);

    /*with EMS_Address fetch configurations*/
    if(is_ems_available())
    {
        /*take root url to fetch details*/
        generate_ems_base_url(EMS_Address,&root_url[0]);

        /*fetching all configurations initially if exists*/
        fetch_startup_configurations(root_url , scope_name);

        /*if scope exists , upload server details & start the server*/
        if(strcmp((char *)plugin.scope->name , NOSCOPE) != 0)
        {
            memset(store_add,'\0',IP_SIZE);
            strncpy(&store_add[0],EMS_Address , strlen(EMS_Address));

            token = strtok(store_add , delimitor);

            upload_secmon_details(root_url,(char *)plugin.scope->id , token);
            /*print_configurations();*/
            
        }
        else
        {
            return;
        }
    }
    /*no EMS_Address is provided*/
    else
    {
        SECMON_CRITICAL("ERROR: invalid EMS_Address\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
        return;
    }
}


/* function called by fetch_startup_configurations to initialize plugin
 * @returns void
 *
 */
void initialize_plugin_configurations()
{
    memset(&plugin,'\0',sizeof(struct Plugin));
    plugin.policy = NULL;
    plugin.collector = NULL;
    plugin.association = NULL;
    plugin.collector_set = NULL;
    plugin.ruleobj = NULL;
    plugin.Collec_rule = NULL;
    plugin.scope = NULL;
    plugin.scope=(struct Scope *)malloc(sizeof(struct Scope));
    memset(plugin.scope,'\0',sizeof(struct Scope));
    strncpy((char *)plugin.scope->name , NOSCOPE , sizeof(plugin.scope->name));
}


/** function called by netflow_api function to get scope
 *  & get configurations according to to secmon scope.
 *  @param root_url
 *      contains root_url for plugin
 *  @param scope_name
 *      contains scope name
 *  @returns void
 *
 */
void fetch_startup_configurations(char *root_url , char *scope_name)
{
    initialize_plugin_configurations();

    strncpy((char *)plugin.root_url , root_url , strlen(root_url));
    SECMON_INFO("in fetch_startup_configurations function\n");

    /*fetch scope id & plugin status according to scope name*/
    fetch_scope_id(root_url , scope_name);

    /*if scope exists fetch other configurations*/
    if(strcmp((char *)plugin.scope->name , NOSCOPE) != 0)
    {
        SECMON_INFO("fetch all configurations\n");
        fetch_all_configurations(root_url,(char *)(plugin.scope)->id);
    }
    /*scope not exists*/
    else
    {
        SECMON_CRITICAL("ERROR: incorrect scope name\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
}


