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
 *  stubs for client api to handle the notification
 *
 */

#include "test.h"

/** for addition notification*/
void fetch_add_association(char *id)
{
    printf( "\n\tclient stub api to fetch & add association with id=%s in configuration\n",id);
}

/** for updating notification*/
void update_scope()
{
    printf( "\n\tclient stub api to update scope (status of plugin)\n");
}

void fetch_update_association(char *id)
{
    printf( "\n\tclient stub api to update association with id=%s in configuration\n",id);
}

void fetch_update_collector(char *id)
{
    printf( "\n\tclient stub api to update collector with id=%s in configuration\n",id);
}

void fetch_update_policy(char *id)
{
    printf( "\n\tclient stub api to update policy with id=%s in configuration\n",id);
}

void fetch_update_rule_ids(char *id)
{
    printf( "\n\tclient stub api to update rule object with id=%s in configuration\n",id);
}

void fetch_update_rule(char *id)
{
    printf( "\n\tclient stub api to update rule with id=%s in configuration\n",id);
}

/** for deletion notification*/
void delete_association(char *id)
{
    printf( "\n\tclient stub api to delete association with id=%s from configuration\n",id);
}

void delete_collector(char *id)
{
    printf( "\n\tclient stub api to delete collector with id=%s from configuration\n",id);
}

void delete_rule_ids(char *id)
{
    printf( "\n\tclient stub api to delete rule object with id=%s from configuration\n",id);
}

void delete_rule(char *id)
{
    printf( "\n\tclient stub api to delete rule with id=%s from configuration\n",id);
}

/** client stub api to print configurations
 *
 */
void print_configurations()
{
}

/** stub to update netflow monitor in client*/
void update_netflow_monitor()
{
    printf( "\n\tclient stub api to update netflow monitor \n");
}

/** stub to update netflow config in client*/
void update_netflow_config()
{
    printf( "\n\tclient stub api to update netflow config \n");
}

/** stub to update sflow config in client*/
void update_sflow_config()
{
    printf( "\n\tclient stub api to update sflow config\n");
}

