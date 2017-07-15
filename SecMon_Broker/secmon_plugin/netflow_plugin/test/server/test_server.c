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
 *  initialize plugin & start server
 *
 */

#include "test.h"

struct Plugin plugin;

/** client function to initialize plugin
 *  @returns void
 *
 */
void initialize_plugin_configurations()
{
    memset(&plugin,'\0',sizeof(struct Plugin));
    plugin.Collec_rule = NULL;
    plugin.policy = NULL;
    plugin.collector = NULL;
    plugin.association = NULL;
    plugin.collector_set = NULL;
    plugin.ruleobj = NULL;
    plugin.Collec_rule = NULL;
    plugin.scope = NULL;
    plugin.scope=(struct Scope *)malloc(sizeof(struct Scope));
    memset(plugin.scope,'\0',sizeof(struct Scope));
    strcpy( (char *)plugin.scope->id,"f1234");
}

/**	initialize plugin & start server to receive notifications
 *
 */
int main()
{
    initialize_plugin_configurations();
    handle_ems_notifications();

    return SUCCESS;
}
