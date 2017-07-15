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
 *  	sort collector object according to priority of its rules
 *
 */

#include "client.h"


/** sort the rules in collector object according to their priority
 *  @param collec_obj
 *      contains collector object of which rules will sort
 *  @param  head
 *      contains rules head
 *  @returns void
 *
 */
void sort_acc_priority(struct Collector_object *collec_obj , struct Classification_object *head , char *id)
{
    struct Classification_object *temp , 								/*temp to process rules*/
                                 *previous , 
                                 *node , 
                                 *save;

    save = NULL;
    node = temp = head;

    /*find rule with rule_id ,  id*/
    while(temp!=NULL)
    {
        if(strcmp((char *)temp->rule_id , id) == 0)
        {
            node = temp;
            break; 
        }

        save = temp;
        temp = temp->next;        
    }

    /*list is already sorted*/
    if(save==NULL)
    {
        return;
    }    

    previous = NULL;

    /*sort the list by placing the node with rule_id id at proper place */
    temp = head;
    while(temp!=NULL)
    {
        if((temp->priority) > (node->priority)) 
        {
            if(previous==NULL)
            {
                save->next = node->next;
                node->next = head;
                collec_obj->classification_object = node;
            }
            else
            {
                save->next = node->next;
                node->next = previous->next;
                previous->next = node;
            }
            return;
        }

        previous = temp;
        temp = temp->next;
    }
}


/** take list of collectors or rule ids ,  separate them &
 *	store them individually
 *  @param value
 *      contains list of collectors or rule objects
 *  @param  type
 *      contains RULE	    -list is of list of rule objects
 *				 COLLECTOR	-list is of list of collectors
 *  @returns void
 *
 */
void store_by_id(char *value , char *type)
{
    char store_value[VALUESIZE],
         *token , 
         *delimitor  =  ",\n";

    memset(store_value,'\0',VALUESIZE);
    memcpy(store_value , value , strlen(value));
    token = strtok(store_value , delimitor);

    /*take each id from list*/
    while(token!=NULL)
    {
        /*store each rule object by id*/
        if(strcmp(type , RULE) == 0)
        {
            store_rule_ids(UUID , token);
        }
        /*store each collector by id*/
        else if(strcmp(type , COLLECTOR) == 0)
        {
            store_collector(UUID , token, TRUE);
        }

        token = strtok(NULL , delimitor);
    }

}

