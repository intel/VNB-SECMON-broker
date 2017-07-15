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
 *  find last of node of list ,  returns that otherwise returns null
 *
 */

#include "client.h"


/** find last association of the associations list
 *  @param head
 *      contains head of associations list
 *  @returns 
 *		NULL 		if list is empty
 *		temp		last node of list
 *
 */
struct Association* find_last_association(struct Association *head)
{
    struct Association *temp; 

    temp = head;
    while(temp->next!=NULL)
    {
        temp = temp->next;
    }

    return temp;
}

/** find last collector object of the collector objects list
 *  @param head
 *      contains head of collector objects list
 *  @returns 
 *      NULL    if list is empty
 *      temp    last node of list
 *
 */
struct Collector_object* find_last_collector_obj(struct Collector_object *head)
{
    struct Collector_object *temp;

    temp = head;
    while(temp->next!=NULL)
    {
        temp = temp->next;
    }

    return temp;
}

/** find last collector of the collectors list
 *  @param head
 *      contains head of collectors list
 *  @returns 
 *      NULL    if list is empty
 *      temp    last node of list
 *
 */
struct Collector* find_last_collector(struct Collector *head)
{
    struct Collector* temp;

    temp = head;
    while(temp->next!=NULL)
    {
        temp = temp->next;
    }

    return temp;
}

/** find last policy of the policies list
 *  @param head
 *      contains head of policies list
 *  @returns 
 *      NULL    if list is empty
 *      temp    last node of list
 *
 */
struct Policy* find_last_policy(struct Policy *head)
{
    struct Policy* temp;

    temp = head;
    while(temp->next!=NULL)
    {
        temp = temp->next;
    }

    return temp;
}

/** find last rule of the rules list
 *  @param head
 *      contains head of rules list
 *  @returns 
 *      NULL    if list is empty
 *      temp    last node of list
 *
 */
struct Classification_object* find_last_rule(struct Classification_object *head)
{
    struct Classification_object* temp;

    temp = head;
    while(temp->next!=NULL)
    {
        temp = temp->next;
    }

    return temp;
}

/** find last rule object of the rule objects list
 *  @param head
 *      contains head of rule objects list
 *  @returns 
 *      NULL    if list is empty
 *      temp    last node of list
 *
 */
struct Rules* find_last_rule_id(struct Rules *head)
{   
    struct Rules *temp;

    temp = head;
    while(temp->next!=NULL)
    {
        temp = temp->next;
    }

    return temp;
}

/** find last collector set of the collector sets list
 *  @param head
 *      contains head of collector sets list
 *  @returns 
 *      NULL    if list is empty
 *      temp    last node of list
 *
 */
struct Collector_set* find_last_collector_set(struct Collector_set *head)
{   
    struct Collector_set *temp;

    temp = head;
    while(temp->next!=NULL)
    {
        temp = temp->next;
    }

    return temp;
}


/** find association having id equal to required id from the associations list
 *  @param head
 *      contains head of associations list
 *  @param id
 *      contains id of association
 *  @returns 
 *      NULL    if no node with id
 *      temp    node having the required id
 *
 */
struct Association* association_node_of_id(struct Association *head , char* id)
{
    struct Association *temp;

    temp = head;

    while(temp!=NULL)
    {
        if(strcmp((char *)temp->id , id) == 0)
        {
            return temp;
        }

        temp = temp->next;
    }

    return NULL;
}

/** find collector having id equal to required id from the collectors list
 *  @param head
 *      contains head of collectors list
 *  @param id
 *      contains id of collector
 *  @returns 
 *      NULL    if no node with id
 *      temp    node having the required id
 *
 */
struct Collector* collector_node_of_id(struct Collector *head , char* id)
{
    struct Collector *temp;

    temp = head;
    while(temp!=NULL)
    {
        if(strcmp((char *)temp->id , id) == 0)
        {
            return temp;
        }

        temp = temp->next;
    }

    return NULL;
}

/** find policy having id equal to required id from the policies list
 *  @param head
 *      contains head of policies list
 *  @param id
 *      contains id of policy
 *  @returns 
 *      NULL    if no node with id
 *      temp    node having the required id
 *
 */
struct Policy* policy_node_of_id(struct Policy *head , char* id)
{
    struct Policy *temp;

    temp = head;
    while(temp!=NULL)
    {
        if(strcmp((char *)temp->id , id) == 0)
        {
            return temp;
        }

        temp = temp->next;
    }

    return NULL;
}

/** find rule having id equal to required id from the rules list
 *  @param head
 *      contains head of rules list
 *  @param id
 *      contains id of rule
 *  @returns 
 *      NULL    if no node with id
 *      temp    node having the required id
 *
 */
struct Classification_object* rule_node_of_id(
        struct Classification_object *head , char* id)
{
    struct Classification_object *temp;

    temp = head;
    while(temp!=NULL)
    {
        if(strcmp((char *)temp->rule_id , id) == 0)
        {
            return temp;
        }

        temp = temp->next;
    }

    return NULL;
}

/** find rule object having id equal to required id from the rule objects list
 *  @param head
 *      contains head of objects list
 *  @param id
 *      contains id of object
 *  @returns 
 *      NULL    if no node with id
 *      temp    node having the required id
 *
 */
struct Rules* rule_id_node_of_id(struct Rules *head , char* id)
{
    struct Rules *temp;

    temp = head;
    while(temp!=NULL)
    {
        if(strcmp((char *)temp->rule_id , id) == 0)
        {
            return temp;
        }

        temp = temp->next;
    }

    return NULL;
}

/** find collector set having id equal to required id from the collector sets list
 *  @param head
 *      contains head of collector sets list
 *  @param id
 *      contains id of collector set
 *  @returns 
 *      NULL    if no node with id
 *      temp    node having the required id
 *
 */
struct Collector_set* collector_set_node_of_id(struct Collector_set *head , char* id)
{
    struct Collector_set *temp;

    temp = head;
    while(temp!=NULL)
    {
        if(strcmp((char *)temp->id , id) == 0)
        {
            return temp;
        }

        temp = temp->next;
    }

    return NULL;
}

/** find collector associated to required policy &
 *	then by collector ,  find collector object
 *  @param p_id
 *      contains policy id 
 *  @returns 
 *      NULL    		if no collector associated to policy or 
 *											no collector object with the collector
 *      Collec_obj	collector object with collector associated to policy
 *
 */
struct Collector_object* find_collector_by_rules(char *p_id)
{
    char collector_id[MAX_ID_LEN];
    struct Collector_object *Collec_obj;

    memset(collector_id,'\0',MAX_ID_LEN);
    strcpy(collector_id , NOCOLLECTORID);

    find_collector_by_policy(p_id,&collector_id[0]);

    /*no collector with policy*/
    if(strcmp(collector_id , NOCOLLECTORID) == 0)
    {
        SECMON_INFO("No collector is there according to policy\n");
        return NULL;
    }

    Collec_obj = find_collector_obj_by_collector_id(collector_id);

    /*no collector object with collector*/
    if(Collec_obj==NULL)
    {
        SECMON_INFO("No collector object is there\n");
        return NULL;
    }

    return Collec_obj;

}

/** find collector associated to policy
 *  @param p_id
 *      contains policy id 
 *  @param collector_id
 *      will contains collector_id associated to policy if exists
 *  @returns void
 *
 */
void find_collector_by_policy(char *p_id , char *collector_id)
{
    struct Association *head , 
                       *temp;
    head = plugin.association;

    temp = head;
    while(temp!=NULL)
    {
        if(strcmp((char*)temp->policy_id , p_id) == 0)
        {
            memset(collector_id,'\0',MAX_ID_LEN);
            strncpy(collector_id,(char *)temp->collector_id , strlen((char *)temp->collector_id));   
            return;
        }

        temp = temp->next;
    }

    return;

}

/** find collector object according to collector as per collector_id
 *  @param collector_id
 *      contains collector id 
 *  @returns 
 *      NULL        if no collector object with the collector
 *      Collec_obj  collector object contains collector with collector_id
 *
 */
struct Collector_object* find_collector_obj_by_collector_id(char *collector_id)
{
    struct Collector_object *coll_obj , 
                            *head;

    head = plugin.Collec_rule;
    coll_obj = head;

    while(coll_obj!=NULL)
    {
        if(strcmp((char *)(coll_obj->collector)->id , collector_id) == 0)
        {
            return coll_obj;
        }

        coll_obj = coll_obj->next;
    }

    return NULL;
}

