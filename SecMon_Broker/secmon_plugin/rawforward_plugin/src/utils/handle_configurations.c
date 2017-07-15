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
 *  fetch scope details & check if its enable fetch all other configurations for plugin
 *	and get response ,  call the parser to handle it
 *
 */

#include "client.h"


/** check the status of rawforward plugin according to scope & if its enable
 *	then fetch associations & all other configurations ,  
 *	called by fetch_startup_configurations or after updating scope
 *  @param root_url
 *      contains root url use to fetch details
 *  @param  scope_id
 *      contains scope id contains scope of secmon
 *  @returns void
 *
 */
void fetch_all_configurations(char *root_url , char *scope_id)
{
    /*plugin is disabled*/
    if(strcmp((char *)plugin.status , DISABLED) == 0)
    {
        SECMON_INFO("plugin is disabled.\n");
        return;
    }

    /*fetch associations*/
    fetch_associations(root_url , scope_id);

}

/**	fetch all associations for rawforward plugin according to scope
 *  called by fetch_all_configurations 
 *  @param root_url
 *      contains root url use to fetch details
 *  @param  scope_id
 *      contains scope id contains scope of secmon
 *  @returns void
 *
 */
void fetch_associations(char* root_url , char *scope_id)
{
    bool is_first_collector;
    char* response ,                                /*store response from server*/
        url[URL_SIZE];       					  /*contain complete url*/ 
    struct Association  *ass_head , 				  /*temp to process associations*/
                        *ass_temp;                 
    memset(url,'\0',URL_SIZE);

    /*get response after fetching all associations*/
    response = get_conf_from_ems(root_url,&url[0], THREETAGS , PLUGINASSOCIATION , SCOPEID,(char *)plugin.scope->id);
    memset(plugin.url,'\0',strlen((char *)plugin.url));
    strncpy((char *) plugin.url , url , strlen(url));

    /*if error in response*/
    if(strcmp(response , ERROR) == 0)
    {
        return;
    }
    /*parse the json response*/
    parse_json_response(response , ASSOCIATION);
    /*fetch other configurations according to association*/
    ass_head = plugin.association;

    ass_temp = ass_head;
    while(ass_temp!=NULL)
    {
        is_first_collector = TRUE;
        /*fetch collector set details*/
        if(strcmp((char *)ass_temp->collector_set_id,"") != 0)
        {
            struct Collector_set *collector_set;
            struct Collector *collector, *collector_temp;
            SECMON_INFO("\ncollector set\n");
            //struct Collector_object *cobj;
            collector_set = fetch_collector_set_by_id(root_url,(char *)ass_temp->collector_set_id);
            collector_temp = collector_set->collectors; 
            while(collector_temp != NULL)
            {
                //printf("collector temp= %p\n",collector_temp);
                collector = fetch_collector_by_id(root_url,(char *)collector_temp->id, TRUE);
                store_collector_set_obj(collector, is_first_collector); 
                is_first_collector = FALSE;
                collector_temp = collector_temp->next;
            }
        }
        else
        {
            SECMON_DEBUG("it is collector not collector set\n");
            struct Collector *collector;
            collector = fetch_collector_by_id(root_url,(char *)ass_temp->collector_id, FALSE);
            store_collector_obj(collector);
        }
        SECMON_DEBUG("fetching policy\n");
        /*fetch policy details*/
        fetch_policy_by_id(root_url,(char *)ass_temp->policy_id);
        SECMON_DEBUG("fetched policy\n");

        ass_temp = ass_temp->next;
    }

    /*print all collector object details*/
    collector_obj_head = plugin.Collec_rule;
    if(collector_obj_head==NULL)
    {
        SECMON_INFO("no collector with rules\n");
    }

    if(response!=NULL)
    {
        free(response);
        response = NULL;
    }
}

/** fetch association corresponding to id for rawforward plugin 
 *	called when updating or adding a new association 
 *  @param root_url
 *      contains root url use to fetch details
 *  @param  id
 *      contains id of association ,  need to fetch
 *  @param  scope_id
 *      contains scope id contains scope of secmon
 *  @returns void
 *
 */
void fetch_association_by_id(char* root_url , char* id , char *scope_id)
{
    char* response ,                                /*store response from server*/
        url[URL_SIZE];  						  /*contain complete url*/
    struct Association *ass_temp ,                  /*temp to process associations*/
                       *head;                   	
    memset(url,'\0',URL_SIZE);

    /*get response after fetching association*/
    response = get_conf_from_ems(root_url,&url[0],TWOTAGS , PLUGINASSOCIATION , id);
    memset(plugin.url,'\0',strlen((char *)plugin.url));
    strncpy((char *) plugin.url , url , strlen(url));

    /*if error in response*/
    if(strcmp(response , ERROR) == 0)
    {
        return;
    }
    /*parse the json response*/
    parse_json_response(response , ADDASSOCIATION);

    /*fetch others configurations according to association*/
    head  =  plugin.association;
    ass_temp  =  association_node_of_id(head , id);

    /*no association with this id*/
    if(ass_temp == NULL)
    {
        SECMON_INFO("no association with this id\n");
        return;
    }

    /*no newly added association*/
    if((ass_temp->next!=NULL) || (new_association==OLDASS))
    {
        return;
    }
    if(strcmp((char *)ass_temp->collector_set_id,"") != 0)
    {
        bool is_first_collector = TRUE; 
        struct Collector_set *collector_set;
        struct Collector *collector, *collector_temp;
        SECMON_INFO("\ncollector set\n");
        collector_set = fetch_collector_set_by_id(root_url,(char *)ass_temp->collector_set_id);
        collector_temp = collector_set->collectors; 
        while(collector_temp != NULL)
        {
            //printf("collector temp= %p\n",collector_temp);
            collector = fetch_collector_by_id(root_url,(char *)collector_temp->id, TRUE);
            //printf("collector =%p\n",collector);
            store_collector_set_obj(collector, is_first_collector); 
            is_first_collector = FALSE;
            collector_temp = collector_temp->next;
        }
    }
    else
    {
        SECMON_DEBUG("it is collector not collector set\n");
        struct Collector *collector;
        collector = fetch_collector_by_id(root_url,(char *)ass_temp->collector_id, FALSE);
        store_collector_obj(collector);
    }

    /*fetch policy details*/
    fetch_policy_by_id(root_url,(char *)ass_temp->policy_id);

    collector_obj_head = plugin.Collec_rule;

    if(response!=NULL)
    {
        free(response);
        response = NULL;
    }
}

/** store collectors and than fetch collector corresponding to id for rawforward plugin 
 *  called after fetching association
 *  @param root_url
 *      contains root url use to fetch details
 *  @param  id
 *      contains id of collector ,  need to fetch
 *  @param  is_collector_set
 *      flag to denote that collector to fetch is inside collector set or not
 *  @returns
 *      collector which is requested otherwise NULL
 */
struct Collector* fetch_collector_by_id(char* root_url , char* id, bool is_collector_set)
{
    char* response ,                                /*store response from server*/
        url[URL_SIZE];       					  /*contain complete url*/
    struct Collector *head , 						  /*temp to process collectors*/
                     *obj;
    //printf("inside fetch_collector_by_id\n");
    memset(url,'\0',URL_SIZE);

    /*get response after fetching collector*/
    response = get_conf_from_ems(root_url,&url[0],TWOTAGS , COLLECTOR,(char *)id);
    memset(plugin.url,'\0',strlen((char *)plugin.url));
    strncpy((char *) plugin.url , url , strlen(url));

    /*if error in response*/
    if(strcmp(response , ERROR) == 0)
    {
        return NULL;
    }

    col_set = COL;

    if(is_collector_set) 
        parse_json_response(response, COLLECTOR_SET_ARRAY);
    else
        parse_json_response(response , COLLECTOR);

    if(is_collector_set)
    {
        head = find_last_collector_set(plugin.collector_set)->collectors;
    }
    else
        head = plugin.collector;
    //printf("head = %p\n", head);

    obj = collector_node_of_id(head , id);
    //printf("obj->ip = %s\n", obj->ip.dst_addr);

    if(response!=NULL)
    {
        free(response);
        response = NULL;
    }
    return obj;
}

/** fetch policy corresponding to id for rawforward plugin 
 *  called after fetching association
 *  @param root_url
 *      contains root url use to fetch details
 *  @param  id
 *      contains id of policy ,  need to fetch
 *  @returns void
 *
 */
void fetch_policy_by_id(char* root_url , char* id)
{
    char* response ,                                /*store response from server*/
        url[URL_SIZE];       					  /*contain complete url*/
    struct Policy *temp ,                           /*to traverse associations*/
                  *head;                   		  /*list*/
    struct Collector_object *collec_obj , 		  /*temp to process collector objects*/
                            *collec_head , 
                            *collec_end;

    memset(url,'\0',URL_SIZE);

    /*get response after fetching policy*/
    response = get_conf_from_ems(root_url,&url[0],TWOTAGS , POLICY,(char *)id);
    memset(plugin.url,'\0',strlen((char *)plugin.url));
    strncpy((char *) plugin.url , url , strlen(url));

    /*if error in response*/
    if(strcmp(response , ERROR) == 0)
    {
        return;
    }

    plugin.ruleobj = NULL;
    parse_json_response(response , POLICY);

    /*no rule ids in policy*/
    if(plugin.ruleobj==NULL)
    {
        SECMON_INFO("rules is null\n");
    }

    head = plugin.policy;

    temp = policy_node_of_id(head , id);

    /*policy not exist with this id*/
    if(temp==NULL)
    {
        SECMON_INFO("no policy to fetch rules \n");
        return ;
    }
    /*if policy is associated with other association also*/
    if(temp->next!=NULL)
    {
        collec_head = plugin.Collec_rule;
        
        collec_end = find_last_collector_obj(collec_head);
        collec_obj = find_collector_by_rules(id);

        collec_end->classification_object = collec_obj->classification_object;

        return;
    }

    /*fetch rules in policies*/
    temp->rule_ids = plugin.ruleobj;
    fetch_all_policy_rules(temp , root_url);

    if(response!=NULL)
    {
        free(response);
        response = NULL;
    }
}

/** fetch all rule objects of policy ,  for rawforward plugin 
 *  called by policy
 *  @param  p_temp
 *      contains policy contains rule objects ids
 *  @param root_url
 *      contains root url use to fetch details
 *  @returns void
 *
 */
void fetch_all_policy_rules(struct Policy *p_temp , char *root_url)
{
    struct Rules *col_obj_temp;                   /*to traverse rules*/

    /*fetching rules for policy*/
    col_obj_temp = p_temp->rule_ids;

    while(col_obj_temp!=NULL)
    {
        fetch_rule_obj_by_id(p_temp , root_url,(char *)col_obj_temp->rule_id);

        col_obj_temp = col_obj_temp->next;
    }

}

/** fetch rule object of policy ,  for rawforward plugin 
 *  @param  p_temp
 *      contains policy contains rule objects ids
 *  @param root_url
 *      contains root url use to fetch details
 *	@param 	id
 *			contains id of rule object
 *  @returns void
 *
 */
void fetch_rule_obj_by_id(struct Policy *p_temp ,  char* root_url , char* id)
{
    char* response ,                                /*store response from server*/
        url[URL_SIZE];       					  /*contain complete url*/
    struct Rules *loc ,              				  /*temp to process all rules*/
                 *head;             

    memset(url,'\0',URL_SIZE);

    /*get response after fetching rule object*/
    response = get_conf_from_ems(root_url,&url[0],TWOTAGS , RULE,(char *)id);
    memset(plugin.url,'\0',strlen((char *)plugin.url));
    strncpy((char *) plugin.url , url , strlen(url));

    /*if error in response*/
    if(strcmp(response , ERROR) == 0)
    {
        return;
    }

    parse_json_response(response , RULE);

    head = p_temp->rule_ids;
    loc = rule_id_node_of_id(head , id);

    /*no rule object with this id*/
    if(loc==NULL)
    {
        SECMON_INFO("no rule_object with this id\n");
        return;
    }

    /*fetch rule*/
    fetch_rule_by_id(loc , root_url,(char *)loc->Classification_id);

    if(response!=NULL)
    {
        free(response);
        response = NULL;
    }
}

/** fetch rule of policy ,  for rawforward plugin 
 *  called by rule object
 *  @param  rule
 *      contains rule object contains rule
 *  @param root_url
 *      contains root url use to fetch details
 *  @param  id
 *      contains id of rule object
 *  @returns void
 *
 */
void fetch_rule_by_id(struct Rules *rule , char* root_url , char* id)
{
    char* response ,                                /*store response from server*/
        url[URL_SIZE];   						  /*contain complete url*/
    struct Classification_object *loc ,      		  /*temp to process rules*/
                                 *head;     
    struct Collector_object     *collec_obj ,       /*temp to process collector objects*/
                                *collec_head;

    memset(url,'\0',URL_SIZE);

    /*get response after fetching rule*/
    response = get_conf_from_ems(root_url,&url[0],TWOTAGS , CLASSIFICATION,(char *)id);
    memset(plugin.url,'\0',strlen((char *)plugin.url));
    strncpy((char *) plugin.url , url , strlen(url));

    /*if error in response*/
    if(strcmp(response , ERROR) == 0)
    {
        return;
    }

    parse_json_response(response , CLASSIFICATION);

    collec_head = plugin.Collec_rule;
    if(collec_head != NULL)
    {
        collec_obj = find_last_collector_obj(collec_head);
    }
    else
    {
       SECMON_DEBUG("collec_head is null \n"); 
    }

    head = collec_obj->classification_object;    
    loc = rule_node_of_id(head , id);

    /*if rule exist in collector object then add details in rule object
      to rule*/
    if(loc!=NULL)
    {
        loc->action = rule->action;
        loc->priority = rule->priority;
        loc->truncate_to_size = rule->truncate_to_size;

        sort_acc_priority(collec_obj , head , id);
        return;
    }

    if(response!=NULL)
    {
        free(response);
        response = NULL;
    }
}

/** fetch collector set corresponding to id for rawforward plugin 
 *  called after fetching association
 *  @param root_url
 *      contains root url use to fetch details
 *  @param  id
 *      contains id of collector set ,  need to fetch
 *  @returns
 *      collector set requested otherwise NULL
 */
struct Collector_set *fetch_collector_set_by_id(char* root_url , char* id)
{
    char* response ,                            /*store response from server*/
        url[URL_SIZE];    					  /*contain complete url*/
    struct Collector_set *obj; 				  /*temp to process collector sets*/
                         
 
    memset(url,'\0',URL_SIZE);

    /*get response after fetching collector set*/
    response = get_conf_from_ems(root_url,&url[0],TWOTAGS , COLLECTORSET,(char *)id);
    memset(plugin.url,'\0',strlen((char *)plugin.url));
    strncpy((char *) plugin.url , url , strlen(url));

    /*if error in response*/
    if(strcmp(response , ERROR) == 0)
    {
        return NULL;
    }

    parse_json_response(response , COLLECTORSET);

    //head = plugin.collector_set;
    obj = collector_set_node_of_id(plugin.collector_set, id);
    //plugin.collector_set = head;
    if(response!=NULL)
    {
        free(response);
        response = NULL;
    }
    return obj;
}

/** fetch collector set corresponding to id for rawforward plugin 
 *  called after fetching association
 *  @param root_url
 *      contains root url use to fetch details
 *  @param  id
 *      contains id of collector set ,  need to fetch
 *  @returns void
 *
 */
void fetch_scope_id(char *root_url , char *scope_name)
{
    char* response ,           /*store response from server*/
        url[URL_SIZE];       /*contain complete url*/

    memset(url,'\0',URL_SIZE);

    /*get response after fetching scope*/
    response = get_conf_from_ems(root_url,&url[0], THREETAGS , SCOPE , NAME , scope_name);
    memset(plugin.url,'\0',strlen((char *)plugin.url));
    strncpy((char *) plugin.url , url , strlen(url));

    /*if error in response*/
    if(strcmp(response , ERROR) == 0)
    {
        return;
    }

    parse_json_response(response , SCOPE);

    /*update the status in plugin*/
    if(strcmp((char *)plugin.status , DISABLED) == 0)
    {
        update_status(FALSE);
    }   
    else
    {
        update_status(TRUE);
    }

    if(response!=NULL)
    {
        free(response);
        response = NULL;
    }
}



/** free all configurations stored
 *  @returns void
 *
 */
void free_configurations()
{
    struct Collector *collector1,*coll_temp;
    struct Policy *policy1,*pol_temp;
    struct Association *association1,*ass_temp;
    struct Collector_set *collector_set1,*col_set_temp;
    struct Rules *ruleobj1,*rule_temp;
    struct Collector_object *Collec_rule1,*col_obj_temp;
    struct Classification_object *classification_object1,*class_temp;

    /*free all associations*/
    ass_temp = plugin.association;
    while(ass_temp!=NULL)
    {
        association1 = ass_temp;
        ass_temp = ass_temp->next;

        if(association1!=NULL)
        {
            free(association1);
            association1 = NULL;
        }
    } 

    /*free all collector sets*/
    col_set_temp = plugin.collector_set;
    while(col_set_temp!=NULL)
    {
        collector_set1 = col_set_temp;
        col_set_temp = col_set_temp->next;

        if(collector_set1!=NULL)
        {
            free(collector_set1);
            collector_set1 = NULL;
        }
    }

    /*free all collectors*/
    coll_temp = plugin.collector;
    while(coll_temp!=NULL)
    {
        collector1 = coll_temp;
        coll_temp = coll_temp->next;

        if(collector1!=NULL)
        {
            free(collector1);
            collector1 = NULL;
        }
    }

    /*free all policies*/
    pol_temp = plugin.policy;
    while(pol_temp!=NULL)
    {
        policy1 = pol_temp;
        pol_temp = pol_temp->next;

        /*free all rule objects*/
        rule_temp = policy1->rule_ids;
        while(rule_temp!=NULL)
        {
            ruleobj1 = rule_temp;
            rule_temp = rule_temp->next;

            if(ruleobj1!=NULL)
            {
                free(ruleobj1);
                ruleobj1 = NULL;
            }
        }

        if(policy1!=NULL)
        {	
            free(policy1);
            policy1 = NULL;
        }
    }

    /*free all collector objects*/
    col_obj_temp = plugin.Collec_rule;
    while(col_obj_temp!=NULL)
    {
        Collec_rule1 = col_obj_temp;
        col_obj_temp = col_obj_temp->next;

        /*free collector in collector objects*/
        coll_temp = Collec_rule1->collector;
        while(coll_temp!=NULL)
        {
            collector1 = coll_temp;
            coll_temp = coll_temp->next;

            if(collector1!=NULL)
            {
                free(collector1);
                collector1 = NULL;
            }
        }

        /*free rules*/
        class_temp = Collec_rule1->classification_object;
        while(class_temp!=NULL)
        {
            classification_object1 = class_temp;
            class_temp = class_temp->next;

            if(classification_object1!=NULL)
            {
                free(classification_object1);
                classification_object1 = NULL;
            }
        }

        if(Collec_rule1!=NULL)
        {
            free(Collec_rule1);
            Collec_rule1 = NULL;
        }
    }

    if(plugin.scope!=NULL)
    {
        free(plugin.scope);
        plugin.scope = NULL;
    }

}

/* print all configurations stored for rawforward plugin
 * @returns void
 */
void print_configurations(void)
{
    struct Association *ass_head , 				  /*temp for print association*/
                       *ass_obj; 
    struct  Collector *coll_head , 				  /*temp for print collector*/
                      *coll_obj;
    struct Classification_object *classotemp ,      /*temp for print rules*/
                                 *head;    
    struct Collector_object     *collec_obj ,       /*temp for collector objects*/
                                *collec_head;
    /*if no configurations*/
    if(collector_obj_head==NULL)
    {
        SECMON_INFO("\nno collector with rules to print\n");
        return;
    }

    /*print all configurations*/
    ass_head = plugin.association;
    ass_obj = ass_head;

    while(ass_obj!=NULL)
    {
        SECMON_DEBUG("ass id=%s\n",ass_obj->id);
        ass_obj = ass_obj->next;
    }

    coll_head = plugin.collector;

    coll_obj = coll_head;
    while(coll_obj!=NULL)
    {
        SECMON_DEBUG("ids=%s\n",coll_obj->id);
        coll_obj = coll_obj->next;
    }

    SECMON_DEBUG("\n\nprint collector with rules\n");

    collec_head = collector_obj_head;

    collec_obj = collec_head;
    while(collec_obj!=NULL)
    {
        SECMON_DEBUG("\ncollector details id =  %s\n",collec_obj->collector->id);
        SECMON_DEBUG("name %s\n",collec_obj->collector->name);
        SECMON_DEBUG("ip %s\n",collec_obj->collector->ip.dst_addr);
        SECMON_DEBUG(" port %d\n",collec_obj->collector->port);
        SECMON_DEBUG(" protocol %d\n",collec_obj->collector->encap_protocol);

        SECMON_DEBUG("socket handle=%d server length=%d\n",collec_obj->socket , collec_obj->server_length);
        SECMON_DEBUG("socket family=%d\n",collec_obj->server_address.sin_family);
        SECMON_DEBUG("socket port=%d\n",collec_obj->server_address.sin_port);

        head = collec_obj->classification_object;

        SECMON_DEBUG("rules  details\n");
        classotemp = head;
        while(classotemp!=NULL)
        {
            SECMON_DEBUG("rule details\n name=%s\n",(char *)classotemp->name);
            SECMON_DEBUG("id=%s\n",(char *)classotemp->rule_id);

            SECMON_DEBUG("src mac=%x\n",classotemp->src_mac[0]);
            SECMON_DEBUG("dst mac=%x\n",classotemp->dst_mac[0]);

            SECMON_DEBUG("src ip=%d\n",classotemp->src_ip);
            SECMON_DEBUG("dest ip=%d\n",classotemp->dst_ip);

            SECMON_DEBUG("min src ip=%d\n",(int)classotemp->min_src_port);
            SECMON_DEBUG("max src ip=%d\n",(int)classotemp->max_src_port);
            SECMON_DEBUG("min dst ip=%d\n",(int)classotemp->min_dst_port);
            SECMON_DEBUG("max dst ip=%d\n",(int)classotemp->max_dst_port);

            SECMON_DEBUG("src ip sub=%d\n",(int)classotemp->src_ip_subnet);
            SECMON_DEBUG("dst ip sub=%d\n",(int)classotemp->dst_ip_subnet);

            SECMON_DEBUG(" action=%d\n",classotemp->action);
            SECMON_DEBUG(" prio=%d\n",classotemp->priority);
            SECMON_DEBUG("protocol=%d\n",classotemp->protocol);
            SECMON_DEBUG("trunc=%d\n",classotemp->truncate_to_size);

            classotemp = classotemp->next;
        }
        collec_obj = collec_obj->next;
    }

}

/**
 *  find collector details inside collector set
 *  @param  cobj
 *      collector objects list
 *  @param  id
 *      id of the collector details for which list to be searched
 *  @returns
 *      collector details containing details of collector
 */
struct Collector_details *find_collector_set_by_id(struct Collector_object *cobj, char *id)
{
    struct Collector_details *col_details;
    struct Collector_object *cobj_tmp = cobj;
    while(cobj_tmp !=NULL)
    {
        col_details = cobj_tmp->collector_details;
        SECMON_DEBUG("Searching Collector object\n");
        while(col_details != NULL)
        {
            SECMON_DEBUG("searching for id... %s, id = %s\n",col_details->id, id);
            if(strcmp((char *)col_details->id, id) == 0)
            {
                SECMON_DEBUG("id matched...\n");
                return col_details;
            }
            col_details = col_details->next;
        }
        cobj_tmp = cobj_tmp->next;
    }
    return NULL;
}

/**
 *  finds last collector detail object
 *  @param  col_details_head
 *      collector details list of which last element to fetched
 *  @returns
 *      collector details of the last element in collector details list passed
 */
inline struct Collector_details *find_last_collector_details_obj(struct Collector_details *col_details_head)
{
    struct Collector_details *col_details_tmp = col_details_head;
    while(col_details_tmp->next != NULL)
        col_details_tmp = col_details_tmp->next;
    return col_details_tmp;
}
