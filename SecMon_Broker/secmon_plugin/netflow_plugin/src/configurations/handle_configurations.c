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
 *	to add new association to configurations  
 *
 */

#include "client.h"



/**	delete all configurations stored ,  called when plugin is disable
 *  @returns void
 *
 */
void delete_all_configurations()
{
    struct Association *ass_temp,*ass_obj;			/*temp to delete associations*/
    struct Collector *coll_temp,*coll_obj;			/*temp to delete collectors*/
    struct Policy *p_temp,*p_obj;					/*temp to delete policies*/
    struct Collector_set *coll_set;					/*temp to delete collector sets*/
    struct Collector_object *coll_rule;				/*temp to delete collector objects*/

    /*delete all netflow monitor and config*/
    delete_netflow_monitor();
    delete_netflow_config();

    /*delete all polices*/
    p_temp = plugin.policy;
    while(p_temp!=NULL)
    {
        p_obj = p_temp;   
        p_temp = p_temp->next;

        delete_policy((char *)p_obj->id);
    }

    /*delete all collectors*/
    coll_temp = plugin.collector;
    while(coll_temp!=NULL)
    {
        coll_obj = coll_temp;
        coll_temp = coll_temp->next;

        delete_collector((char *)coll_obj->id);
    }

    /*delete all associations*/
    ass_temp = plugin.association;
    while(ass_temp!=NULL)
    {   
        ass_obj = ass_temp;
        ass_temp = ass_temp->next;

        delete_association((char *)ass_obj->id);
    }

    /*check collector set left for delete or not*/
    coll_set = plugin.collector_set;
    if(coll_set!=NULL)
    {
        SECMON_INFO("collectors set are left for delete\n");
    }

    /*check collector object left for delete*/
    coll_rule = plugin.Collec_rule;
    if(coll_rule!=NULL)
    {
        SECMON_INFO("coll obj are left for delete\n");
    }

    collector_obj_head = NULL;
}


/** delete association associated with id supplied ,  if exists
 *	called by server when notification comes to delete or update association
 *  @returns void
 *
 */
void delete_association(char *id)
{
    struct Association *node , 			/*temperories to process associations*/
                       *save , 
                       *obj , 
                       *head;
    int count = 0 , len = strlen(id),count2 = 0;
    char temp[len];

    strncpy(temp , id , len);

    head = plugin.association;
    /*if no association exits*/
    if(head==NULL)
    {
        SECMON_INFO("No associations to delete");
        //printf("No associations to delete\n");
        return;
    }

    /*association with that id*/
    obj = association_node_of_id(head , id);
    if(obj==NULL)
    {
        return;
    }

    /*count no of associations with same policy & collector*/
    strncpy(id , temp , len);
    node = head;
    while(node!=NULL)
    {
        if(obj->policy_id!=NULL)
        {
            if(strcmp((char *)obj->policy_id,(char *)node->policy_id) == 0)
            {
                count++;
            }
        }

        if(obj->collector_id!=NULL)
        {
            if(strcmp((char *)obj->collector_id,(char *)node->collector_id) == 0)
            {
                count2++;
            }
        }

        node = node->next;
    }

    save = NULL;
    node = head;

    /*traverse associations*/
    while(node!=NULL)
    {
        strncpy(id , temp , len);

        /*delete node if id matched*/
        if(strcmp((char *)node->id , id) == 0)
        {
            /*delete collector obj*/
            if(strcmp((char *)node->collector_set_id,"") != 0)
            {
                col_set = COLSET;
                delete_collector_set((char *)node->collector_set_id);
            }
            else
            {
                col_set = COL;
                delete_collector_obj((char *)node->collector_id);
            }

            /*delete policy or collector if they are associated with 
              current association only*/
            if(count==ONECONF)
            {
                delete_policy((char *)node->policy_id);
            }

            if(count2==ONECONF)
            {
                delete_collector((char *)node->collector_id);
            }

            /*association at head*/
            if(save==NULL)
            {
                plugin.association = node->next;
            }
            else
            {
                save->next = node->next;
            }

            if(node !=NULL)
            {
                free(node);
                node = NULL;
            }
            break;
        }
        save = node;
        node = node->next;
    }
}


/** delete collector associated with id supplied ,  if exists
 *  @returns void
 *
 */
void delete_collector(char *id)
{
    struct Collector *node , 			/*temperories to process collectors*/
                     *save , 
                     *head;
    int len = strlen(id);
    char temp[len];

    strncpy(temp , id , len);

    head = plugin.collector;
    /*if no collector exits*/
    if(head==NULL)
    {
        SECMON_INFO("no collector to delete\n");
        return;
    }

    save = NULL;
    node = head;

    /*traverse collectors*/
    while(node!=NULL)
    {
        strncpy(id , temp , len);

        /*delete node if id matched*/
        if(strcmp((char *)node->id , id) == 0)
        {
            /*delete collector object*/
            col_set = COL;
            delete_collector_obj((char *)id);

            /*collector at head*/
            if(save==NULL)
            {
                plugin.collector = node->next;
            }
            else
            {
                save->next = node->next;
            }

            delete_netflow_destination((char *)node->ip.dst_addr , node->port);

            if(node!=NULL)
            {
                free(node);
                node = NULL;
            }
            break;
        }
        save = node;
        node = node->next;
    }
}



/** delete collector object associated with collector or collector set specified by id supplied , 
 *  if exists
 *  @param id
        id of the collector or collector set which to delete
 *  @returns void
 *
 */
void delete_collector_obj(char *id)
{
    struct Collector_object *node , 		/*temperories to process collector objects*/
                            *save , 
                            *head;
    int len = strlen(id);
    char temp[len];

    strncpy(temp , id , len);

    head = plugin.Collec_rule;
    /*if no collector objects exits*/
    if(head==NULL)
    {
        SECMON_INFO("no collector objects to delete\n");
        return;
    }

    save = NULL; 
    node = head;

    /*traverse collector objects*/
    while(node!=NULL)
    {
        strncpy(id , temp , len);

        /*delete node if id matched*/
        if(node->collector_set == COLSET)
        {
            if((strcmp((char *)node->collector_set_id , id) == 0))
            {
                /*node at head*/
                if(save==NULL)
                    plugin.Collec_rule = node->next;
                else
                    save->next = node->next;

                /* if collector details is not empty than free it 
                 * in case of collector set we store collector in collector details
                 * that's why we are freeing collector details inside collector object
                 */
                if(node!=NULL)
                {
                    struct Collector_details *collec_det = node->collector_details;
                  
                    while (collec_det)
                    {
                        struct Collector_details *temp = collec_det->next;
                        free(collec_det);
                        collec_det = temp;
                    }
                  
                    collec_det = NULL;
                    free(node);
                    node = NULL;
                }
                break; 
            }
        }
        else
        {
            if((strcmp((char *)(node->collector)->id , id) == 0))
            {
                /*node at head*/
                if(save==NULL)
                    plugin.Collec_rule = node->next;
                else
                    save->next = node->next;

                if(node!=NULL)
                {
                    free(node);
                    node = NULL;
                }
                break;
            }
        }
        save = node;
        node = node->next;
    }

    collector_obj_head = plugin.Collec_rule;
}

/** delete collector set associated with id supplied ,  if exists
 *  @returns void
 *
 */
void delete_collector_set(char *id)
{
    struct Collector_set *node ,  		/*temperories to process collector sets*/
                         *save , 
                         *head;
    int len = strlen(id);
    char temp[len];

    strncpy(temp , id , len);

    head = plugin.collector_set;

    /*if no collector set exits*/
    if(head==NULL)
    {
        SECMON_INFO("no collector set to delete\n");
        return;
    }

    save = NULL;
    node = head;

    /*traverse collector sets*/
    while(node!=NULL)
    {
        strncpy(id , temp , len);

        /*delete node if id matched*/
        if(strcmp((char *)node->id , id) == 0)
        {
            /*delete collector object*/
            col_set = COLSET;
            delete_collector_obj((char *)node->id);

            /*set at head*/
            if(save==NULL)
            {
                plugin.collector_set = node->next;
            }
            else
            {
                save->next = node->next;
            }

            if(node !=NULL)
            {
                free(node);
                node = NULL;
            }
            break;
        }
        save = node;
        node = node->next;
    }
}

/** delete policy associated with id supplied ,  if exists
 *  @returns void
 *
 */
void delete_policy(char *id)
{
    struct Policy *node , 				/*temperories to process policies*/
                  *save , 
                  *head;
    struct Rules *rule_temp,*rule_obj;

    int len = strlen(id);
    char temp[len];

    strncpy(temp , id , len);

    head = plugin.policy;

    /*if no policy exits*/
    if(head==NULL)
    {
        SECMON_INFO("no policy to delete\n");
        return;
    }

    save = NULL;
    node = head;

    /*traverse policies*/
    while(node!=NULL)
    {
        strncpy(id , temp , len);

        /*delete node if id matched*/
        if(strcmp((char *)node->id , id) == 0)
        {
            /*node at head*/
            if(save==NULL)
            {
                plugin.policy = node->next;
            }
            else
            {
                save->next = node->next;
            }

            if(node !=NULL)
            {
                /*delete ruleobject & rules in policy*/
                rule_temp = node->rule_ids;
                while(rule_temp!=NULL)
                {
                    rule_obj = rule_temp;
                    rule_temp = rule_temp->next;

                    delete_rule_ids((char *)rule_obj->rule_id);
                }

                free(node);
                node = NULL;
            }
            break;
        }
        save = node;
        node = node->next;
    }
}

/** delete rule associated with id supplied from all collector objects , 
 *	if exists in collector object
 *  @returns void
 *
 */
void delete_rule(char *id)
{
    struct Collector_object *collec_obj , 			/*temperories to process collector objects*/
                            *collec_head;

    struct Classification_object *head , 				/*temperories to process rules*/
                                 *save , 
                                 *node;
    int len = strlen(id);
    char temp[len];

    strncpy(temp , id , len);

    collec_head = plugin.Collec_rule;

    /*if no collector objects*/
    if(collec_head==NULL)
    {
        SECMON_INFO("no collector with rules to delete\n");
        return;
    }

    collec_obj = collec_head;

    /*traverse collector objects*/
    while(collec_obj!=NULL)
    {
        /*take rules*/
        head = collec_obj->classification_object;

        /*if no rule in collector object*/
        if(head==NULL)
        {
            SECMON_INFO("no rules for collector to delete\n");
            collec_obj = collec_obj->next;
            continue;
        }

        save = NULL;
        node = head;

        /*traverse rules in collector object*/
        while(node!=NULL)
        {
            strncpy(id , temp , len);

            /*delete node if id matched*/
            if(strcmp((char *)node->rule_id , id) == 0)
            {
                /*rule at head*/
                if(save==NULL)
                {
                    collec_obj->classification_object = node->next;

                    /*if there is only rule in collector object which is requested to delete
                      then deleting collector object*/
                    if(collec_obj->classification_object==NULL)
                    {
                        // delete_collector_obj((char *)(collec_obj->collector)->id);
                        delete_collector_obj((char *)collec_obj->collector_id);
                    }
                }
                else
                {
                    save->next = node->next;
                }

                if(node!=NULL)
                {
                    free(node);
                    node = NULL;
                }               
                break;
            }
            save = node;
            node = node->next;
        }

        collec_obj = collec_obj->next;
    }
}


/** delete rule object & rule associated with id supplied 
 *	from all policies ,  if exists in policy
 *  @returns void
 *
 */
void delete_rule_ids(char *id)
{
    struct Policy *policy_obj , 			/*temperories to process policies*/
                  *policy_head;
    struct Rules *head , 					/*temperories to process rule objects*/
                 *save , 
                 *node;
    int len = strlen(id);
    char temp[strlen(id)];

    strncpy(temp , id , len);

    policy_head = plugin.policy;

    /*if no policies*/
    if(policy_head==NULL)
    {
        SECMON_INFO("no policy to delete rule objects\n");
        return;
    }

    policy_obj = policy_head;

    /*traverse policies*/
    while(policy_obj!=NULL)
    {
        /*take rule objects in policy*/
        head = policy_obj->rule_ids;

        /*if no rule objects in policy*/
        if(head==NULL)
        {
            SECMON_INFO("no rule object to delete\n");
            return;
        }

        save = NULL;
        node = head;

        /*traverse rule objects*/
        while(node!=NULL)
        {
            strncpy(id , temp , len);

            /*delete node if id matched*/
            if(strcmp((char *)node->rule_id , id) == 0)
            {
                /*delete rule*/
                delete_rule((char *)node->Classification_id);

                /*rule objects at head*/
                if(save==NULL)
                {
                    policy_obj->rule_ids = node->next;
                }
                else
                {
                    save->next = node->next;
                }

                if(node!=NULL)
                {
                    free(node);
                    node = NULL;
                }
                break;
            }
            save = node;
            node = node->next;
        }

        policy_obj = policy_obj->next;
    }
}
/** fetch association according to id supplied and add it to configurations , 
 * 	called by server when notification comes to add new association.
 *  @param id
 *      contains id of association need to add
 *  @returns void
 *
 */
void fetch_add_association(char* id)
{
    SECMON_INFO("fetching & adding association\n");
    fetch_association_by_id((char *)plugin.root_url , id,(char *)(plugin.scope)->id);

}

/** add new association according to id if association not exists
 *  & store its other details 
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @returns void
 *
 */
void add_association(char* key , char* value)
{
    struct Association *association ,       /*pointer in which details store*/
                       *loc ,               /*to traverse head*/
                       *head;             /*contain head of association list*/
    char   *id , 							  /*to store id of current association*/
           url[URL_SIZE],				  /*to store current url*/
           *temp;						  /*temp value to take collector id*/
    int url_len , id_len;										
    const char delimiter[2] = ":";
    memset(url,'\0',URL_SIZE);

    head = plugin.association;

    /*if key is id then check id exists ,  if not then add it in last*/
    if(strcmp(key , UUID) == 0)
    {
        association  =  (struct Association *)malloc(sizeof(struct Association));
        if(association == NULL)
        {
            SECMON_CRITICAL("ERROR: error in allocating memory to association\n");
            perror("Error occurs. Please check /var/log/secmon.log file for error\n");
            exit(EXIT0);
        }

        memset(association,'\0',sizeof( struct Association));

        strncpy((char *) association->id , value , strlen(value)); 
        association->next = NULL;

        /*list is empty*/
        if(head==NULL)
        {   
            plugin.association = association;
            new_association = NEWASS;
        }

        else
        {
            loc = association_node_of_id(head , value);

            /*association already exist with id*/
            if(loc!=NULL)
            {
                SECMON_INFO("previous association exists\n");
                if(association!=NULL)
                {
                    free(association);
                    association = NULL;
                }
                new_association = OLDASS;
                return;
            }

            loc = find_last_association(head);
            loc->next = association;
            new_association = NEWASS;
        }
    }
    /*store other details if association is newly added otherwise return*/
    else
    {
        /*take id from url & search its exists in list*/
        id = strrchr((char *)plugin.url,'/');

        url_len = strlen((char *)plugin.url);
        id_len = strlen(id);

        memcpy(url,(char *)plugin.url , url_len-id_len);
        id = strrchr(url,'/');
        id++;

        loc = association_node_of_id(head , id);
        if(loc==NULL)
        {
            SECMON_INFO("association node not exist to add details\n");
            return;
        }

        /*association exists but its is not the new added association*/
        if(loc->next!=NULL)
        {
            return;
        }

        /*store details for association*/
        association = loc;

        if(strcmp(key , POLICYID) == 0 )
        {
            strncpy((char *)association->policy_id , value , strlen(value));
        }

        if(strcmp(key , COLLECTORID) == 0 )
        {
            /*temp = strstr(value , EXT1);*/
            /*temp++;*/
            temp = strtok(value , delimiter);
            if(strcmp(temp, "Collector")==0)
            {
                temp = strtok(NULL , delimiter);
                strncpy((char *)association->collector_id , temp , strlen(temp));
                strcpy((char *)association->collector_set_id , "");
            }
            else if(strcmp(temp, "Collectorset")==0)
            {
                temp = strtok(NULL , delimiter);
                strncpy((char *)association->collector_set_id , temp , strlen(temp));
                strcpy((char *)association->collector_id, "");
            }
        }

        if(strcmp(key , DIRECTION) == 0 )
        {
            strncpy((char *)association->direction , value , strlen(value));
        }

        if(strcmp(key , SCOPE) == 0 )
        {
            association->scope=(uint32_t)atoi(value);
        }
    }

}


/** delete netflow config
 *  @returns void
 *
 */
void delete_netflow_config()
{
    struct Netflow_Config *temp;

    temp = plugin.netconfig;

    if(temp!=NULL)
    {
        plugin.netconfig = NULL;

        free(temp);
        temp = NULL;
    }
}

/** delete netflow monitor
 *  @returns void
 *
 */
void delete_netflow_monitor()
{
    struct Netflow_Monitor *temp;

    temp = plugin.netmonitor;

    if(temp!=NULL)
    {
        plugin.netmonitor = NULL;

        free(temp);
        temp = NULL;
    }
}

