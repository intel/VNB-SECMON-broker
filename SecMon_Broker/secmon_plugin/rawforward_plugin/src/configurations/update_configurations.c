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
 *  
 *
 *
 *
 */

#include "client.h"


/** store association with details if not exists
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @returns void
 *
 */
void store_association(char* key , char* value)
{
    struct Association *association ,     /*pointer in which details store*/
                       *loc ,             /*to traverse head*/
                       *head;           /*store association list*/
    char *temp;							/*to store value to take collector id*/
    const char delimiter[2]= ":";
    head = plugin.association;

    /*if id as key then store association in end if not exists*/
    if(strcmp(key , UUID) == 0)
    {
        association =  (struct Association *)malloc(sizeof( struct Association));

        if(association==NULL)
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
            if(loc!=NULL)
            {
                SECMON_INFO("association id already exists\n");
                if(association!=NULL)
                {
                    free(association);
                    association = NULL;
                }
                new_association = OLDASS;
                return;
            }

            /*append in end*/
            loc = find_last_association(head);
            loc->next = association;
            new_association = NEWASS;
        }
    }
    /*store other details of association*/
    else
    {
        loc = find_last_association(head);
        association = loc;

        if(strcmp(key , POLICYID) == 0 )
        {
            strncpy((char *)association->policy_id , value , strlen(value));
        }

        if(strcmp(key , COLLECTORID) == 0 )
        {
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

        /*if(strcmp(key , COLLECTORSETID) == 0 )
        {
            temp = strstr(value , EXT1);
            temp++;
            strncpy((char *)association->collector_set_id , temp , strlen(temp));
        }*/

        if(strcmp(key , DIRECTION) == 0)
        {
            strncpy((char *)association->direction , value , strlen(value));
        }

        if(strcmp(key , SCOPE) == 0)
        {
            association->scope=(uint32_t)atoi(value);
        }
    }

}


/** store collector with details for collector or for collector set if not exists
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @param  is_collector_set
 *      flag to denote collector or collector set
 *  @returns void
 *
 */

void store_collector(char* key , char* value, bool is_collector_set)
{
    struct Collector *Collec ,           /*pointer in which details store*/
                     *loc ,              /*to traverse head*/
                     *head;            /*store collector list*/
    char   *id , 						   /*store current collector id*/
           url[URL_SIZE];			   /*store current url*/
    int url_len , id_len;
    struct Collector_set *collector_set;
    memset(url,'\0',URL_SIZE);
    
    //printf("store_collector: is_collector_set = %d \n",is_collector_set);
    if(is_collector_set)
    {
        //printf("in collector set\n");
        collector_set = find_last_collector_set(plugin.collector_set);
        head = collector_set->collectors;
    }
    else
    {
        //printf("in collector\n");
        head = plugin.collector;
    }

    /*if key is id store collector if not exists*/
    if(strcmp(key , UUID) == 0)
    {
        Collec  =  malloc(sizeof(struct Collector));
        //printf("Collec initially = %p\n",Collec);
        memset(Collec,'\0',sizeof(struct Collector));
        strncpy((char *) Collec->id , value , strlen(value));
        Collec->next = NULL;

        /*list is empty*/
        if(head==NULL)
        {
            //printf("store_collector: head is null\n");
            if(is_collector_set)
            {
                collector_set = find_last_collector_set(plugin.collector_set);
                collector_set->collectors = Collec;
                //printf("plugin.collector_set = %p\n",collector_set);
            }
            else
            {
                plugin.collector = Collec;
                //printf("store_collector: Collector\n");
            }
        }
        else
        {
            //printf("store_collector: head is not null\n");
            if(!is_collector_set)
            {
                loc = collector_node_of_id(head , value);
                if(loc!=NULL)
                {
                    SECMON_INFO("collector id already exists\n");
                    //printf("collector id already exists\n");
                    if(Collec!=NULL)
                    {
                        free(Collec);
                        Collec = NULL;
                    }
                    return;
                }
                /*append in end*/
                loc = find_last_collector(head);
                loc->next = Collec;
            }
            else
            {
                loc = collector_node_of_id(head , value);
                if(loc!=NULL)
                {
                    SECMON_INFO("collector id already exists\n");
                    //printf("collector id already exists\n");
                    if(Collec!=NULL)
                    {
                        free(Collec);
                        Collec = NULL;
                    }
                    return;
                }
                /*append in end*/
                loc = find_last_collector(head);
                loc->next = Collec;

            }
        }

    }
    else if(strcmp(key, WEIGHT) == 0)
    {
        struct Collector *col_temp;
        col_temp = plugin.collector_set->collectors;
        while(col_temp->next != NULL)
        {
            //printf("store_collector: Searching last collector\n");
            col_temp = col_temp->next;
        }
        col_temp->weight = ((uint32_t)atoi(value)) << 8; 
    }
    /*store other details of collector*/
    else
    {
        //printf("key = %s, url = %s\n",key, plugin.url);
        /*take current id of collector in url*/
        id = strrchr((char *)plugin.url,'/');

        url_len = strlen((char *)plugin.url);
        id_len = strlen(id);

        memcpy(url,(char *)plugin.url , url_len-id_len);
        id = strrchr(url,'/');
        id++;
        //printf("id = %s, head=%p\n", id, head);
        loc = collector_node_of_id(head , id);

        /*no collector with id*/
        if(loc==NULL)
        {
            SECMON_INFO("collector not exist with id\n");
            //printf("collector not exist with id\n");
            return;
        }

        /*already stored collector*/
        if(loc->next!=NULL && !is_collector_set)
        {
            SECMON_DEBUG("already stored collector\n");
            return;
        }

        Collec = loc;
        //printf("Collec = %p\n",Collec);
        if(strcmp(key , NAME) == 0 || strcmp(key , CNAME) == 0)
        {
            strncpy((char *)Collec->name , value , strlen(value));
            //printf("name = %s\n", Collec->name);
        }

        if(strcmp(key , UDPPORT) == 0)
        {
            Collec->port=(uint32_t)atoi(value);
        }

        if(strcmp(key , ENCAP_PROTO) == 0)
        {
            if(strcmp(value , UDP) == 0)
            {
                Collec->encap_protocol  =  UDP_PROC;
            }
            else
            {
                Collec->encap_protocol  =  SFLOW_PROC;
            }
        }

        if(strcmp(key , IP) == 0)
        {
            strncpy((char *)Collec->ip.dst_addr , value , strlen(value));
            //printf("store_collector: ip = %s\n", Collec->ip.dst_addr);
        }

        if(strcmp(key , IPV6) == 0)
        {
            strncpy((char *)Collec->ip.dst_addr , value , strlen(value));
        }
    }

}
/** copies details of the collector fetched from the 
 *  EMS into the collector set.
 *  @param cobj
 *      collector object inside which collector details are stored for collector
 *  @param collector
 *      collector whose details to copy
 *  @returns void
 */
void copy_collector(struct Collector_object *cobj, struct Collector *collector)
{
    int sock;
    struct Collector_details *collector_details, *col_details_tmp;
    col_details_tmp = (struct Collector_details *)malloc(sizeof(struct Collector_details));
    memset(col_details_tmp, '\0',sizeof(struct Collector_details));
    
    if((sock = socket(AF_INET ,  SOCK_DGRAM ,  IPPROTO_UDP)) < 0)
    {
        SECMON_CRITICAL("ERROR: socket() failed");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
    else
        col_details_tmp->socket  =  sock;
   
    /*create collector's server_address from collector's ip & port*/
    memset(&col_details_tmp->server_address ,  '\0', sizeof(struct sockaddr_in));
    col_details_tmp->server_address.sin_family       =  AF_INET;
    col_details_tmp->server_address.sin_port         =  htons(collector->port);
    col_details_tmp->server_length  =  sizeof(struct sockaddr_in);
    if((inet_aton((const char *)collector->ip.dst_addr, &col_details_tmp->server_address.sin_addr)) == 0)
    {
        SECMON_CRITICAL("ERROR: inet_aton() failed:\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
    col_details_tmp->encap_protocol = collector->encap_protocol;
    strncpy((char *)col_details_tmp->id, (char *)collector->id, strlen((char *)collector->id));
    col_details_tmp->weight = collector->weight;
    //printf("collector details id = %s\n",col_details_tmp->id);
    //printf("collector weight = %u\n",col_details_tmp->weight);
    col_details_tmp->next = NULL;
    
    collector_details = cobj->collector_details; 
    if(collector_details == NULL)
    {
        //printf("first collector set\n");
        collector_details = col_details_tmp;
        
        cobj->collector_details = collector_details;
    }
    else
    {
        //printf("second collector set\n");
        struct Collector_details *col_details_last;
        col_details_last = find_last_collector_details_obj(collector_details);
        col_details_last->next = col_details_tmp;
    }
}


/** store collector obj with collector details
 *  @param collector
 *      contains collector details which to store in collector object list
 *  @param  is_first_collector
 *      contains flag to denote that collector information passed is for first collector
 *      or not
 *  @returns void
 *
 */
void store_collector_set_obj(struct Collector *collector, bool is_first_collector)
{
    struct Collector_object *cobj, *temp;
    struct Collector_set *collector_set;
    // cobj = plugin.Collec_rule;
    struct Collector_object *head = plugin.Collec_rule;
    if(head == NULL)
    {
        cobj = (struct Collector_object *)malloc(sizeof(struct Collector_object));
        if(cobj == NULL)
            return;
        memset(cobj, '\0',sizeof(struct Collector_object));
        cobj->collector_set = TRUE;
        collector_set = find_last_collector_set(plugin.collector_set);
        strncpy((char *)cobj->collector_set_id, (char *)collector_set->id, strlen((char *)collector_set->id));
        cobj->load_balancer_algo = collector_set->load_balancer_algo;
        if(cobj->load_balancer_algo == ROUND_ROBIN)
            cobj->collector_count++;
        //printf("ip = %s\n", collector->ip.dst_addr); 
        copy_collector(cobj, collector);
        plugin.Collec_rule = cobj;
    }
    else
    {
        if(!is_first_collector)       
        {
            cobj = find_last_collector_obj(plugin.Collec_rule);
            if(cobj->load_balancer_algo == ROUND_ROBIN)
                cobj->collector_count++;
            copy_collector(cobj, collector);
        }
        else
        {
            //printf("Collector object is NULL\n");
            cobj = (struct Collector_object *)malloc(sizeof(struct Collector_object));
            if(cobj == NULL)
                return;
            memset(cobj, '\0', sizeof(struct Collector_object));
            cobj->collector_set = TRUE;
            collector_set = find_last_collector_set(plugin.collector_set);
            strncpy((char *)cobj->collector_set_id, (char *)collector_set->id, strlen((char *)collector_set->id));
            cobj->load_balancer_algo = collector_set->load_balancer_algo;
            if(cobj->load_balancer_algo == ROUND_ROBIN)
                cobj->collector_count++; 
            copy_collector(cobj, collector);
            temp = find_last_collector_obj(plugin.Collec_rule);
            temp->next = cobj;
        }
    }
}

/** store collector obj with collector details
 *  @param collec
 *      contains collector whose details to be stored
 *  @returns void
 *
 */
void store_collector_obj(struct Collector *collec)
{
    struct Collector_object *coll_obj ,   /*to store collector_obj details*/
                            *head ,       /*head pointer to list*/
                            *temp1;     /*to traverse collector_obj*/
    int sock;							/*socket handle*/

    head = plugin.Collec_rule;
    coll_obj =  malloc(sizeof(struct Collector_object));
    memset(coll_obj,'\0',sizeof(struct Collector_object));

    coll_obj->collector  =  malloc(sizeof(struct Collector));
    memset(coll_obj->collector,'\0',sizeof(struct Collector));

    strcpy((char *)coll_obj->collector->id,(char *)collec->id);
    strcpy((char *)coll_obj->collector->name,(char *)collec->name);
    coll_obj->collector->port = collec->port;
    coll_obj->collector->encap_protocol = collec->encap_protocol;
    strcpy((char *)coll_obj->collector->ip.dst_addr,(char *)collec->ip.dst_addr);
    coll_obj->collector->next = NULL;

    coll_obj->classification_object = NULL;
    coll_obj->next = NULL;    

    coll_obj->server_length  =  sizeof(coll_obj->server_address);
    if((sock  =  socket(AF_INET ,  SOCK_DGRAM ,  IPPROTO_UDP)) < 0)
    {
        SECMON_CRITICAL("ERROR: socket() failed");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
    else
    {
        coll_obj->socket  =  sock;
    }

    /*take address supplied in collector ip & port*/
    memset(&coll_obj->server_address ,  '\0', sizeof(coll_obj->server_address));
    coll_obj->server_address.sin_family       =  AF_INET;              
    coll_obj->server_address.sin_port         =  htons(coll_obj->collector->port); 
    if((inet_aton((const char *)coll_obj->collector->ip.dst_addr  ,  &coll_obj->server_address.sin_addr)) == 0)
    {
        SECMON_CRITICAL("ERROR: inet_aton() failed:\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }

    /*no collector_objects*/
    if(head==NULL)
    {
        plugin.Collec_rule = coll_obj;
    }
    /*append obj at the end*/
    else
    {
        temp1 = find_last_collector_obj(head);
        temp1->next = coll_obj;
    }
    coll_obj->collector_set = COL;
}


/** store collector set with details in end of list
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @returns void
 *
 */
void store_collector_set(char* key , char* value)
{
    //printf("store_collector_set\n");
    struct Collector_set *p ,           /*pointer in which details store*/
                         *loc ,         /*to traverse head*/
                         *head;       /*store collector_set list*/
    head = plugin.collector_set;
    /*key is id then store collector set with id if not exists*/
    if(strcmp(key , UUID) == 0)
    {
        p = malloc(sizeof(struct Collector_set));
        memset(p,'\0',sizeof(struct Collector_set));
        strncpy((char *)p->id , value , strlen(value));
        p->next = NULL;
        p->collectors = NULL;

        /*list is empty*/
        if(head==NULL)
        {  
            //printf("updating plugin.collector_set\n"); 
            plugin.collector_set = p;
        }
        else
        {
            //printf("updating plugin.collector_set next\n"); 
            loc = find_last_collector_set(head);
            loc->next = p;
        }
    }
    /*store other details of collector set*/
    else
    {
        loc = find_last_collector_set(head);
        p = loc;
        if(strcmp(key , NAME) == 0)
        {
            strncpy((char *)p->name , value , strlen(value));
        }

        if(strcmp(key , COLLECTORIDS) == 0)
        {     
            //printf("value = %s\n",value); 
            parse_json_response(value , COLLECTOR_SET_ARRAY);
        }
        if(strcmp(key, LOAD_BALANCER_ALGO) == 0)
        {
            p->load_balancer_algo = (uint8_t)atoi(value);
        }
    }
}

/** store policy with details if not exists
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @returns void
 *
 */
void store_policy(char* key , char* value)
{
    struct Policy *p ,                  /*pointer in which details store*/
                  *loc ,                /*to traverse head*/
                  *head;              /*store policy list*/
    char   *id , 						  /*id of current policy*/
           url[URL_SIZE];			  /*current url*/
    int url_len , id_len;

    memset(url,'\0',URL_SIZE);

    head = plugin.policy;

    /*key is id then store policy if not exists*/
    if(strcmp(key , UUID) == 0)
    {
        p = malloc(sizeof(struct Policy));
        memset(p,'\0',sizeof(struct Policy));
        strncpy((char *)p->id , value , strlen(value));
        p->next = NULL;
        p->rule_ids = NULL;

        /*list is empty*/
        if(head==NULL)
        {   
            plugin.policy = p;
        }
        else
        {
            loc = policy_node_of_id(head , value);
            if(loc!=NULL)
            {
                SECMON_INFO("policy id already exists\n");
                if(p!=NULL)
                {
                    free(p);
                    p = NULL;
                }
                return;
            }

            /*append in end*/
            loc = find_last_policy(head);

            loc->next = p;
        }
    }

    /*store other details of policy*/
    else
    {
        /*take current policy id*/
        id = strrchr((char *)plugin.url,'/');

        url_len = strlen((char *)plugin.url);
        id_len = strlen(id);

        memcpy(url,(char *)plugin.url , url_len-id_len);
        id = strrchr(url,'/');
        id++;

        loc = policy_node_of_id(head , id);

        /*no policy exists with that id*/
        if(loc==NULL)
        {
            SECMON_INFO("policy not exist with id\n");
            return;
        }

        /*already has details of policy*/
        if(loc->next!=NULL)
        {
            plugin.ruleobj = loc->rule_ids;
            return;
        }

        p = loc;

        if(strcmp(key , NAME) == 0)
        {
            strncpy((char *)p->name , value , strlen(value));
        }

        if(strcmp(key , RULEIDS) == 0)
        {       
            store_by_id(value , RULE);
        }

    }

}

/** store rule with details if not exists
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @returns void
 *
 */
void store_rule(char* key , char* value)
{
    struct Classification_object *obj ,        /*pointer in which details store*/
                                 *loc ,        /*to traverse head*/
                                 *head;      /*store rules list*/
    struct Collector_object  *collec_obj ,     /*collector obj pointer*/
                             *collec_head;	 /*store collector obj list*/

    char   *id , 								 /*store current rule id*/
           url[URL_SIZE];					 /*store current url*/
    int url_len , id_len , index;
    uint32_t temp_mac[ETHER_ADDR_LEN];

    memset(url,'\0',URL_SIZE);

    collec_head = plugin.Collec_rule;

    /*if key is id store rule  if not exists*/
    if(strcmp(key , UUID) == 0)
    {
        obj = malloc(sizeof(struct Classification_object));
        memset(obj,'\0',sizeof(struct Classification_object));
        strncpy((char *)obj->rule_id , value , strlen(value));
        obj->next = NULL;

        /*no collector associated with rules*/
        if(collec_head==NULL)
        {
            SECMON_INFO("no collector obj to store rules\n");
            if(obj!=NULL)
            {
                free(obj);
                obj = NULL;
            }
            return;
        }

        /*newest collector associated with rules*/
        collec_obj = find_last_collector_obj(collec_head);

        head = collec_obj->classification_object;

        /*first rule added to collector*/
        if(head==NULL)
        {
            collec_obj->classification_object = obj;
        }
        /*append if not exists*/
        else
        {
            loc = rule_node_of_id(head , value);
            if(loc!=NULL)
            {
                SECMON_INFO("rule is already here in collector object\n");
                free(loc);
                loc = NULL;
                return;
            }            

            loc = find_last_rule(head);
            loc->next = obj;
        }
    }
    /*store other details of rule*/
    else
    {
        /*take current id of rule in url*/
        id = strrchr((char *)plugin.url,'/');

        url_len = strlen((char *)plugin.url);
        id_len = strlen(id);

        memcpy(url,(char *)plugin.url , url_len-id_len);
        id = strrchr(url,'/');
        id++;

        /*no collector & rule*/
        if(collec_head==NULL)
        {
            SECMON_INFO("collector head null\n");
            return;
        }

        collec_obj = find_last_collector_obj(collec_head);

        head = collec_obj->classification_object;

        /*no rule to store details*/
        if(head ==NULL)
        {
            SECMON_INFO("no rules to add details\n");
            return;
        }

        loc = rule_node_of_id(head , id);

        /*rule not exists with id*/
        if(loc==NULL)
        {
            SECMON_INFO("no rule with this id\n");
        }

        /*already have details of rule*/
        if(loc->next!=NULL)
        {
            return;
        }

        obj = loc;   

        if(strcmp(key , NAME) == 0)
        {
            strncpy((char *)obj->name , value , strlen(value));
        }

        if(strcmp(key , SRCMAC) == 0)
        {
            if(strncmp(value,"*",1) == 0)
            {
                for(index = 0;index < ETHER_ADDR_LEN;index++)
                {
                    obj->src_mac[index] = 0;
                }
            }
            else {
                sscanf(value ,  "%x:%x:%x:%x:%x:%x",&temp_mac[0],
                        &temp_mac[1],&temp_mac[2],
                        &temp_mac[3],&temp_mac[4],&temp_mac[5]);
                for(index = 0;index < ETHER_ADDR_LEN;index++)
                {
                    obj->src_mac[index]=temp_mac[index];
                }
            }
        }

        if(strcmp(key , DESTMAC) == 0)
        {
            if(strncmp(value,"*",1) == 0)
            {
                for(index = 0;index < ETHER_ADDR_LEN;index++)
                {
                    obj->dst_mac[index] = 0;
                }
            }
            else {
                sscanf(value ,  "%x:%x:%x:%x:%x:%x",&temp_mac[0],
                        &temp_mac[1],&temp_mac[2],
                        &temp_mac[3],&temp_mac[4],&temp_mac[5]);
                for(index = 0;index < ETHER_ADDR_LEN;index++)
                {
                    obj->dst_mac[index]=temp_mac[index];
                }
            }
        }

        if(strcmp(key , SRCIP) == 0)
        {
            store_ip_mask(value,&obj->src_ip , obj->src_ip_subnet);
        }

        if(strcmp(key , DESTIP) == 0)
        {
            store_ip_mask(value,&obj->dst_ip , obj->dst_ip_subnet);
        }

        if(strcmp(key , MINSRCPORT) == 0)
        {
            obj->min_src_port=(uint16_t)atoi(value);
        }

        if(strcmp(key , MAXSRCPORT) == 0)
        {
            obj->max_src_port=(uint16_t)atoi(value);
        }

        if(strcmp(key , MINDESTPORT) == 0)
        {
            obj->min_dst_port=(uint16_t)atoi(value);
        }

        if(strcmp(key , MAXDESTPORT) == 0)
        {
            obj->max_dst_port=(uint16_t)atoi(value);

        }

        if(strcmp(key , ACTION) == 0)
        {
            obj->action=(uint16_t)atoi(value);
        }

        if(strcmp(key , PRIORITY) == 0)
        {
            obj->priority=(uint32_t)atoi(value);
        }

        if(strcmp(key , PROTOCOL) == 0)
        {
            obj->protocol=(uint16_t)atoi(value);
        }

        if(strcmp(key , SRCSUBIP) == 0)
        {
            obj->src_ip_subnet=(uint8_t)atoi(value);
            calculate_first_address(&obj->src_ip , obj->src_ip_subnet);
        }

        if(strcmp(key , DESTSUBIP) == 0)
        {
            obj->dst_ip_subnet=(uint8_t)atoi(value);
            calculate_first_address(&obj->dst_ip , obj->dst_ip_subnet);
        }

    }

}

/** store rule object with details if not exists
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @returns void
 *
 */
void store_rule_ids(char *key , char* value)
{
    struct Rules *rule ,             /*node contain new rule object*/
                 *loc ,              /*to traverse all rules*/
                 *head;            /*to store rule_objects list*/
    char   *id , 					   /*store current collector id*/
           url[URL_SIZE];          /*store current url*/
    int url_len , id_len;

    memset(url,'\0',URL_SIZE);

    head = plugin.ruleobj;

    /*if key is id store rule object if not exists*/
    if(strcmp(key , UUID) == 0)
    {
        rule = malloc(sizeof(struct Rules));
        memset(rule,'\0',sizeof(struct Rules));
        strncpy((char *)rule->rule_id , value , strlen(value));
        rule->next = NULL;

        /*rule objects list is empty*/
        if(head==NULL)
        {
            plugin.ruleobj = rule;
        }
        /*append in end if not exists*/
        else
        {
            loc = rule_id_node_of_id(head , value);
            if(loc!=NULL)
            {
                SECMON_INFO("rule object id already exists\n");  
                if(rule!=NULL)
                {
                    free(rule);
                    rule = NULL;
                }
                return;
            }

            loc = find_last_rule_id(head);
            loc->next = rule;
        }
    }
    /*store other details of rule object*/
    else
    {
        /*take current id of rule object in url*/
        id = strrchr((char *)plugin.url,'/');

        url_len = strlen((char *)plugin.url);
        id_len = strlen(id);

        memcpy(url,(char *)plugin.url , url_len-id_len);
        id = strrchr(url,'/');
        id++;

        loc = rule_id_node_of_id(head , id);

        /*no rule object with id*/
        if(loc==NULL)
        {
            SECMON_INFO("rule object not exist with id\n");
            return;
        }

        rule = loc;

        if(strcmp(key , NAME) == 0)
        {
            strncpy((char *)rule->name , value , strlen(value));
        }

        if(strcmp(key , CLASSIFICATIONID) == 0)
        {
            strncpy((char *)rule->Classification_id , value , strlen(value));
        }

        if(strcmp(key , ACTION) == 0)
        {
            rule->action=(uint16_t)atoi(value);
        }

        if(strcmp(key , PRIORITY) == 0)
        {
            rule->priority=(uint32_t)atoi(value);
        }

        if(strcmp(key , TRUNC) == 0)
        {
            rule->truncate_to_size=(uint32_t)atoi(value);
        }
    }

}

/** store scope id ,  name & status of plugin
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @returns void
 *
 */
void store_scope(char* key , char* value)
{
    struct Scope *scope1;        /*pointer in which details store*/

    scope1 = plugin.scope;

    /*key is id i.e scope id*/
    if(strcmp(key , UUID) == 0)
    {
        memset(scope1,'\0',sizeof( struct Scope));
        strncpy((char *) scope1->id , value , strlen(value)); 
    }
    /*store name & status of plugin*/
    else
    {
        if(strcmp(key , NAME) == 0 )
        {
            strncpy((char *)scope1->name , value , strlen(value));
        }

        if(strcmp(key , STATUS) == 0 )
        {
            strncpy((char *)plugin.status , value , strlen(value));
        }
    }
}

/** fetch association details according to id and update it if exists or 
 *	add it if not ,  called by server when notification comes.
 *  @param id
 *      contains id of association need to update
 *  @returns void
 *
 */
void fetch_update_association(char* id)
{
    int len = strlen(id);
    char temp_id[len];

    memset(temp_id,'\0',len);
    strcpy(temp_id , id);

    delete_association(id);

    strncpy(id , temp_id , strlen(temp_id));
    fetch_add_association(id);

}

/** fetch collector details according to id and update it if exists or 
 *  add it if not ,  called by server when notification comes.
 *  @param id
 *      contains id of collector need to update
 *  @returns void
 *
 */
void fetch_update_collector(char* id)
{
    struct Association *ass_head , 
                       *ass_temp;
    char ass_id[MAX_ID_LEN];
    int len = strlen(id);
    char temp_id[len];
    struct Collector_set *collector_set;
    struct Collector *collector;
    bool collector_found = FALSE;
    memset(temp_id,'\0',strlen(id));
    strcpy(temp_id , id);

    ass_head = plugin.association;

    /*find association according to collector delete it 
      and then add it with new configurations*/
    ass_temp = ass_head;
    while(ass_temp!=NULL)
    {
        memset(ass_id,'\0',MAX_ID_LEN);
        strncpy(id , temp_id , strlen(temp_id));
        if(strcmp((char *)ass_temp->collector_id , id) == 0)
        {
            strncpy(ass_id,(char *)ass_temp->id , strlen((char *)ass_temp->id));
            /*delete association n collector*/
            delete_association(ass_id);
            delete_collector(id);

            /*add new association*/
            fetch_add_association(ass_id);
            break;
        }
        collector_set = collector_set_node_of_id(plugin.collector_set, (char *)ass_temp->collector_set_id);
        if (collector_set != NULL)
        {
          collector = collector_set->collectors;
          while(collector != NULL)
          {
            SECMON_DEBUG("collector update: Searching collector sets\n");
            if(strcmp((char *)collector->id, id) == 0)
            {
              strncpy(ass_id,(char *)ass_temp->id , strlen((char *)ass_temp->id));
              SECMON_DEBUG("cid matched association id = %s\n",ass_id);
              delete_association(ass_id);
              /*add new association*/
              fetch_add_association(ass_id);
              collector_found = TRUE;
              break;
            }
            collector = collector->next;
          }
        }

        if(collector_found == TRUE)
        {
            SECMON_DEBUG("found and updated the collector\n");
            break;
        }
        ass_temp = ass_temp->next;
    }

}

/** fetch policy details according to id and update it if exists or 
 *  add it if not ,  called by server when notification comes.
 *  @param id
 *      contains id of policy need to update
 *  @returns void
 *
 */
void fetch_update_policy(char *id)
{
    struct Association *ass_head , 
                       *ass_temp;
    struct Policy *p_head , 
                  *p_obj;
    char ass_id[SIZE][MAX_ID_LEN];
    int no_associations = 0 , index , len = strlen(id);
    char temp_id[len];

    memset(temp_id,'\0',strlen(id));
    strcpy(temp_id , id);

    p_head = plugin.policy;
    ass_head = plugin.association;

    /*take all association with which policy associated*/
    ass_temp = ass_head;  
    while(ass_temp!=NULL)
    {   
        strncpy(id , temp_id , strlen(temp_id));

        if(strcmp((char *)ass_temp->policy_id , id) == 0)
        {
            memset(ass_id[no_associations],'\0',MAX_ID_LEN);

            /*delete association*/
            strncpy(ass_id[no_associations],(char *)ass_temp->id , 
                    strlen((char *)ass_temp->id));
            delete_association(ass_id[no_associations]);

            no_associations++;
        }    

        ass_temp = ass_temp->next;
    }

    /*delete policy*/
    strncpy(id , temp_id , strlen(temp_id));
    p_obj = policy_node_of_id(p_head , id);

    if(p_obj!=NULL)
    {
        delete_policy(id);
    }

    /*add all associations associated to policy with new configurations*/
    for(index = 0;index<no_associations;index++)
    {
        fetch_add_association(ass_id[index]);
    }

}

/** fetch rule details according to id and update it if exists or 
 *  add it if not ,  called by server when notification comes.
 *  @param id
 *      contains id of rule need to update
 *  @returns void
 *
 */
void fetch_update_rule(char* id)
{
    struct Policy *p_head , 
                  *p_obj;
    struct Rules *rule_head , 
                 *rule_obj;
    char pol_id[SIZE][MAX_ID_LEN];
    int no_policies = 0 , index , len = strlen(id);
    char temp_id[len];

    memset(temp_id,'\0',strlen(id));
    strcpy(temp_id , id);

    p_head = plugin.policy;

    /*take all policies that contains rule*/
    p_obj = p_head;
    while(p_obj!=NULL)
    {
        rule_head = p_obj->rule_ids;

        rule_obj = rule_head;
        while(rule_obj!=NULL)
        {
            strncpy(id , temp_id , strlen(temp_id));

            if(strcmp((char *)rule_obj->Classification_id , id) == 0)
            {
                memset(pol_id[no_policies],'\0',MAX_ID_LEN);

                strncpy(pol_id[no_policies],(char *)p_obj->id , 
                        strlen((char *)p_obj->id));

                no_policies++;
                break;
            }

            rule_obj = rule_obj->next;
        }
        p_obj = p_obj->next;
    }

    strncpy(id , temp_id , strlen(temp_id));
    delete_rule(id);

    /*add policies associated to rule with new configurations*/
    for(index = 0;index<no_policies;index++)
    {
        fetch_update_policy(pol_id[index]);
    }

}

/** fetch rule object details according to id and update it if exists or 
 *  add it if not ,  called by server when notification comes.
 *  @param id
 *      contains id of rule object need to update
 *  @returns void
 *
 */
void fetch_update_rule_ids(char* id)
{
    struct Policy *p_head , 
                  *p_obj;
    struct Rules *rule_head , 
                 *rule_obj;
    char pol_id[SIZE][MAX_ID_LEN];
    int no_policies = 0 , index , len = strlen(id);
    char temp_id[len];

    memset(temp_id,'\0',strlen(id));
    strcpy(temp_id , id);

    p_head = plugin.policy;

    /*take all policies that contains rule*/
    p_obj = p_head;
    while(p_obj!=NULL)
    {
        rule_head = p_obj->rule_ids;

        rule_obj = rule_head;
        while(rule_obj!=NULL)
        {
            strncpy(id , temp_id , strlen(temp_id));

            if(strcmp((char *)rule_obj->rule_id , id) == 0)
            {
                memset(pol_id[no_policies],'\0',MAX_ID_LEN);

                strncpy(pol_id[no_policies],(char *)p_obj->id , 
                        strlen((char *)p_obj->id));

                no_policies++;
                break;
            }

            rule_obj = rule_obj->next;
        }
        p_obj = p_obj->next;
    }

    strncpy(id , temp_id , strlen(temp_id));
    delete_rule_ids(id);

    /*add policies associated to rule with new configurations*/
    for(index = 0;index<no_policies;index++)
    {
        fetch_update_policy(pol_id[index]);
    }
}

/** fetch collector set details according to id and update it if exists or 
 *  add it if not ,  called by server when notification comes.
 *  @param id
 *      contains id of collector set  need to update
 *  @returns void
 *
 */
void fetch_update_collectorset(char* id)
{   
    struct Association *ass_head , 
                       *ass_temp;
    char ass_id[MAX_ID_LEN];

    ass_head = plugin.association;

    /*find association according to collector set delete it 
      and then add it with new configurations*/
    ass_temp = ass_head;
    while(ass_temp!=NULL)
    {
        memset(ass_id,'\0',MAX_ID_LEN);
        if(strcmp((char *)ass_temp->collector_set_id,"") != 0)
        {
            if(strcmp((char *)ass_temp->collector_set_id , id) == 0)
            {
                strncpy(ass_id,(char *)ass_temp->id , 
                        strlen((char *)ass_temp->id));
                fetch_update_association(ass_id);
                break;
            }
        }
        ass_temp = ass_temp->next;
    }

}


/** fetch the details stored in scope table at ems server & update status if required
 *  @returns void
 *
 */
void update_scope()
{
    char old_status[IP_SIZE];

    memset(old_status,'\0',IP_SIZE);
    strncpy(old_status,(char *)plugin.status , strlen((char *)plugin.status));

    fetch_scope_id((char *)plugin.root_url,(char *)plugin.scope->name);

    /*no change in status*/
    if(strcmp((char *)plugin.status , old_status) == 0)
    {
        return;
    }

    if(strcmp((char *)plugin.scope->name , NOSCOPE) != 0)
    {
        if(strcmp((char *)plugin.status , DISABLED) == 0)
        {
            delete_all_configurations();
            return;
        }

        /*plugin is enable then fetch all configurations*/
        fetch_all_configurations((char *)plugin.root_url,(char *)(plugin.scope)->id);
    }
    else
    {
        SECMON_CRITICAL("ERROR: incorrect scope name\n");
        perror("Error occurs. Please check /var/log/secmon.log file for error\n");
    }
}
