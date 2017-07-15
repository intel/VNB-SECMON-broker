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
 *  generate collect field value from list of collect fields supplied
 *
 */

#include "client.h"


/**  generate collect field value according to list
 *	 @returns 
 *		val		collect_field value
 *
 */
int calculate_collect_field(char values[][FIELD_VALUE_SIZE],int num)
{
    int val = 0 , index = num-1;

    if(strcmp(values[index],COLLECNEXTHOPADD) == 0)
    {
        val = 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],COLLECTIPV4TTL) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],COLLECTIPV4LEN) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],COLLECTINTERFACE) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],COLLECTFLOWDIR) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],COLLEC_VLAN) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],COLLEC_MAC) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],VLANNAME) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],MACADDRESS) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],FLOWACESSTIME) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],COLLECTCOUNTER) == 0)
    {
        val = val | 1;
    }

    return val;

}

/**  take list of collect fields ,  separate them & store them
 *	 according to each value generate integer value
 *	 @returns 
 *			collect_value   collect_field value
 *
 */
int generate_collect_field(char *values)
{
    int collect_value = 0 , number = 0;
    char *store_value , 
         *token , 
         *delimator  =  ",\n";
    char fields[NUMCOLLECTFIELDS][FIELD_VALUE_SIZE];

    store_value = malloc(SIZE *sizeof(char));

    memset(store_value,'\0',SIZE);
    memcpy(store_value , values , strlen(values));

    /*tokenize values*/
    token = strtok(store_value , delimator);

    while(token!=NULL)
    {
        /*store tokens in fields*/
        strcpy(fields[number],token);

        if(number<=NUMCOLLECTFIELDS)
        {
            number++;
        }
        else
        {
            SECMON_DEBUG("extra collect fields.Ignoring it\n");
            break;
        }

        token = strtok(NULL , delimator);
    }

    collect_value = calculate_collect_field(fields , number);

    return collect_value;
}


/**  generate match field value according to list
 *   @returns 
 *      val   match_field value
 *
 */
int calculate_match_field(char values[][FIELD_VALUE_SIZE],int num)
{
    int val = 0 , index = num-1;

    /*generate value*/
    if(strcmp(values[index],VLANNAME) == 0)
    {
        val = 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],MACADDRESS) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],ININTERFACE) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],DESTPORT) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],SRCPORT) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],DSTADDRESS) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],SRCADDRESS) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],MATCHPROTOCOL) == 0)
    {
        val = val | 1;
        index--;
    }
    val = val<<1;

    if(strcmp(values[index],TOS) == 0)
    {
        val = val | 1;
    }
    val = val<<1;
    val = val | 1;

    return val;

}

/**  take list of match fields ,  separate them & store them
 *   according to each value generate integer value
 *   @returns 
 *      match_value  match_field value
 *
 */
int generate_match_field(char *values)
{
    int match_value = 0 , number = 0;
    char *store_value , 
         *token , 
         *delimator  =  ",\n";
    char fields[NUMMATCHFILEDS][FIELD_VALUE_SIZE];

    store_value = malloc(SIZE *sizeof(char));

    /*copy values*/
    memset(store_value,'\0',SIZE);
    memcpy(store_value , values , strlen(values));

    /*tokenize values*/
    token = strtok(store_value , delimator);

    while(token!=NULL)
    {
        /*store tokens in fields*/
        memset(fields[number],'\0',FIELD_VALUE_SIZE);
        strncpy(fields[number],token , strlen(token));

        if(number<=NUMMATCHFILEDS)
        {
            number++;
        }
        else
        {
            SECMON_DEBUG("extra match fields.Ignoring it\n");
            break;
        }

        token = strtok(NULL , delimator);
    }

    match_value = calculate_match_field(fields , number);

    return match_value;
}

