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
 *  parse the contents and get the key & value
 *  call appropriate functions to store them
 *
 */

#include "client.h"
#include "server.h"


/** get the value and call appropriate function to store it
 *  in structure using key
 *  @param jobj
 *      contains value retrived
 *  @param obj
 *      contains type of object which store the value
 *  @param key
 *      contains key of value
 *  @returns void
 *
 */
void get_json_value(json_object *jobj , char* obj , char* key)
{
    enum json_type type;            /*store type of value*/
    char res1[VALUESIZE];           /*store value*/
    int val = 0;                      /*store integer value*/
    double val1 = 0;                  /*store double value*/

    /*Getting the type of the json object*/
    type  =  json_object_get_type(jobj); 
    memset(res1,'\0',VALUESIZE);
    /*retrive different types of values & store in res1*/
    switch (type) 
    {
        case json_type_null:
        case json_type_object:
        case json_type_array:
            strcpy(res1,"");    
            break;
        case json_type_boolean:
            sprintf(res1,"%s",json_object_get_boolean(jobj)? "true": "false");
            break;
        case json_type_double: 
            val1 = json_object_get_double(jobj);
            sprintf(res1,"%f",val1);
            break;
        case json_type_int: 
            val = json_object_get_int(jobj);
            sprintf(res1,"%d",val);
            break;
        case json_type_string:
            strcpy(res1 , json_object_get_string(jobj));
            break;
    }

    /*store status of notifications*/
    if(strcmp(obj , NOTIFICATION) == 0)
    {
        store_notification(key , res1);
        return;
    }

    /*store scope details of plugin*/
    if(strcmp(obj , SCOPE) == 0)
    {
        store_scope(key , res1);
        return;
    }

    /*store association details of plugin*/ 
    if(strcmp(obj , ASSOCIATION) == 0)
    {   
        store_association(key , res1);
        return;
    }

    /*store collector details of plugin*/
    if(strcmp(obj , COLLECTOR) == 0)
    {
        //printf("COLLECTOR: key = %s, res1 = %s\n", key, res1);
        store_collector(key , res1, COL);
        return;
    }

    /*store collector set details of plugin*/
    if(strcmp(obj , COLLECTORSET) == 0)
    {   
        store_collector_set(key , res1);
        return;
    }

    if(strcmp(obj, COLLECTOR_SET_ARRAY) == 0)
    {
        //printf("inside COLLECTOR_SET_ARRAY\n");
        //printf("COLLECTOR_SET_ARRAY key = %s, res1 = %s\n", key, res1);
        store_collector(key, res1 , COLSET);
    }
    /*store policy details of plugin*/
    if(strcmp(obj , POLICY) == 0)
    {
        store_policy(key , res1);
        return;
    }

    /*store rule details of plugin*/
    if(strcmp(obj , RULE) == 0)
    {
        store_rule_ids(key , res1);
        return;
    }

    /*store rule details of plugin*/
    if(strcmp(obj , CLASSIFICATION) == 0)
    {
        store_rule(key , res1);
        return;
    }

    /*add association details of plugin*/ 
    if(strcmp(obj , ADDASSOCIATION) == 0)
    {   
        add_association(key , res1);
        return;
    }

}

/** parse the json array value with corresponding key 
 *  @param jobj
 *      contains value retrived
 *  @param obj
 *      contains type of object which store the value
 *  @param key
 *      contains key of value
 *  @param key1
 *      contains key of value
 *  @returns void
 *
 */
void json_parse_array( json_object *jobj ,  char *key , 
        char* obj , char* key1) 
{
    SECMON_DEBUG("inside json_parse_array\n");
    enum json_type type;                /*to store type of value*/
    json_object *jarray  =  jobj;         /*store value of key*/

    /*check if new array*/
    if(key)
    {
        /*get value of key*/
        // jarray  =  json_object_object_get(jobj ,  key); 
        json_object_object_get_ex(jobj ,  key, &jarray);

    }

    /*take length of array*/
    int arraylen  =  json_object_array_length(jarray); 

    int index;                              /*loop counter*/
    json_object * jvalue;                   /*store array value*/

    for (index = 0; index< arraylen; index++)
    {
        /*take value at i index*/
        jvalue  =  json_object_array_get_idx(jarray ,  index); 
        type  =  json_object_get_type(jvalue);

        /*if array contains another array*/
        if (type == json_type_array)
        {
            key1 = key;
            json_parse_array(jvalue ,  NULL , obj , key1);
        }

        /*get value*/
        else if (type != json_type_object) 
        {
            get_json_value(jvalue , obj , key);
        }

        /*value is object type*/
        else 
        {
            json_parse_object(jvalue , obj);
        }
    }

    json_object_put(jvalue);
    json_object_put(jarray);
}

/** take the response in object form and parse it
 *  @param jobj
 *      contains response/value retrived
 *  @param obj
 *      contains type of object which store the value
 *  @returns void
 *
 */
void json_parse_object(json_object * jobj , char* obj)
{
    enum json_type type;                /*store type*/

    /*take each key , value pair*/
    json_object_object_foreach(jobj ,  key ,  val) 
    {
        /*take type of value to parse*/
        type  =  json_object_get_type(val);

        switch (type) 
        {
            case json_type_null:
            case json_type_boolean: 
            case json_type_double: 
            case json_type_int: 
            case json_type_string: 
                get_json_value(val , obj , key);
                break;

            case json_type_object: 
                // jobj  =  json_object_object_get(jobj ,  key);
                json_object_object_get_ex(jobj ,  key, &jobj);

                json_parse_object(jobj , obj); 
                break;

            case json_type_array: 
                json_parse_array(jobj ,  key , obj , key);
                break;
        }
    }   
} 

/** take the response and parse it
 *  @param response
 *      contains response/value retrived
 *  @param obj
 *      contains type of object which store the value
 *  @returns void
 *
 */
void parse_json_response(char* response , char *obj)
{
    json_object * jobj;             /*store json data*/
    enum json_type type;            /*store type*/

    /*store response in json object and parse it*/
    jobj  =  json_tokener_parse(response);

    type  =  json_object_get_type(jobj);
    if(type==json_type_array)
    {
        json_parse_array(jobj ,  NULL , obj , NULL);
    }
    else
    {
        json_parse_object(jobj , obj);
    }

    json_object_put(jobj);   
}
