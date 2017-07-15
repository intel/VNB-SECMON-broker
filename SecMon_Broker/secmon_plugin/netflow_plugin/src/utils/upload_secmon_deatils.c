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
 *  upload server details running at secmon to receive notification of updating
 *	at ems server into secmon_details table
 *
 */

#include "client.h"
#include "server.h"

/* Post ip address ,  port number ,  scope ,  plugin name & mac address (details)
 *	of server on ems server
 *  @param url
 *      contains url on which details will post
 *  @param  scope
 *      contains scope_id for scope of secmon
 *  @param  server_ip
 *      contains server ip
 *  @returns void
 *
 */
void register_plugin(char *url , char *scope , char *server_ip)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers  =  NULL; 
    const char *data;

    json_object *json; 

    char  ip[IPV4_ADDR_LEN];
    int  port;

    /* get a curl handle */ 
    curl  =  curl_easy_init();

    if(curl) 
    {
        /* set content type */
        headers  =  curl_slist_append(headers ,  ACCEPT_HDR);
        headers  =  curl_slist_append(headers ,  CONTENTTYPE_HDR);

        /*take server ip and port of server on secmon*/
        read_ip_port((char *)ip,&port);

        /*form json data*/
        json  =  json_object_new_object();

        json_object_object_add(json , IP ,  json_object_new_string(ip));
        json_object_object_add(json , SCOPENAME ,  json_object_new_string(scope));
        json_object_object_add(json ,  PORT ,  json_object_new_int(port));
        json_object_object_add(json ,  PLUGINKEY ,  json_object_new_string(NETFLOW));
        json_object_object_add(json , MAC ,  json_object_new_string(SERVER_MAC));

        data = json_object_to_json_string(json);

        curl_easy_setopt(curl ,  CURLOPT_CUSTOMREQUEST , POST);
        curl_easy_setopt(curl ,  CURLOPT_HTTPHEADER ,  headers);

        curl_easy_setopt(curl ,  CURLOPT_POSTFIELDS ,  data);
        curl_easy_setopt(curl ,  CURLOPT_URL , url);

        res  =  curl_easy_perform(curl);

        /* Check for errors */ 
        if(res != CURLE_OK)
            fprintf(stderr ,  "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        curl_easy_cleanup(curl);
    }

    json_object_put(json);
    curl_slist_free_all(headers);
}


/** generate on which serve details will post and post details to server
 *  @param root_url
 *      contains root url 
 *  @param  scope
 *      contains scope_id for scope of secmon
 *  @param  ip
 *      contains server ip
 *  @returns void
 *
 */
void upload_secmon_details(char *root_url , char *scope , char *ip)
{
    char     url[URL_SIZE],
             add_tags[SIZE];

    /*add tags to for complete url & post details*/
    memset(add_tags,'\0',SIZE); 
    strncpy(add_tags,"",1);

    strncat(add_tags , EXT , strlen(EXT));
    strncat(add_tags , SECMONDETAILS , strlen(SECMONDETAILS));
    strncat(add_tags , EXT , strlen(EXT));

    memset(url,'\0',URL_SIZE);
    strncpy(url , root_url , strlen(root_url));
    strncat(url , add_tags , strlen(add_tags));

    register_plugin(&url[0],scope , ip);


}
