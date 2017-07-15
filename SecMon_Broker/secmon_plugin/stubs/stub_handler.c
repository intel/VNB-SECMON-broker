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
 *	stub for handler to send notification server
 *
 */
#include "test.h"

/** stub to read server details
 *  @param ip
 *      will contain ip address of secmon server
 *  @param port
 *      will contain port  of secmon server
 *  @returns void
 *
 */
void  read_server_details(char *ip , char *port)
{
    FILE *p_config_file  =  NULL;                 /*pointer to config file*/

    p_config_file  =  fopen(SERVERCONFIGFIE ,  "r");

    /*can't able open file*/
    if(NULL == p_config_file)
    {
        syslog(LOG_CRIT|LOG_LOCAL0,"Could not open the server config file\n");
        exit(EXIT0);
    }

    /*Read the Server Ip and Server Port Number from the config file*/
    fscanf(p_config_file  ,  "%*[^0123456789]%[^\n] %*[^0123456789]%[^\n] ",
            ip ,  port);

    fclose(p_config_file);

}

/** stub to send notification to secmon server like handler
 *  @param url
 *      contains url on which details will post
 *  @param  tab_name
 *      contains configuration to update
 *  @param  id_val
 *      contains id of configuration
 *  @param  op
 *      contains operation
 *  @returns void
 *
 */
void send_notification_stub(char* url , char* tab_name , char *id_val , char* op)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers  =  NULL; 
    const char *data;
    json_object *json; 

    /* get a curl handle */ 
    curl  =  curl_easy_init();

    if(curl) 
    {

        /* set content type */
        headers  =  curl_slist_append(headers ,  "Content-Type: application/json");

        /*form json data*/
        json  =  json_object_new_object();

        json_object_object_add(json , TABLE ,  json_object_new_string(tab_name));
        json_object_object_add(json , ROWID ,  json_object_new_string(id_val));
        json_object_object_add(json , OPERATION ,  json_object_new_string(op));

        data = json_object_to_json_string(json);

        curl_easy_setopt(curl ,  CURLOPT_CUSTOMREQUEST , POST);
        curl_easy_setopt(curl ,  CURLOPT_HTTPHEADER ,  headers);

        curl_easy_setopt(curl ,  CURLOPT_POSTFIELDS ,  data);
        curl_easy_setopt(curl ,  CURLOPT_URL , url);

        res  =  curl_easy_perform(curl);

        /* Check for errors */ 
        if(res != CURLE_OK)
            fprintf( stderr ,  "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        curl_easy_cleanup(curl);
    }

    json_object_put(json);
    curl_slist_free_all(headers);
}

/**	handler stub ,  creating a notification 
 *	& send it to server
 *
 */
void handler_stub()
{
    char exit='N';
    char tab_name[VALUELEN],id_name[VALUELEN],op_name[VALUELEN];
    char url[SIZE];
    char ip[IPV4_ADDR_LEN];
    char port[PORT_SIZE];

    read_server_details((char *)ip,(char *)port);

    memset(url,'\0',SIZE);
    strncpy(url , HTTP , strlen(HTTP));
    strncat(url , ip , strlen(ip));
    strncat(url , EXT1 , strlen(EXT1));
    strncat(url , port , strlen(port));
    strncat(url , EXT , strlen(EXT));

    do
    {
        memset(tab_name,'\0',VALUELEN);					
        memset(id_name,'\0',VALUELEN);					
        memset(op_name,'\0',VALUELEN);					

#ifdef NETFLOW_PLUGIN
        printf("\nOperating tables:\n\tscope\n\tnetflowassociation\n\tcollector\n\tpolicy\n\truleobject");
        printf("\n\tclassificationobject\n\tnetflowconfig\n\tnetflowmonitor\nEnter table name: ");
#elif SFLOW_PLUGIN
        printf("\nOperating tables:\n\tscope\n\tsflowassociation\n\tcollector\n\tpolicy\n\truleobject");
        printf("\n\tclassificationobject\n\tsflowconfig\nEnter table name: ");
#else
        printf("\nOperating tables:\n\tscope\n\trawforwardassociation\n\tcollector\n\tpolicy\n\truleobject");
        printf("\n\tclassificationobject\nEnter table name: ");
#endif

        scanf("%s",tab_name);

        printf( "\nEnter row id(id of configuration): ");
        scanf("%s",id_name);

        printf( "\noperations-\n\tFLUSH(to clean all data)\n\tDELETE (for deletion)\n\tPOST(to add)\n\tPUT(to update)\nEnter operation: ");
        scanf("%s",op_name);

        send_notification_stub(url , tab_name , id_name , op_name);

        getchar();
        printf("\nEnter y or Y to exit!. Enter your choice: ");
        scanf("%c",&exit);
    }
    while( (exit!='y') && (exit!='Y') );

}


/** stub for handler to send notification to server
 *
 */
int main()
{
    handler_stub();	

    return SUCCESS;
}
