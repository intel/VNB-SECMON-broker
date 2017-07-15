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
 *  initialize server and receive updating notifications from server & handles it
 *
 */

#include <signal.h>

#include "client.h"
#include "server.h"


struct Notification_Details *notification = NULL;

/**  initialize socket for server ,  waits for connection ,  accept the connection
 *	 then get the response contain the notification of updating 
 *	 & handles the notification
 *   @returns void
 *
 */
void handle_ems_notifications()
{
    int socket_descriptor , connection_descriptor , error;
    char    data[RESPONSE_SIZE],
            *data_point , 
            *content;
    struct  sockaddr_in client_addr;
    socklen_t len;
    char response[]=SUCCESS_REPLY;							/*response message from server*/

    notification = malloc(sizeof(struct Notification_Details));

    /*initialize socket for server*/
    error = initialize_socket(&socket_descriptor);

    /*error in initializing the socket for server*/
    if(error == FAILURE)
    {
        SECMON_CRITICAL("ERROR:NETFLOW server can't able to start\n");
        perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");

        if(notification!=NULL)
        {
            free(notification);
        }
        return;        
    }

    /*continusly waiting for receiving responses*/
    for(;;)
    {
        printf("\n\t....Netflow Server Is Running....\n");
        printf("..Waiting for response....\n");
        fflush(stdout);

        len = sizeof(client_addr);

        /*accept connection from client*/
        connection_descriptor  =  accept(socket_descriptor ,  (struct sockaddr*)&client_addr ,  &len);

        /*error in accepting connection*/
        if ( connection_descriptor < 0)
        {
            SECMON_CRITICAL("ERROR:NETFLOW can't able to accept connection\n");
            perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");

            if(notification!=NULL)
            {
                free(notification);
            }
            break;
        }

        /*receive response from client*/
        memset(data,'\0',RESPONSE_SIZE);
        recv(connection_descriptor , data , sizeof(data),0);

        /*send reply to client*/
        if(strstr(data, "GET")!=NULL)
        {
          printf("NETFLOW: sending ACK\n");
            //printf("inside if, GET received in request");
            fflush(stdout);
            if(send(connection_descriptor  , response  ,  strlen(response)  ,  0) < 0)
            {
                SECMON_CRITICAL("ERROR:NETFLOW Send failed for GET request\n");
                return;
            }
            //printf("response sent:%s", response);
            close(connection_descriptor);
            continue;
        }
        if( send(connection_descriptor  , response  ,  strlen(response)  ,  0) < 0)
        {
            SECMON_CRITICAL("ERROR:NETFLOW Send failed\n");
            perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");

            if(notification!=NULL)
            {
                free(notification);
            }
            return;
        }

        close(connection_descriptor);
        data_point=&data[0];

        content = malloc(DATA_SIZE * sizeof(char));
        memset(content,'\0',DATA_SIZE);
        content = strstr(data_point , CRLF2);
        SECMON_DEBUG("received.,%s..",content);

        memset(notification,'\0',sizeof(struct Notification_Details));
        fwait(netflow_rule_futex);

        parse_json_response(content , NOTIFICATION);

       SECMON_DEBUG( "\n\ntab=%s id=%s operation=%s\n",notification->table_name , notification->id , notification->operation);
        //printf("\n\ntab=%s id=%s operation=%s\n",notification->table_name , notification->id , notification->operation);
        /*handle the notification according to operation*/
        if(strcmp(notification->operation , FLUSH)==0)
        {
            /*request to flush all hash entries if its secmon scope*/

            SECMON_DEBUG("flush\n");
            if(strcmp(notification->id,(char *)plugin.scope->id)==0)
            {
                SECMON_INFO("scope matched\n");
                flush_netflow_hash_table();
            }
            fpost(netflow_rule_futex);

            continue;
        }

        else if(strcmp(notification->operation , DELETE)==0)
        {
            delete_configurations(); 
            fpost(netflow_rule_futex);
            continue;
        }
        else if(strcmp(notification->operation , POST)==0)
        {
            add_configurations();
            fpost(netflow_rule_futex);
            continue;
        }
        else if(strcmp(notification->operation , PUT)==0)
        {
            update_configurations();
            fpost(netflow_rule_futex);
            continue;
        }
        else
        {
            SECMON_CRITICAL("ERROR:NETFLOW in correct operation\n");
            perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");
            fpost(netflow_rule_futex);
            continue;
        }
        fpost(netflow_rule_futex);
        free(content);
    }    
}


/**  called by handle_EMS_notifications to initialize server by create socket
 * 	 store its value in socket_descriptor for further server processing & bind
 *   server to that socket_descriptor to receive notifications
 *   @param socket_descriptor
 *      will contains the created socket value for further server handling
 *   @returns void
 *
 */
int initialize_socket(int *socket_descriptor)
{
    struct sockaddr_in server_addr;
    char ip[IPV4_ADDR_LEN];
    int  port;

    /*read ip & port of server*/
    read_ip_port((char *)ip,&port);
    printf("server ip=%s & port=%d\n",ip , port);

    memset(&server_addr,'\0',sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    server_addr.sin_addr.s_addr = inet_addr(DEFAULTSERVERIP);

    /*create socket with server address & bind server with created socket
      to receive notifications*/
    *socket_descriptor = socket(AF_INET , SOCK_STREAM , 0);
    if(*socket_descriptor<0)
    {
        SECMON_CRITICAL("ERROR:NETFLOW error in creating socket for server\n");
        perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");
        return FAILURE;
    }

    if(bind(*socket_descriptor,(struct sockaddr*)&server_addr , sizeof(server_addr))<0)
    {
        SECMON_CRITICAL("ERROR:NETFLOW bind failed\n");
        perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");
        return FAILURE;
    }

    listen(*socket_descriptor , MAXCON);

    return SUCCESS;
}


/** read config file and take ip address & port number 
 *  of server
 *  @param ip
 *      will contain ip address of secmon server
 *  @param port
 *      will contain port  of secmon server
 *  @returns void
 *
 */
void  read_ip_port(char *ip , int *port)
{
    FILE *p_config_file  =  NULL;                 /*pointer to config file*/
    char temp[PORT_SIZE];

    p_config_file  =  fopen(SERVERCONFIGFIE ,  "r");

    /*can't able open file*/
    if(NULL == p_config_file)
    {
        SECMON_CRITICAL("ERROR:NETFLOW Could not open the server config file\n");
        perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");
        exit(EXIT0);
    }

    /*Read the Server Ip and Server Port Number from the config file*/
    fscanf(p_config_file  ,  "%*[^0123456789]%[^\n] %*[^0123456789]%[^\n] ",
            ip ,  temp);

    *port = atoi(temp);

    fclose(p_config_file);

}


/** store notification comes in response for further processing the notification
 *  @param key
 *      contains key
 *  @param  value
 *      contains value according to key
 *  @returns void
 *
 */
void store_notification(char *key , char *value)
{
    /*store operation ,  configuration & id of configuration*/
    if(strcmp(key , TABLE)==0)
    {
        strncpy(notification->table_name , value , strlen(value));
        return;
    }

    if(strcmp(key , ROWID)==0)
    {
        strncpy(notification->id , value , strlen(value));
        return;
    }

    if(strcmp(key , OPERATION)==0)
    {
        strncpy(notification->operation , value , strlen(value));
        return;
    }
}

/**  called by server when notification comes to update a configuration
 *   then it checks which configuration needs update ,  according to it
 *   call appropriate client api
 *   @returns void
 *
 */
void update_configurations()
{
    char *curr_configuration = notification->table_name;

    /*check which configuration need to update by checking 
      table name in notification & then update it*/
    if(strcmp(curr_configuration , SCOPE)==0)
    {
        update_scope();
        return;
    }

    if(strcmp(curr_configuration , PLUGINASSOCIATION)==0)
    {
        fetch_update_association(notification->id);
#ifdef SECMON_DEBUG_LOG
//        print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , COLLECTOR)==0)
    {
        fetch_update_collector(notification->id);
#ifdef SECMON_DEBUG_LOG
 //       print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , POLICY)==0)
    {
        fetch_update_policy(notification->id);
#ifdef SECMON_DEBUG_LOG
 //       print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , RULE)==0)
    {
        fetch_update_rule_ids(notification->id);
#ifdef SECMON_DEBUG_LOG
//        print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , CLASSIFICATION)==0)
    {
        fetch_update_rule(notification->id);
#ifdef SECMON_DEBUG_LOG
//        print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , NETFLOWCONFIG)==0)
    {
        update_netflow_config();
#ifdef SECMON_DEBUG_LOG
//        print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , NETFLOWMONITOR)==0)
    {
        update_netflow_monitor();
#ifdef SECMON_DEBUG_LOG
//        print_configurations();
#endif
        return;
    }

	if(strcmp(curr_configuration, COLLECTORSET) == 0)
    {
        fetch_update_collectorset(notification->id);
        return;
    }

    else
    {
        SECMON_INFO("invalid notification\n");
        return;
    }
}


/**  called by server when notification comes to add a new configuration
 *   then it checks its a request to add association ,  if its
 *	 then call client api to add new association otherwise denied the operation
 *   @returns void
 *
 */
void add_configurations()
{
    char *curr_configuration = notification->table_name;

    /*check the notification comes to add association or not*/
    if(strcmp(curr_configuration , PLUGINASSOCIATION)==0)
    {
        fetch_add_association(notification->id);
#ifdef SECMON_DEBUG_LOG
        SECMON_DEBUG( "after addition\n");
//        print_configurations();
#endif
        return;
    }
    else
    {
        SECMON_CRITICAL("ERROR:NETFLOW Permission denied! Can't add the requested configuration - curr_configuration %s and expected - %s\n", curr_configuration, PLUGINASSOCIATION);
        perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");
        return;
    }
}


/**  called by server when notification comes to delete a configuration
 *   then it checks if configuration is association or collector or rule or rule object
 *	 if its one of them then checks which one is to delete according to it
 *   call appropriate client api otherwise denied the operation
 *   @returns void
 *
 */
void delete_configurations()
{
    char *curr_configuration = notification->table_name;

    /*check which configuration need to delete by checking 
      table name in notification & then delete it*/   
    if(strcmp(curr_configuration , PLUGINASSOCIATION)==0)
    {
        delete_association(notification->id);
#ifdef SECMON_DEBUG_LOG
//        print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , COLLECTOR)==0)
    {
        delete_collector(notification->id);
#ifdef SECMON_DEBUG_LOG
 //       print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , RULE)==0)
    {
        delete_rule_ids(notification->id);
#ifdef SECMON_DEBUG_LOG
 //       print_configurations();
#endif
        return;
    }

    if(strcmp(curr_configuration , CLASSIFICATION)==0)
    {
        delete_rule(notification->id);
#ifdef SECMON_DEBUG_LOG
 //       print_configurations();
#endif
        return;
    }

    /*invalid delete operation*/
    else
    {
        SECMON_CRITICAL("ERROR:NETFLOW Permission denied! Can't delete netflow the requested configuration - curr_configuration %s\n", curr_configuration);
        perror("Error occur netflow. Please check /var/log/secmon.log file for error\n");	
        return;
    }
}


