/*    Copyright (c) 2016 Intel Corporation.
 *    All Rights Reserved.
 *
 *    Licensed under the Apache License ,  Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing ,  software
 *    distributed under the License is distributed on an "AS IS" BASIS ,  WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND ,  either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */



#ifndef SERVER_API
#define SERVER_API

/** @file
 *  server header file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json/json.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define RESPONSE_SIZE   2000					/**< Response size of Request */
#define DATA_SIZE       1500					/**< Data size */
#define VALUELEN        100						/**< Length of the Value */
#define MAXCON          5						/**< Maxcon */
#define TABLE           "table_name"			/**< Table Name */
#define OPERATION       "operation"				/**< Operaion */					
#define ROWID           "row_id"				/**< Row ID */
#define DELETE          "DELETE"				/**< Delete */
#define POST            "POST"					/**< Post */
#define PUT             "PUT"					/**< Put */
#define FLUSH           "FLUSH"					/**< Flush */
#define CRLF2            "\r\n\r\n"				/**< CRLF */
#define NOTIFICATION    "notification"			/**< notification */
#define SERVERCONFIGFIE "/opt/secmon/plugins/config/rawforward_server.ini"		/**< Path to server config file */
#define DEFAULTSERVERIP "0.0.0.0"												/**< Default Server IP */

/**
 *	Struct containing information about Notification
 */
struct Notification_Details
{
    char table_name[VALUELEN];
    char id[VALUELEN];
    char operation[VALUELEN];
};

void store_notification(char *,char *);
void handle_ems_notifications();
void read_ip_port(char *,int *);
void get_json_notification(json_object *,char* );
void json_parse_notification_array( json_object *,char*,char*);
void json_parse_notification_object(json_object * );
void json_parse_notification(char* );
int initialize_socket(int *);

void delete_configurations();
void update_configurations();
void add_configurations();

extern struct Notification_Details *notification;

#endif
