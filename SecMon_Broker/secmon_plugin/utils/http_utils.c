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
 *  generate root url to fetch contents from server
 *
 */

#include "common.h"

static CURL *ch = NULL;

/**  generate root url to fetch details from server
 *    @returns void
 *
 */
void generate_ems_base_url(char *address , char *root_url)
{
    memset(root_url,'\0',ROOT_URL_SIZE);

    /*generate "https://ip:port/v1.0/secmon" root url to fetch details*/     
    strncpy(root_url , HTTPS , strlen(HTTPS));
    strncat(root_url , address , strlen(address));
    strncat(root_url , EXT , strlen(EXT));
    strncat(root_url , AGENT , strlen(AGENT)); 
    SECMON_DEBUG("root url=%s\n",root_url);

}

/**  generate url according to root url and arguments
 * 	 fetch the contents from the server
 *   @returns 
 *		response		response from server
 *
 */
char* get_conf_from_ems(char *root_url , char * url , int num,...)
{   
    va_list valist;                         /*to traverse arguments*/
    int index;                              /*loop counter*/ 
    char* response ,                          /*response from curl*/
        add_tags[SIZE];                     /*add on tags*/

    memset(add_tags,'\0',SIZE);

    va_start(valist , num);
    strncpy(add_tags,"",1);

    /*generate addition tags need to add to form url*/
    for(index = 0;index<num;index++)
    {
        strncat(add_tags , EXT , strlen(EXT));
        strcat(add_tags , va_arg(valist , char*));
    }

    va_end(valist);

    strncat(add_tags , EXT , strlen(EXT));

    /*generate url with root_url & add tags*/
    strncpy(url , root_url , strlen(root_url));                   
    strncat(url , add_tags , strlen(add_tags));

    /*fetch contents from server according to url*/
    response = HTTPS_fetch_url(url);

    return response;
}


/** take the contents of web page and store contents
 *  in supplied structure payload
 *  @param contents
 *      contains the contents of page
 *  @param size
 *      contains the size of data
 *  @param  nmemb
 *      contains memory size
 *  @param userp
 *      contains pointer to structure to store content
 *  @returns 
 *      -1  if error in reallocating the memory
 *      size of content in case of success
 *
 */
size_t curl_callback (void *contents ,  size_t size ,  size_t nmemb ,  void *userp)
{   
    size_t realsize  =  size * nmemb;          /* store buffer size */
    struct Curl_Fetch_St *p  =  NULL;          /* pointer to fetch struct */
    p  =  (struct Curl_Fetch_St *) userp; 

    p->payload  =  realloc(p->payload ,  p->size + realsize + 1);
    memset(p->payload,'\0', p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) 
    {
        SECMON_DEBUG("error in re-allocation\n");
        if(p->payload!=NULL)
        {
            free(p->payload);
            p->payload = NULL;
        }

        return FAILURE;
    }

    /*store contents in buffer*/
    memcpy(&(p->payload[p->size]), contents ,  realsize);

    p->size += realsize;
    p->payload[p->size]  =  0;

    return realsize;
}

/** fetch url ,  store its contents in structure 
 *  and returns curl result
 *  @param ch
 *      contains pointer to curl handle
 *  @param url
 *      contains url to fetch
 *  @param fetch
 *      contains structure in which contents will store
 *  @returns
 *      CURLE_FAILED_INIT   if error in allocating the memory
 *      200 in case of success otherwise error in executing curl
 *
 */
CURLcode curl_fetch_url(CURL *ch ,  const char *url ,  struct Curl_Fetch_St *fetch) 
{
    CURLcode rcode;                   /* curl result code */

    fetch->payload  =  (unsigned char *)malloc(sizeof(unsigned char *) * 1);
    memset(fetch->payload,'\0',sizeof(unsigned char *) * 1);

    /* check payload */
    if (fetch->payload == NULL) 
    {
        return CURLE_FAILED_INIT;
    }

    fetch->size  =  0;

    /* set url to fetch */
    curl_easy_setopt(ch ,  CURLOPT_URL ,  url);

    /* set call-back function */
    curl_easy_setopt(ch ,  CURLOPT_WRITEFUNCTION ,  curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ch ,  CURLOPT_WRITEDATA ,  (void *) fetch);

    /* fetch the url */
    rcode  =  curl_easy_perform(ch);

    return rcode;
}

/** initialize curl ,  fetch url contents ,  
 *  check its status ,  return contents if no error 
 *  otherwise return error
 *  @param url
 *      contains url to fetch
 *  @returns
 *      ERROR   error in handling curl or fetching contents
 *      content received in case of success 
 *
 */
char* HTTP_fetch_url(char* url)
{
    SECMON_DEBUG("url to fetch details=%s\n",url);
    CURLcode rcode;                                     /* curl result code */  

    struct Curl_Fetch_St curl_fetch;                    /* curl fetch struct */
    struct Curl_Fetch_St *cf =&curl_fetch;              /* pointer to struct */ 
    long http_code;

    /*initialize curl handle*/
    if (ch == NULL)
    {
        ch = curl_easy_init();                              
        if(ch==NULL)
        {   
            fprintf(stderr ,  "ERROR: Failed to create curl handle\n");

            return ERROR;
        }
    }

    /*fetch contents & get status code of fetch response*/
    rcode  =  curl_fetch_url(ch ,  url ,  cf);

    /*get http response*/
    curl_easy_getinfo(ch ,  CURLINFO_RESPONSE_CODE ,  &http_code);
    SECMON_DEBUG("http code: %lu\n", http_code);

    /* check for error in executing curl */
    if (rcode != CURLE_OK || cf->size < INVALID_RESPONSE_SIZE || http_code!=HTTP_SUCCESS_CODE)
    {
        fprintf(stderr ,  "ERROR: Failed to fetch url (%s) - curl said: %s\n",
                url ,  curl_easy_strerror(rcode));

        return ERROR;
    }

    /*No data */
    if(cf->payload==NULL)
    {
        fprintf(stderr ,  "ERROR: Failed to populate payload\n");

        if(cf->payload!=NULL)
        {
            free(cf->payload);
            cf->payload = NULL;
        }

        return ERROR;
    }

    /*if url is invalid*/
    else if(strstr((char *)cf->payload,"invalid URL")!=NULL)
    {
        fprintf(stderr ,  "ERROR: Invalid URL\n");

        if(cf->payload!=NULL)
        {
            free(cf->payload);
            cf->payload = NULL;
        }

        return ERROR;
    }

    else
    {
        return ((char *)cf->payload);
    }

}


/** initialize curl ,  fetch url contents ,  
 *  check its status ,  return contents if no error 
 *  otherwise return error
 *  @param url
 *      contains url to fetch
 *  @returns
 *      ERROR   error in handling curl or fetching contents
 *      content received in case of success 
 *
 */
char* HTTPS_fetch_url(char* url)
{
    SECMON_DEBUG("url to fetch details=%s\n",url);
    printf("url to fetch details=%s, line[%d]\n",url,__LINE__);
    fflush(stderr);
    CURLcode rcode;                                     /* curl result code */  

    struct Curl_Fetch_St curl_fetch;                    /* curl fetch struct */
    struct Curl_Fetch_St *cf =&curl_fetch;              /* pointer to struct */ 
    long http_code;

    /*initialize curl handle*/
    if (ch == NULL)
    {
        ch = curl_easy_init();                              
        if(ch==NULL)
        {   
            fprintf(stderr ,  "ERROR: Failed to create curl handle\n");

            return ERROR;
        }
    }
      curl_easy_setopt(ch, CURLOPT_VERBOSE, 1L);

      /* disconnect if we can't validate server's cert */ 
      curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0L);

	 /* set the file with the certs vaildating the server */ 
      curl_easy_setopt(ch, CURLOPT_CAINFO, CA_INFO);      
      curl_easy_setopt(ch, CURLOPT_CAPATH, CA_PATH);
       curl_easy_setopt(ch, CURLOPT_SSLCERT, SECMON_CERT);
      curl_easy_setopt(ch, CURLOPT_SSLKEY, SECMON_KEY);

      curl_easy_setopt(ch, CURLOPT_KEYPASSWD, 0);

    /*fetch contents & get status code of fetch response*/
    rcode  =  curl_fetch_url(ch ,  url ,  cf);

    /*get http response*/
    curl_easy_getinfo(ch ,  CURLINFO_RESPONSE_CODE ,  &http_code);
    SECMON_DEBUG("http code: %lu\n", http_code);

    /* check for error in executing curl */
    if (rcode != CURLE_OK || cf->size < INVALID_RESPONSE_SIZE || http_code!=HTTP_SUCCESS_CODE)
    {
        fprintf(stderr ,  "ERROR: Failed to fetch url (%s) - curl said: %s\n",
                url ,  curl_easy_strerror(rcode));

        return ERROR;
    }

    /*No data */
    if(cf->payload==NULL)
    {
        fprintf(stderr ,  "ERROR: Failed to populate payload\n");

        if(cf->payload!=NULL)
        {
            free(cf->payload);
            cf->payload = NULL;
        }

        return ERROR;
    }

    /*if url is invalid*/
    else if(strstr((char *)cf->payload,"invalid URL")!=NULL)
    {
        fprintf(stderr ,  "ERROR: Invalid URL\n");

        if(cf->payload!=NULL)
        {
            free(cf->payload);
            cf->payload = NULL;
	}
	return ERROR;

    }
    else
    {
        return ((char *)cf->payload);
    }


}
