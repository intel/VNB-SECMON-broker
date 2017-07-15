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
 *  generate proper url with the root url and arguments supplied &
 *  get the server response
 *
 */
#include "timehelper.h"
#include "constants.h"
/**  
 *  to get jiffies
 *   @returns 
 *      response        response from server
 *
 */
inline unsigned long get_jiffies()
{
    struct timeval tv;
    unsigned long ms;
    gettimeofday(&tv , NULL);
    ms  =  tv.tv_sec * 1000;
    return  ms;
}

/**  
 *   convert jiffies to mili-secs
 *   @returns 
 *      response        response from server
 *
 */
unsigned long jiffies_to_msecs(unsigned long j)
{
    return (MSEC_PER_SEC / HZ) * j;
}

/**  
 *   check time less than current or not
 *   @returns 
 *      response        response from server
 *
 */
int time_is_before_jiffies(unsigned long a)
{
    unsigned long now  =  get_jiffies(); //timespec now();
    if (a <= now)
        return SUCCESS;
    else
        return FAILURE;
}

/**  
 *   check time greater than current or not
 *   @returns 
 *      response        response from server
 *
 */
int time_is_after_jiffies(unsigned long a)
{
    unsigned long now  =  get_jiffies(); //timespec now();
    if (a >= now)
        return SUCCESS;
    else
        return FAILURE;
}

