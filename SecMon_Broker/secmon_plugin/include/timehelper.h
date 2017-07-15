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


#ifndef _TIMEHELPER_H
#define _TIMEHELPER_H

/** @file
 * header file for handle time
 *
 */

#include <sys/time.h>
#include <time.h>
#include <stdio.h>

#define HZ (1000)						/**< Hertz */
#define MSEC_PER_SEC 1000				/**< Milli-seconds per seconds */
#define USEC_PER_MSEC          1000      /**< Micro-seconds per milli-second */
#define USEC_PER_SEC           1000000   /**< Micro-seconds per second */




unsigned long get_jiffies();

unsigned long jiffies_to_msecs(unsigned long j);

int time_is_before_jiffies(unsigned long a);

int time_is_after_jiffies(unsigned long a);

#endif

