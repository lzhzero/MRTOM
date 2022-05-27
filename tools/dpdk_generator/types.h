/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef METRON_TYPES_H
#define METRON_TYPES_H

#include "header.h"
#include <rte_acl.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_memory.h>

/* How many telemetry packets per kafka message. */
#define KAFKA_BATCH_SIZE 32 

/* Max number of flow entries*/
#define MAX_FLOW_ENTRIES 1024

/*Num of histogram buckets in current prototype*/
#define HISTOGRAM1_BUCKET_NUM 10

/*
 * Allow strings to be used for preprocessor #define's
 */
#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

 typedef int bool;
#define true 1
#define false 0

#define valid(s) (s == NULL ? false : strlen(s) > 1)

/*
 * Allows unused function parameters to be marked as unused to
 * avoid unnecessary compile-time warnings.
 */
#ifdef __GNUC__
#define UNUSED(x) UNUSED_##x __attribute__((__unused__))
#else
#define UNUSED(x) UNUSED_##x
#endif

/*
 * Logging definitions
 */
#define LOG_ERROR(log_type, fmt, args...) RTE_LOG(ERR, log_type, fmt, ##args);
#define LOG_WARN(log_type, fmt, args...)                                       \
    RTE_LOG(WARNING, log_type, fmt, ##args);
#define LOG_INFO(log_type, fmt, args...) RTE_LOG(INFO, log_type, fmt, ##args);

#ifdef DEBUG
#define LOG_LEVEL RTE_LOG_DEBUG
#define LOG_DEBUG(log_type, fmt, args...) RTE_LOG(DEBUG, log_type, fmt, ##args);
#else
#define LOG_LEVEL RTE_LOG_INFO
#define LOG_DEBUG(log_type, fmt, args...)                                      \
    do                                                                         \
    {                                                                          \
    } while (0)
#endif



/*
 * Application configuration parameters.
 */
typedef struct
{
    /* The number of receive descriptors to allocate for the receive ring. */
    uint16_t nb_rx_desc;

    /* The number of receive queues to set up for each ethernet device. */
    uint16_t nb_rx_queue;

    
    /* Defines which ports packets will be consumed from. */
    unsigned int enabled_port_mask;

    
    /* The number of receive workers. */
    unsigned int nb_rx_workers;

    
    /* The number of NIC ports from which packets will be consumed. */
    unsigned int nb_ports;


} app_params __rte_cache_aligned;


/*
 * Tracks packet processing metrics.
 */
typedef struct
{
    uint64_t in;
    uint64_t out;
    uint64_t depth;
    uint64_t drops;
    uint64_t ring_space;
    /* save previous in counter - required to calculate rate with periodic
     * readouts */
    uint64_t in_prev;
    uint64_t out_prev;
} app_stats __rte_cache_aligned;

/*
 * The parameters required by a receive worker.
 */
typedef struct
{
    /* worker identifier */
    uint16_t worker_id;

    /* queue identifier from which packets are fetched */
    uint16_t queue_id;

    /* how many packets are pulled off the queue at a time */
    uint16_t rx_burst_size;

    /* Defines which ports packets will be consumed from. */
    unsigned int enabled_port_mask;

    /* Defines which ports packets will be consumed from. */
    unsigned int nb_ports;

    unsigned int port_id;


    /* the ring onto which the packets are enqueued */
    struct rte_ring *output_ring;

    /* metrics */
    app_stats stats;

} rx_worker_params __rte_cache_aligned;


/*
 * The parameters required by a mrtom worker.
 */
typedef struct
{
    /* worker identifier */
    uint16_t worker_id;

    
    /* how many packets are pulled off the queue at a time */
    uint16_t rx_burst_size;

    
    /* the ring onto which the packets are enqueued */
    struct rte_ring *input_ring;

    /* metrics */
    app_stats stats;

} mrtom_worker_params __rte_cache_aligned;







#endif
