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

#include <rte_acl.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_timer.h>

#include "args.h"
#include "config.h"
#include "nic.h"
#include "types.h"
#include "worker.h"

static void wait_for_workers(void)
{
    unsigned lcore_id;

    // wait for each worker to complete
    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        if (rte_eal_wait_lcore(lcore_id) < 0)
        {
            LOG_WARN(USER1, "Failed to wait for worker; lcore=%u \n", lcore_id);
        }
    }
}

int main(int argc, char *argv[])
{
    
    app_params p = {0};
    parse_args(argc, argv, &p);
    


    // allocate ring buffers
    
    // allocate parameter struct for each lcore worker
    rx_worker_params rx_params[p.nb_rx_workers];
    mrtom_worker_params mrtom_params[p.nb_tx_workers];
    //mrtom_worker_params *mrtom_params = malloc(sizeof(mrtom_worker_params));

    


    

    
    // Initialize receiving NIC
    init_receive(p.enabled_port_mask, p.nb_rx_queue, p.nb_rx_desc);
    printf("init_receive finished\n");

    // Initialize mrtom rings


    struct rte_ring *mrtom_rings[NUM_TX_WORKERS];
    init_mrtom_rings(mrtom_rings, NUM_TX_WORKERS, DEFAULT_FLOW_RING_SIZE);

    // start receive and transmit workers
    start_workers(rx_params, mrtom_params, mrtom_rings, &p);
    monitor_workers(rx_params, p.nb_rx_workers, mrtom_params, p.nb_tx_workers);

    wait_for_workers();

    return 0;
}
