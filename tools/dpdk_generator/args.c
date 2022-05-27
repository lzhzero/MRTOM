
#include "args.h"
#include <rte_ethdev.h>
#include <rte_timer.h>
#include <string.h>


/* MAC updating enabled by default */
static int mac_updating = 0;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

static const char short_options[] =
    "p:"  /* portmask */
    "q:"  /* number of queues */
    "T:"  /* timer period */
    ;
static const struct option lgopts[] = {
    { CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
    { CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
    {NULL, 0, 0, 0}
};


/* display usage */
static void
mrtom_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n",
	       prgname);
}

static int
mrtom_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;
    /* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/*
 * Parse the command line arguments passed to the application; the arguments
 * which no not go directly to DPDK's EAL.
 */
int parse_args(int argc, char **argv, app_params *p)
{
    
    
  

    
    
    // initialize the environment
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Failed to initialize EAL: %i\n", ret);
    }

    // enable tsc timer
    rte_timer_subsystem_init();

    // advance past the environmental settings
    argc -= ret;
    argv += ret;

    p->nb_ports = NUM_PORTS;
    p->nb_rx_desc = 1024;
    p->nb_rx_queue = 1;
    p->nb_rx_workers = NUM_RX_WORKERS;

      int opt;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;


	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
            p->enabled_port_mask = mrtom_parse_portmask(optarg);
			if (p->enabled_port_mask == 0) {
				printf("invalid portmask\n");
				mrtom_usage(prgname);
				return -1;
			}
			break;

		

		default:
			mrtom_usage(prgname);
			return -1;
		}
	}
    return ret;
}