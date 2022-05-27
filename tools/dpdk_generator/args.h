#include <getopt.h>
#include <libconfig.h>
#include <rte_ethdev.h>
#include <rte_memory.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "types.h"
#include "config.h"
#include <stdbool.h>

/**
 * Parse the command line arguments passed to the application.
 */
int parse_args(int argc, char **argv, app_params *app);