try:
    mcg1  = mc.mgrp_create(1)
except:
    print """
clean_all() does not yet support cleaning the PRE programming.
You need to restart the driver before running this script for the second time
"""
    quit()

node1 = mc.node_create(
    rid=5,
    port_map=devports_to_mcbitmap([152, 160, 168]),
#    port_map=devports_to_mcbitmap([146, 144, 160]),
    lag_map=lags_to_mcbitmap([]))
mc.associate_node(mcg1, node1, xid=0, xid_valid=False)
