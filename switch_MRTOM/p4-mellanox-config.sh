#sde-9.0.0 need -p option to connect to running program
#./run_pd_rpc-ba102.py -p myprog setup.py && bfshell -f bf_config2.txt

#sde-8.9.0 does not need -p option
CONFIG_DIR=./p4-mellanox
./run_pd_rpc-ba102.py  $CONFIG_DIR/pd_setup.py && bfshell -f $CONFIG_DIR/bf_config.txt && bfshell -b $PWD/$CONFIG_DIR/bfrt_config.py
