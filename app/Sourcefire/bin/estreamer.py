#!/usr/bin/env python
import os
import sys
import subprocess
import ConfigParser
import re
from SplunkLogger import SplunkLogger

# Setup app path
APP_PATH        = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', 'Sourcefire')
APP_BIN_PATH    = os.path.join(APP_PATH, 'bin')
CONFIG_FILE     = os.path.join(APP_PATH, 'default', 'config.ini')
TMP_PATH        = os.path.join(APP_PATH, 'tmp')
LOG_PATH        = os.path.join(APP_PATH, 'log')
OUTPUT_FILE     = os.path.join(LOG_PATH, 'estreamer.log')
PID_PREFIX      = "estreamer.pid."
PID_PREFIX_FILENAME = os.path.join(TMP_PATH, PID_PREFIX)
SCRIPT_NAME     = 'ssl_test.pl'
START_SCRIPT    = os.path.join(APP_BIN_PATH, SCRIPT_NAME)

# Read config file
Config = ConfigParser.ConfigParser()
Config.read(CONFIG_FILE)
ESTREAMER_SERVER = Config.get('server', 'ip')
# Still need to get splunkLogger to work with stdout from subprocess.Popen(),
# so we don't have to write directly to output_log.
#
#MAX_BYTES       = Config.getint('logging', 'maxBytes')
#BACKUP_COUNT    = Config.getint('logging', 'backupCount')
#splunkLogger = SplunkLogger(OUTPUT_FILE, MAX_BYTES, BACKUP_COUNT)

def is_process_running():
    ''' Check whether or not estreamer.pid.* file exists in tmp directory.
        If exists, verify it, and return True.
        Else return False.
    '''
    is_running = False
    files = os.listdir(TMP_PATH)
    for filename in files:
        if (re.match(PID_PREFIX, filename)):
            # Verify that the process actually is running
            pid = filename[filename.rindex(".")+1:]
            ps = subprocess.Popen("ps -f -p %s | grep %s" % (pid, SCRIPT_NAME), stdout=subprocess.PIPE, shell=True)
            ps_output = ps.stdout.read()
            if (ps_output == '' or ps_output is None):
                # The process is no longer running, delete tmp file and start it.
                os.remove(os.path.join(TMP_PATH, filename))
            else:
                is_running = True
    return is_running

# If no running process, start it.
if (not is_process_running()):
    # This write output to file directly
    output_logfile = file(OUTPUT_FILE, 'w')
    estreamer = subprocess.Popen("%s %s -o splunk" % \
                                 (START_SCRIPT, ESTREAMER_SERVER), stdout=output_logfile, cwd=APP_BIN_PATH, shell=True)
    # Write pid to tmp directory, so we can find it again next time the script runs.
    pid_file = open("%s%s" % (PID_PREFIX_FILENAME, estreamer.pid), 'w')
    pid_file.close()