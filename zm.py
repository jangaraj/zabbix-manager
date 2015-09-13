#!/usr/bin/env python
'''
Created on September 13, 2015

@author: Jan Garaj
@contact: info@monitoringartist.com
@version: 0.0.0

Examples:

    export "ZM_CFGFILE=/etc/zabbix/zm.conf" - Set the path to configuration file
    ./%prog [options]    
    ./%prog -h - show this help message and exit
'''
log = None

import os
import sys
import logging.handlers

# By default all errors go to /var/log/messages
# This can be disabled by setting option syslog to False
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
def init_log(log):
    """ All Errors go to stderr and /var/log/messages"""
    
    log = logging.getLogger('zabbix_manager')
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s " + "%(levelname)s\t%(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)
    
    syslog_handler.setLevel(logging.ERROR)
    formatter = logging.Formatter("zabbix_manager %(levelname)s\t%(message)s")
    syslog_handler.setFormatter(formatter)
    log.addHandler(syslog_handler)
    
    return log

log = init_log(log)

try:
    from optparse import OptionParser, TitledHelpFormatter
    from ConfigParser import SafeConfigParser
    import Queue
except ImportError:
    # Checks the installation of the necessary python modules
    msg = ((os.linesep * 2).join(["An error found importing one module:",
    str(sys.exc_info()[1]), "You need to install it", "Exit..."]))
    log.error(msg)
    sys.exit(msg)
except SyntaxError, e:
    # Checks the installation of the necessary python modules
    msg = (os.linesep * 2).join(["An error found importing one module:",
            str(sys.exc_info()[1]), "You need to install correct versions of libraries (Python 2.6 and boto 2.5.2)", "Exit..."])
    log.error(msg)
    sys.exit(msg)

class OptionsError(Exception): pass
class CommandError(Exception): pass
class TimeOutException(Exception): pass
class TmpFileException(Exception): pass

VERSION = '1.0.0'
BASE_REPO = 'https://github.com/jangaraj/zabbix-manager'



def configure_log_file(conf):
    """If configured then log rotating log file will be used"""

    if conf.log_file_path is not None and conf.log_file_path.strip() != "":
        #if os.path.isfile(conf.log_file_path):
        try:
            handler = logging.handlers.RotatingFileHandler(conf.log_file_path, mode='a', maxBytes=100000, backupCount=3)
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(asctime)s " + "%(levelname)s\t%(message)s")
            handler.setFormatter(formatter)        
            log.addHandler(handler)
        except Exception, (errno):
            log.error("Could not open the log file %s - %s" % (conf.log_file_path, errno))
    
    if conf.syslog == False:
        log.removeHandler(syslog_handler)        

def buildParams(cfg, parser):
    # Required options   
    defcfg = cfg.defaults()

    # Optional
    parser.add_option('--config-file', dest='config_file', type="string", default=None,
        help='path to config file. Can be provided by --config-file or ENV')

    parser.add_option('--log-file-path', dest='log_file_path', type="string",
        help='path to log file. Default is disabled (None)', default=defcfg.get("log-file-path", None))

    parser.add_option('--syslog', action="store_true", dest='syslog',
        help='send all script errors syslog (/var/log/messages), Default is enabled', default=defcfg.get("syslog", "True") == "True")

    parser.add_option('--OID', dest='OID', type="string", default=defcfg.get("OID", "1.3.6.1.4.1.2333.3.2.545"),
        help='Full OID for the trap e.g. 1.3.6.1.4.1.2333.3.2.545')

    parser.add_option('--runbook', dest='runbook', type="string",
        default=defcfg.get("runbook", "https://confluence.dev.bbc.co.uk/display/men/Zenoss+Event+Class+Run+Book+for+_Status_MonUtils"),
        help='URL to app\'s run book')

    parser.add_option('--check-time-out', dest='check_time_out', type="int",
        default=defcfg.get("check-time-out", 5), help='Timeout (seconds) after which monitor will be killed')

    parser.add_option('--snmp-trap-targets', dest='snmp_trap_targets', type="string",
                      default=defcfg.get("snmp-trap-targets", "172.23.66.51 172.23.66.52 "\
                       "172.23.59.66 172.23.59.67 10.56.162.47 10.160.202.22"),
                      help='Default SNMP TRAP TARGETS (if SNMP_TRAP_TARGETS environment variable is not defined)')

    parser.add_option('--snmp-trap-target-env', dest='snmp_trap_target_env', type="string",
                      default=defcfg.get("snmp-trap-target-env", "SNMP_TRAP_TARGETS"),
                      help='Default name of SNMP trap destination environment variable')

    parser.add_option('--snmptrap-cmd', dest='snmptrap_cmd', type="string",
                      default=defcfg.get("snmptrap-cmd", "/usr/bin/snmptrap -d -v 2c -c public"),
                      help='Default snmptrap command')
    
    parser.add_option('--json-file-path', dest='json_file_path', type="string",
                      default=defcfg.get("json-file-path", "/usr/share/bbc-monitoring-utils"),
                      help='Default file path for storing of json output files')
                      
    parser.add_option('--state-file-path', dest='state_file_path', type="string",
        default=defcfg.get("state-file-path", "/usr/share/bbc-monitoring-utils"),
        help='File path for preserving last state of checks')                      
    
    parser.add_option('--retry-attempts', dest='retry_attempts', type="int",
                      default=defcfg.get("retry-attempts", "1"),
                      help='Number of attempts for monitor run, when monitor is reaching predefined execution timeout')    

    parser.add_option('--verify', action="store_true", dest='verify',
        help='Do not send any SNMP data/traps. Just verify.', default=defcfg.get("verify", "False") == "True")

    parser.add_option('-v', '--verbose', dest='verbose', type="int", help='Verbose level - 0 default is None', default=defcfg.get("verbose", 0))

    return parser

def readCommadLine(env, arguments, usage):
    """Read the command line -  returns options"""
    config_file = os.environ.get(env, None)
    
    is_help = False

    if not config_file:
        try:
            # If config_file in command line parse it
            config_file = [arg.split("=")[1] for arg in arguments if "--config-file" in arg][0]
        except (ValueError, IndexError): pass

    parser = OptionParser(usage, version="%s" % VERSION, formatter=TitledHelpFormatter(width=255, indent_increment=4))
    cfg = SafeConfigParser()

    if is_help == False:
        if config_file is None or not os.path.isfile(config_file):
            raise OptionsError("config-file %s does not exist. Specify path to configuration "\
                "file in environment %s or in command line --config-file" % (str(config_file), str(env)))
        try:
            cfg.read(config_file)
        except:
            raise OptionsError("reading config-file %s." % (str(config_file)))        

    buildParams(cfg, parser)    
    options, args = parser.parse_args(arguments)
    options.sections = {}
    for section in cfg.sections():
        options.sections[ section ] = {'config': cfg.get(section, 'config'),
                                       'keys':  cfg.get(section, 'keys'),
                                       'package':  cfg.get(section, 'package')}
    return options


def runMain(arguments, output=sys.stdout):
    """The main function"""

    usage = """
    %prog [options]
    
      Script to fetching of system stats from mpstat/iostat/nestat/forks (vmstat -f)
      
Examples:
    
    export "MON_CFGFILE=/usr/local/etc/monitoring-utils.conf" - Set the path to configuration file
    ./%prog [options]    
    ./%prog -h - show this help message and exit
    ./%prog -v <value> - enable verbose output, for debug use value 4"""

    status = 0

    log.setLevel(logging.ERROR)
    # TODO
    conf = readCommadLine("MON_CFGFILE", arguments, usage)        
    
    if conf.verbose > 0:
        log.setLevel(logging.INFO)
    
    if conf.verbose > 3:
        log.setLevel(logging.DEBUG)
    
    configure_log_file(conf)    
    errors = Queue.Queue()
    log.debug("starting zm.py")
        
    # TODO param switch
           
    return status    

if __name__ == '__main__': 
    runMain(sys.argv[1:])
