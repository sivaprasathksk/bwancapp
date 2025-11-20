
BWANCAPP_DESCRIPTION = """
    BWANCAPP is a script by Mohanad Elamin. Modified by Siva Prasath K S K to port graphql calls to REST API calls.

    BWANCAPP Help configure, query Netskope Borderless SDWAN tenant custom apps in bulk via GraphQL API calls
    Requirements:
        python >= 3.11 (it should work with any version > 3 but I've only tested
                        it with 3.11)

        third-party libraries:
            requests >= 2.31.0   (http://docs.python-requests.org/en/latest/)
            tabulate
        You should be able to install the third-party libraries via pip (or pip3
        depending on the setup):

            pip3 install requests
            pip3 install tabulate
"""

BWANCAPP_VERSION = "2025-11-20_00"
CONFIG_FILENAME = "~/.bwanCapp.conf"
#
# Any of these can be customized in the configuration file, for example:
#
#    $ cat ~/.bwanCapp.conf
#    [bwan_config]
#    # auth details
#    tenant_url=
#    api_token=

import os
import sys
import json
from wsgiref import headers
import tabulate
import argparse
import csv

from configparser import ConfigParser
from logging import basicConfig as logging_basicConfig, \
    getLogger as logging_getLogger, \
    DEBUG   as logging_level_DEBUG, \
    INFO    as logging_level_INFO,  \
    WARN    as logging_level_WARN,  \
    ERROR   as logging_level_ERROR, \
    debug   as debug,   \
    info    as info,    \
    warning    as warn,    \
    error   as error


from requests import Session as RQ_Session

#
# 256 color terminal color test:
#
# print("FG | BG")
# for i in range(256):
#    # foreground color | background color
#    print("\033[48;5;0m\033[38;5;{0}m #{0} \033[0m | "
#            "\033[48;5;{0}m\033[38;5;15m #{0} \033[0m".format(i))
#
LOGGING_LEVELS = {
    'ERROR' : {
        'level' : logging_level_ERROR,
        'name'  : 'ERROR',
        'xterm' : '31m',
        '256color': '38;5;196m',
    },
    'NORMAL' : {
        'level' : 35,
        'name'  : 'CAD',
        'xterm' : '37m',
        '256color': '38;5;255m',
    },
    'WARNING' : {
        'level' : logging_level_WARN,
        'name'  : 'WARNING',
        'xterm' : '33m',
        '256color': '38;5;227m',
    },
    'INFO' : {
        'level' : logging_level_INFO,
        'name'  : 'INFO',
        'xterm' : '36m',
        '256color': '38;5;45m',
    },
    'DEBUG' : {
        'level' : logging_level_DEBUG,
        'name'  : 'DEBUG',
        'xterm' : '35m',
        '256color': '38;5;135m',
    },
}

#
# We allow the log level to be specified on the command-line or in the
# config by name (string/keyword), but we need to convert these to the
# numeric value:
#

LOGGING_LEVELS_MAP = {
    'NORMAL'    : LOGGING_LEVELS['NORMAL']['level'],
    'ERROR'     : logging_level_ERROR,
    'WARN'      : logging_level_WARN,
    'INFO'      : logging_level_INFO,
    'DEBUG'     : logging_level_DEBUG,
    'normal'    : LOGGING_LEVELS['NORMAL']['level'],
    'error'     : logging_level_ERROR,
    'warn'      : logging_level_WARN,
    'info'      : logging_level_INFO,
    'debug'     : logging_level_DEBUG
}

def custom_signal_handler(signal, frame):
    """Very terse custom signal handler

    This is used to avoid generating a long traceback/backtrace
    """

    warn("Signal {} received, exiting".format(str(signal)))
    sys.exit(1)

class bwanRestapi:
    def __init__(self, tenant_url, api_token):
        self.tenant_url = tenant_url
        self.api_token = api_token
        self.session = RQ_Session()
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_token}"
        }
        self.url_prefix = tenant_url + "/v2/custom-apps"
        
    def get_custom_apps(self):
        info("Getting custom apps")
        table_header = ["id","name"]
        response_dict = []
        params = {}
        hasNextPage = True
        end_cursor = None
        index = 1
        while True:

            if end_cursor:
                params = {'after': end_cursor}
            response = self.session.get(url=f"{self.url_prefix}", headers=self.headers, params=params)
            if response.status_code == 200:
                data = response.json()
                info("Custom apps retrieved successfully - Page {}".format(index))
                hasNextPage = data["page_info"].get("has_next", False)
                end_cursor = data["page_info"].get("end_cursor", None)                
                for app in data["data"]:
                    response_dict.append(app)
                if not hasNextPage:
                   break
                else:
                    index += 1
                    info("Fetching next page of custom apps... - Page {}".format(index))
            else:
                error("Failed to retrieve custom apps")
                return None
        table_data = [[row[col] for col in table_header] for row in response_dict]
        info(tabulate.tabulate(table_data, headers=table_header, tablefmt="grid"))
        info("\nTotal number of Custom Apps is {}\n".format(len(response_dict)))
        id_list = [ id['id'] for id in response_dict ]
        return(id_list,response_dict)
       
    def del_custom_app(self, custom_app_id):
        info("deleting custom app with ID {}".format(custom_app_id))
        response = self.session.delete(url=f"{self.url_prefix}/{custom_app_id}", headers=self.headers)

        if response.status_code == 200:
            info("Custom app with ID {} deleted successfully".format(custom_app_id))
        else:
            info("Response text: {}".format(response.text))
            info("Response code: {}".format(response.status_code))
            error("Failed to delete custom app with ID {}".format(custom_app_id))

    def capp_def_str(self,name, ip_addr, port_range, protocol):


        if port_range == "*":
            port_range = "1-65535"

        capp_def_str = {
            "host": ip_addr,
            "port_range": port_range,
            "protocol": protocol,
            "web_access": False
        }

        if protocol.upper() == "TCP" or protocol.upper() == "UDP":
            capp_def_str["protocol"] = protocol.lower()
            return capp_def_str
        elif protocol.upper() == "ICMP" or protocol.upper() == "IPV4":
            capp_def_str["protocol"] = protocol.lower()
            capp_def_str.pop("port_range", None)
            return capp_def_str
        elif protocol.upper() == "ANY":
            info(capp_def_str)
            temp_definition = []
            for proto in ["tcp", "udp", "icmp"]:
                capp_def_str_copy = capp_def_str.copy()
                capp_def_str_copy["protocol"] = proto
                if proto == "icmp":
                    capp_def_str_copy.pop("port_range", None)
                temp_definition.append(capp_def_str_copy)
            return temp_definition
        else:
            error("Unsupported protocol: {}. Supported protocols are TCP, UDP, ICMP, IPV4, ANY".format(protocol))
            return None
    
    def add_custom_app(self, data_file, custom_app_prefix):
        
        ip_data_dict = {}
        try:
            with open(data_file, "r") as f:
                reader = csv.reader(f, delimiter=';')
                next(reader)
                
                try:
                    for name,address,protocl,port in reader:
                        if name not in ip_data_dict:
                            ip_data_dict[name] = []
                        ip_data_dict[name].append({
                            "address": address,
                            "protocol": protocl,
                            "port": port
                            })
                except ValueError:
                    error("Next to this entry {} is not in the expected format".format((name,address,protocl,port)))
                    exit(1)

        except FileNotFoundError:
            error("File {} not found".format(data_file))
            exit(1)
        info("Parsed {} entries from file {}".format(len(ip_data_dict), data_file))
        for key,value in ip_data_dict.items():
            capp_definition =[]
            for entry in value:
                address = entry["address"]
                protocl = entry["protocol"]
                port = entry["port"]
                name = "{}-{}".format(custom_app_prefix,key)
                if protocl.upper() == "ANY":
                    definitions = self.capp_def_str(name, address, port, protocl)
                    for def_item in definitions:
                        capp_definition.append(def_item)
                else:
                    capp_definition.append(self.capp_def_str(name, address, port, protocl))
            datadict = {
                "definitions":capp_definition,
                "description": name,
                "enabled": True,
                "native": False,
                "name": name,
                "type_id": 24
            }
            info("Custom App Definition String: {}".format(json.dumps(datadict, indent=4)))
            if datadict is not None:
                response = self.session.post(url=self.url_prefix, headers=self.headers, data=json.dumps(datadict))
                if response.status_code == 201:
                    info("Custom app {} added successfully".format(name))
                else:
                    info("Response text: {}".format(response.text))
                    info("Response code: {}".format(response.status_code))
                    error("Failed to add custom app {}".format(name))

def main():
    #
    # Set logging to INFO by default (log everything except DEBUG).
    #
    # Also try to add colors to the logging output if the logging output goes
    # to a capable device (not a file and a terminal supporting colors).
    #
    # Actually adding the ANSI escape codes in the logging level name is pretty
    # much an ugly hack but it is the easiest way (less changes).
    #
    # An elegant way of doing this is described here:
    #  http://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
    #
    fmt_str = '%(asctime)s %(levelname)s: %(message)s'

    logging_basicConfig(format=fmt_str, level=logging_level_INFO,
                        stream=sys.stdout)
    logger = logging_getLogger()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('-u','--tenant_url', help='BWAN Tenant URL')
    argparser.add_argument('-t','--api_token', help='BWAN Tenant API Token')
    argparser.add_argument('-g','--get_custom_apps', help='Get BWAN Custom App', action='store_true')
    argparser.add_argument('-d','--del_custom_app', help='Delete Custom App with ID, 0 for All', metavar='CUSTOM_APP_ID')
    argparser.add_argument('-a','--add_custom_app', help='Add BWAN Custom App from File', metavar='FILENAME')
    argparser.add_argument('-p','--custom_app_prefix', help='Custom App name prefix. Default: capp', metavar='PREFIX')

    args = argparser.parse_args(args=None if sys.argv[1:] else ['--help'])


    cfgparser = ConfigParser()
    try:
        if not cfgparser.read(os.path.expanduser(CONFIG_FILENAME)):
            warn("Config file doesn't exit, will look into CLI arguments")
            if (args.tenant_url is not None):
                tenant_url = args.tenant_url
            else:
                error("add the tenant_url to arguments or to the config file.")
                sys.exit(1)

            if (args.api_token is not None):
              bwan_api_token = args.api_token
            else:
              error("add the api_token to arguments or to the config file.")
              sys.exit(1) 
        else:
          config = cfgparser['bwan_config']
          if ('bwan_config' not in cfgparser):
              error("Configuration file {} doesn't contain 'bwan_config' section"
                    "".format(os.path.expanduser(CONFIG_FILENAME)))
              sys.exit(1)
          elif (('tenant_url' not in cfgparser['bwan_config']) or
                  ('api_token' not in cfgparser['bwan_config'])):
              error("Config file doesn't contain (all) required authentication info")
              sys.exit(1)
          else:
            config = cfgparser['bwan_config']
            tenant_url=config['tenant_url']
            bwan_api_token=config['api_token']
    except:
        error("Can't parse configuration file {}"
              "".format(os.path.expanduser(CONFIG_FILENAME)))
        sys.exit(1)
    info("Working with tenant: {}".format(tenant_url))

    Bwan_RestApi = bwanRestapi(tenant_url, bwan_api_token)
    if args.get_custom_apps:
       Bwan_RestApi.get_custom_apps()

    if args.del_custom_app:
        if args.del_custom_app == "0":
            id_list, response_dict = Bwan_RestApi.get_custom_apps()
            if len(id_list) == 0:
                info("No custom app found. Nothing to delete.")
                exit(0)
            info("The script will delete {} custom app".format(len(id_list)))
            while True:
                answer = input("Do you want to Continue? (Yes/Y or No/N) ")
                if answer.lower() in ["y","yes"]:
                    for app_id in id_list:
                        Bwan_RestApi.del_custom_app(app_id)
                    break
                elif answer.lower() in ["n","no"]:
                    info("No custom app deleted. Exiting...")
                    exit(0)
                else:
                    error("Please select Yes/y or No/n")
            
        elif args.del_custom_app is not None:
            Bwan_RestApi.del_custom_app(args.del_custom_app)

    if args.add_custom_app:
        info("Adding custom apps from file {}".format(args.add_custom_app))
        capp_name_prefix = args.custom_app_prefix if args.custom_app_prefix else "capp"
        Bwan_RestApi.add_custom_app(args.add_custom_app, capp_name_prefix)

if __name__ == "__main__":

    main()