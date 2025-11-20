# bwanCapp

bwanCapp.py is a tool that help configure, query, and delete Netskope Borderless SDWAN tenant custom apps in bulk via Rest API calls


## Prerequisites

1. Python3
2. The following python modules (see requirements.txt)
	- requests
  - tabulate



## Installation

```
$ git clone https://github.com/sivaprasathksk/bwancapp
$ cd bwancapp
$ pip3 install -r requirements.txt
```


## Running

### Generate API Token

1. Log in to the SASE Orchestrator as a System Admin and navigate to Administration > Tokens.
2. Click the + icon to create a new token.
3. Provide a Name and Permissions details. The Permissions must be supplied in JSON format.
4. Click Create to generate the token.
5. The popup window will show the token detail. Copy the token and save it for future use.


### Script help
```
$ python3 bwanCapp.py -h
usage: bwanCapp.py [-h] [-u TENANT_URL] [-t API_TOKEN] [-g] [-d CUSTOM_APP_ID] [-a FILENAME] [-p PREFIX]

options:
  -h, --help            show this help message and exit
  -u TENANT_URL, --tenant_url TENANT_URL
                        BWAN Tenant URL
  -t API_TOKEN, --api_token API_TOKEN
                        BWAN Tenant API Token
  -g, --get_custom_apps
                        Get BWAN Custom App
  -d CUSTOM_APP_ID, --del_custom_app CUSTOM_APP_ID
                        Delete Custom App with ID, 0 for All
  -a FILENAME, --add_custom_app FILENAME
                        Add BWAN Custom App from File
  -p PREFIX, --custom_app_prefix PREFIX
                        Custom App name prefix. Default: capp
```

### BWAN Token 
1. Log in to the SASE Orchestrator as a System Admin and navigate to Administration > Tokens.
2. Click the + icon to create a new token.
3. Provide a Name and Permissions details. The Permissions must be supplied in JSON format. use the following permissions
```
[
  {
    "rap_privs": [
      "privCustomAppCreate",
      "privCustomAppWrite",
      "privCustomAppRead",
      "privCustomAppDelete",
      "privAuditRecordCreate",
      "privAuditRecordRead",
    ],
    "rap_resource": ""
  }
]
```
4. Modify the expiration date as required.

### Create Custom App From file
1. Create csv file with the IP address and custom app name as per the following format __(Entries with the same app name will be added to the same custom app. Allowed Protocol: TCP, UDP, ICMP or Any allowed. Allowed Port: single port or multiple ports seperated by , or *.CSV seperated by ;)__ :
```
name,address,protocl,port
app1;192.168.1.1;tcp;80
app1;192.168.1.2;udp;443
app1;192.168.1.3;any;*
app2;192.168.2.0/24;any;8080
app3;www.example.com;tcp;80
app3;www.example1.com;tcp;90,300,4000
```
2. Run the script:
```
$ python3 bwanCapp.py -u https://<TENANT_URL> -t <TOKEN> -a ip_file.csv
2024-07-19 11:52:08,672 WARNING: Config file doesn't exit, will look into CLI arguments
2024-07-19 11:52:08,672 INFO: Working with tenant: <TENANT_URL>
2024-07-19 11:52:08,672 INFO: Creating custom app: capp-app1
2024-07-19 11:52:09,180 INFO: Creating custom app: capp-app2
2024-07-19 11:52:09,369 INFO: Creating custom app: capp-app3
```

3. Confirm the Custom App is created in the orchestrator und Configure > Custom Apps

### Delete Custom App(s)
1. Get the list of Apps and IDs
```
$ python3 bwanCapp.py -u <TENANT_URL> -t <TOKEN> -g
2024-07-19 11:58:15,801 WARNING: Config file doesn't exit, will look into CLI arguments
2024-07-19 11:58:15,801 INFO: Working with tenant: <TENANT_URL>
2024-07-19 11:58:15,801 INFO: Getting custom apps
+--------------------------+-------------+
| id                       | capp_name   |
+==========================+=============+
| 669a46bdf4e33791bd438775 | capp-app1   |
+--------------------------+-------------+
| 669a46bdf4e33791bd438795 | capp-app2   |
+--------------------------+-------------+
| 669a46bef4e33791bd4387d5 | capp-app3   |
+--------------------------+-------------+

Total number of Custom Apps is 3
```

2. Delete the Custom App using the ID
```
$ python3 bwanCapp.py -u <TENANT_URL> -t <TOKEN> -d 669a46bef4e33791bd4387d5
2024-07-19 11:59:07,856 WARNING: Config file doesn't exit, will look into CLI arguments
2024-07-19 11:59:07,856 INFO: Working with tenant: <TENANT_URL>
2024-07-19 11:59:07,856 INFO: deleting custom app with ID 669a46bef4e33791bd4387d5
```

3. You can delete all custom apps by passing 0 as ID **BE CAREFUL**
```
$ python3 bwanCapp.py -u <TENANT_URL> -t <TOKEN> -d 0
2024-07-19 12:01:49,075 WARNING: Config file doesn't exit, will look into CLI arguments
2024-07-19 12:01:49,075 INFO: Working with tenant: <TENANT_URL>
2024-07-19 12:01:49,075 INFO: Getting custom apps
+--------------------------+-------------+
| id                       | capp_name   |
+==========================+=============+
| 669a479680ee76bd7b468030 | capp-app1   |
+--------------------------+-------------+
| 669a479780ee76bd7b46805a | capp-app2   |
+--------------------------+-------------+
| 669a479780ee76bd7b468095 | capp-app3   |
+--------------------------+-------------+

Total number of Custom Apps is 3

2024-07-19 12:01:49,350 INFO: The script will delete 3 custom app
Do you want to Continue? (Yes/Y or No/N) yes
2024-07-19 12:01:53,212 INFO: deleting custom app with ID 669a479680ee76bd7b468030
2024-07-19 12:01:53,398 INFO: deleting custom app with ID 669a479780ee76bd7b46805a
2024-07-19 12:01:53,943 INFO: deleting custom app with ID 669a479780ee76bd7b468095
```

## Disclaimer

This software is supplied "AS IS" without any warranties and support.
