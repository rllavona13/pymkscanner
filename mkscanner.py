__AUTHOR__ = 'Ramon Rivera Llavona'

import paramiko
import nmap
import mysql.connector
import sys
import json
from multiprocessing import Semaphore, Process

auth_file = open('/home/rrivera/Documents/Python_Projects/pymkscanner/auth.json')
login = json.load(auth_file)
auth_file.close()

hosts = sys.argv[1]
nscan = nmap.PortScanner()
nscan.scan(hosts=hosts, arguments='-Pn -p 8291')

semaphore = Semaphore(100)

print('')
print('-------------------------------------------------------------')
print('Scanning for Mikrotik Routers, your host/range is: %s' % sys.argv[1])
print('')

for host in nscan.all_hosts():
    if nscan[host]['tcp'][8291]['state']==u'open':
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=login['username'], password=login['password'], look_for_keys=False)
            ssh.invoke_shell()
            stdin, stdout, stderr = ssh.exec_command('system identity print')
            mk_scanned_host = stdout.read()  # saves the output from ssh for MySQL query use
            list_fixed = mk_scanned_host.strip('name:').split('name:')
            identity_fixed = (list_fixed[1])
            # print(json.dumps(mk_scanned_host, indent=4))
            ssh.close()
            sql_connector = mysql.connector.connect(user='python',
                                                    password='yzh8RB0Bcw1VivO3',
                                                    host='localhost',
                                                    database='test')

            cursor = sql_connector.cursor()

            add_mikrotik = ("INSERT INTO devices"
                            "(name, ip)"
                            "VALUES ('%s', '%s')" % (identity_fixed, host))

            cursor.execute(add_mikrotik)
            sql_connector.commit()
            cursor.close()
            sql_connector.close()
            print(str(identity_fixed))
            print(" %s  successfully added to the Database. " % host)
            print('-------------------------------------------------------------')
            print('')

        except Exception as ex:  # print the error and continues with the next ip address
            print(ex)

    else:
        print('No mikrotik found...')
        exit()
