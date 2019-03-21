__AUTHOR__ = 'Ramon Rivera Llavona'

import paramiko
import nmap
import mysql.connector
import sys
import json
from pysnmp.entity.rfc3413.oneliner import cmdgen


mikrotik_identity = 'iso.3.6.1.2.1.1.5.0'
mikrotik_version = 'iso.3.6.1.2.1.47.1.1.1.1.2.65536'
mikrotik_model = 'iso.3.6.1.2.1.1.1.0'
mikrotik_serial = '1.3.6.1.4.1.14988.1.1.7.3.0'

auth_file = open('/home/rrivera/Documents/Python_Projects/pymkscanner/auth.json')
login = json.load(auth_file)
auth_file.close()

# hosts = sys.argv[1]
hosts = '172.31.240.133'
nscan = nmap.PortScanner()
nscan.scan(hosts=hosts, arguments='-Pn -p 8291')


def mk_scanner():

    for host in nscan.all_hosts():
        if nscan[host]['tcp'][8291]['state']==u'open':
            """
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=host, username=login['username'], password=login['password'], look_for_keys=False)
                ssh.invoke_shell()
                stdin, stdout, stderr = ssh.exec_command('system identity print')
                mk_scanned_host = stdout.read()  # saves the output from ssh for MySQL query use
                list_fixed = mk_scanned_host.strip('name:').split('name:')
                identity_fixed = (list_fixed[1])
                print(identity_fixed)
                # print(json.dumps(mk_scanned_host, indent=4))
                ssh.close()

            except Exception as ex:  # print the error and continues with the next ip address
                print(ex)
            """

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=login['username'], password=login['password'], look_for_keys=False)
            ssh.invoke_shell()
            stdin, stdout, stderr = ssh.exec_command('system routerboard print')
            ssh.close()

        else:
            print('No Mikrotik found...')
            exit()


if __name__ == '__main__':


    mk_scanner()

