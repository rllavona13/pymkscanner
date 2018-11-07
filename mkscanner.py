__AUTHOR__ = 'Ramon Rivera Llavona'

import paramiko
import nmap
import mysql.connector
import sys
import json


auth_file = open('auth.json')
login = json.load(auth_file)
auth_file.close()

hosts = sys.argv[1]
nscan = nmap.PortScanner()
nscan.scan(hosts=hosts, arguments='-Pn -p 8291')

print('Scanning for Mikrotik Routers, your host/range is: %s' % sys.argv[1])
print('')

for host in nscan.all_hosts():

    for proto in nscan[host].all_protocols():

        lport = list(nscan[host][proto].keys())
        lport.sort()

        for port in lport:
            list_ports = (port, nscan[host][proto][port]['state'])

            if list_ports[1] == 'open':

                print("%s Is a Mikrotik" % host)  # print the ip which are trying to connect.
                print("")

                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hostname=host, username=login['username'], password=login['password'])
                    ssh.invoke_shell()
                    stdin, stdout, stderr = ssh.exec_command('system identity print')
                    mk_scanned_host = stdout.read()  # saves the output from ssh for MySQL query use
                    list_fixed = mk_scanned_host.strip('name:').split('name:')
                    identity_fixed = (list_fixed[1])
                    # print(json.dumps(mk_scanned_host, indent=4))
                    ssh.close()

                    """
                    verify_query = ("SELECT EXISTS(SELECT 1 FROM devices WHERE"
                                    "(ip)".format(host))
                    """

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
                    print(" %s  successfully added to the Mikrotik Database. " % host)
                    print('-------------------------------------------------------------')
                    print('')

                except Exception as ex:  # print the error and continues with the next ip address
                    print(ex)

            else:
                print('No mikrotik found...')
                exit()
