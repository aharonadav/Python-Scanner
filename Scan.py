#!/usr/bin/python
import nmap
import os
import MySQLdb


class Scan():

    db = MySQLdb.connect(host="localhost",
                         user="root",
                         passwd="password",
                         db="<DB name>")

    cursor = db.cursor()
    winlist = []
    linuxlist = []
    linuxdict = {}
    nm = nmap.PortScanner()
    hostlist = nm.all_hosts()

    def __init__(self, ip, arg):
        self.ip = ip
        self.arg = arg

    def sql(self):
        try:
            Scan.cursor.execute(self.sql)
            Scan.db.commit()
        except:
            Scan.db.rollback()

    def scan(self):
        Scan.nm.scan(hosts=self.ip, arguments=self.arg)
        Scan.hostlist = Scan.nm.all_hosts()

    def cmd1(self):
        for self.host in Scan.nm.all_hosts():
            self.cmd = os.popen('nmap -p 22 %s |awk \'FNR == 6 {print $2}\'' % self.host).read()
            self.cmd = self.cmd.rstrip("\n").strip()
            self.hostname = os.popen('dig -x %s +short' % self.host).read()
            Scan.linuxdict[self.host] = self.hostname

            if self.cmd == 'open':
                self.ostype = "Linux"

                self.sql = """INSERT INTO hosts (IP,HOSTNAME) VALUES ("%s", "%s")""" % (self.host, self.hostname)
                Scan.sql(self)

            else:
                self.ostype="Windows"
                Scan.winlist.append(self.host)
                self.sql = """INSERT INTO hosts (IP) VALUES ("%s")""" % self.host
                Scan.sql(self)

    def dict(self):
            for self.host, self.hostname in Scan.linuxdict.iteritems():
                self.linuxfile = open("linux_file", 'a')
                print(self.host, self.hostname)
                self.linuxfile.write(self.host)
                self.linuxfile.write("  -----   %s" % self.hostname)

#    def file(self):
#        self.linuxfile = open("linuxlist", 'r')
#        for x in Scan.linuxlist:
#            self.linuxfile.write("%s\n" % x)
#        self.linuxfile.close()
#
#        self.winfile=open("winlist", 'w')
#        for self.y in Scan.winlist:
#            self.winfile.write("%s\n" % self.y)
#        self.winfile.close()


##  Vlan1
s = Scan('192.168.192.0/24', '-n -sP -PE -PA22')
s.scan()
s.cmd1()
s.dict()
#s.file()
### Vlan2
#s = Scan('10.0.81.0/24', '-n -sP -PE -PA22')
#s.scan()
#s.cmd1()
#s.file()
