#!/usr/bin/python
# -*- coding: utf-8 -*-

import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)


def connScan(targetHost, targetPort):
    try:
        connSocket = socket(AF_INET, SOCK_STREAM)
        connSocket.connect((targetHost, targetPort))
        connSocket.send('ViolentPython\r\n')
        results = connSocket.recv(100)
        screenLock.acquire()
        print '[+] %d/tcp open' % targetPort
        print '[+] ' + str(results)
    except:
        screenLock.acquire()
        print '[-] %d/tcp closed' % targetPort
    finally:
        screenLock.release()
        connSocket.close()


def portScan(targetHost, targetPorts):
    try:
        targetIP = gethostbyname(targetHost)
    except:
        print "[-] Cannot resolve '%s': Unknown host" % targetHost
        return

    try:
        targetName = gethostbyaddr(targetIP)
        print '\n[+] Scan Results for: ' + targetName[0]
    except:
        print '\n[+] Scan Results for: ' + targetIP

    setdefaulttimeout(1)
    for targetPort in targetPorts:
        t = Thread(target=connScan, args=(targetHost, int(targetPort)))
        t.start()

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: %prog -H  <target host> -p <target port>')
    parser.add_option('-H', dest='targetHost', type='string', help='specify target host')
    parser.add_option('-p', dest='targetPort', type='string', help='specify target port[s] separated by comma')

    (options, args) = parser.parse_args()

    targetHost = options.targetHost
    targetPorts = str(options.targetPort).split(',')

    if (targetHost is None) | (targetPorts[0] is None):
        parser.print_help()
        exit(0)

    portScan(targetHost, targetPorts)
