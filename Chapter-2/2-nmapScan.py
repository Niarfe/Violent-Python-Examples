#!/usr/bin/python
# -*- coding: utf-8 -*-

import nmap
import optparse


def nmapScan(targetHost, targetPort):
    nmScan = nmap.PortScanner()
    nmScan.scan(targetHost, targetPort)
    state = nmScan[targetHost]['tcp'][int(targetPort)]['state']
    print "[*] " + targetHost + " tcp/" + targetPort + " " + state

if __name__ == '__main__':
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='targetHost', type='string', help='specify target host')
    parser.add_option('-p', dest='targetPort', type='string', help='specify target port[s] separated by comma')

    (options, args) = parser.parse_args()

    targetHost = options.targetHost
    targetPorts = str(options.targetPort).split(',')

    if (targetHost is None) | (targetPorts[0] is None):
        parser.print_help()
        exit(0)
    for targetPort in targetPorts:
        nmapScan(targetHost, targetPort)
