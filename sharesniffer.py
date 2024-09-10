#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""sharesniffer.py - sniff out and find all smb/nfs shares
on the local network and try to mount them for crawling.
Requires python-nmap, netifaces modules, Nmap in PATH
and Nmap nse scripts.
See README.md or https://github.com/shirosaidev/sharesniffer
for more information.

Copyright (C) Chris Park 2018
sharesniffer is released under the Apache 2.0 license. See
LICENSE for the full license text.
"""

try:
    import nmap
except ImportError:
    raise ImportError('python-nmap module required, please install with pip')
try:
    import netifaces
except ImportError:
    raise ImportError('netifaces module required, please install with pip')
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
import argparse
import logging
import re
import subprocess
import os
import sys
from random import randint
from concurrent.futures import ThreadPoolExecutor, as_completed


SHARESNIFFER_VERSION = '0.1-b.8'
__version__ = SHARESNIFFER_VERSION


class sniffer:
    def __init__(self, hosts=None, excludehosts=None, nfs=False, smb=False, smbuser='guest', smbpass='', max_workers=10):
        self.hosts = hosts
        self.nfs = nfs
        self.smb = smb
        self.smbuser = smbuser
        self.smbpass = smbpass
        self.excludehosts = excludehosts
        self.nm = nmap.PortScanner()
        self.max_workers = max_workers

    def get_host_ranges(self):
        """ Retrieves the network ranges for scanning. """
        cidr = []
        for ifacename in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(ifacename)
                addr = addrs[netifaces.AF_INET]
                ip = addr[0]['addr']
            except KeyError:
                continue
            if ip == '127.0.0.1' or ip == 'fe80::1%lo0':
                continue
            try:
                netmask = addr[0]['netmask'].split('.')
            except KeyError:
                cidr.append(ip + '/' + '32')
                continue
            ipaddr = ip.split('.')
            net_start = [str(int(ipaddr[x]) & int(netmask[x]))
                         for x in range(0, 4)]
            binary_str = ''
            for octet in netmask:
                binary_str += bin(int(octet))[2:].zfill(8)
            net_size = str(len(binary_str.rstrip('0')))
            cidr.append('.'.join(net_start) + '/' + net_size)
        hostlist = ' '.join(cidr)
        return hostlist

    def scan_host(self, host):
        """ Scans a single host and returns NFS/SMB open ports. """
        open_ports = {'nfs': False, 'smb': False}
        self.nm.scan(host, '111,445', arguments=self.nmapargs)
        for proto in self.nm[host].all_protocols():
            lport = self.nm[host][proto].keys()
            for port in lport:
                if self.nm[host][proto][port]['state'] == 'open':
                    if port == 111:
                        open_ports['nfs'] = True
                    if port == 445:
                        open_ports['smb'] = True
        return host, open_ports

    def sniff_hosts(self):
        """ Sniffs for NFS/SMB shares on the network. """
        hostlist_nfs = []
        hostlist_smb = []
        if not self.hosts:
            logger.info('No hosts specified, finding your network info')
            hosts = self.get_host_ranges()
            logger.info('Networks found: %s', hosts)
        else:
            hosts = self.hosts

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {executor.submit(self.scan_host, host): host for host in hosts.split()}
            for future in as_completed(future_to_host):
                host, open_ports = future.result()
                if open_ports['nfs']:
                    hostlist_nfs.append(host)
                if open_ports['smb']:
                    hostlist_smb.append(host)

        return hostlist_nfs, hostlist_smb

def get_nfs_shares(self, hostlist):
    nfsshares = []
    for host in hostlist:
        shares = {'host': host, 'openshares': [], 'closedshares': []}
        output = self.nm.scan(host, '111',
                              arguments='%s --datadir %s --script %s/nfs-showmount.nse,%s/nfs-ls.nse'
                                        % (self.nmapargs, nmapdatadir, nmapdatadir, nmapdatadir))
        logger.debug('nm scan output: ' + str(output))
        try:
            nfsshowmount = output['scan'][host]['tcp'][111]['script']['nfs-showmount'].strip().split('\n')
            nfsls = output['scan'][host]['tcp'][111]['script']['nfs-ls'].strip().split('\n')
        except KeyError:
            print('%s PORT 111/tcp OPEN (rpcbind) but no results from nse script' % host)
            continue

        openshares = []
        closedshares = []
        sharedict = {'sharename': nfsshowmount[0].strip().split(' ')[0]}
        
        # Ensure the list has at least 5 elements before accessing nfsls[4]
        if len(nfsls) > 4 and re.search(r'ERROR: Mount failed: Permission denied', nfsls[4]):
            closedshares.append(sharedict)
            continue
        else:
            openshares.append(sharedict)
        
        for share in openshares:
            shares['openshares'].append(share['sharename'])
        for share in closedshares:
            shares['closedshares'].append(share['sharename'])
        nfsshares.append(shares)
        
    return nfsshares

    def get_smb_shares(self, hostlist):
        smbshares = []
        for host in hostlist:
            shares = {'host': host, 'openshares': [], 'closedshares': []}
            if self.smbuser != '' and self.smbpass != '':
                output = self.nm.scan(host, '445',
                                      arguments='%s --datadir %s --script %s/smb-enum-shares.nse \
                                      --script-args smbusername=%s,smbpassword=%s'
                                                % (self.nmapargs, nmapdatadir, nmapdatadir, self.smbuser, self.smbpass))
            else:
                output = self.nm.scan(host, '445',
                                      arguments='%s --datadir %s --script %s/smb-enum-shares.nse'
                                                % (self.nmapargs, nmapdatadir, nmapdatadir))
            logger.debug('nm scan output: ' + str(output))
            try:
                sharelist = output['scan'][host]['hostscript'][0]['output'].strip().split('\n')
            except KeyError:
                print('%s PORT 445/tcp OPEN (microsoft-ds) but no results from nse script' % host)
                continue
            openshares = []
            closedshares = []
            x = 0
            while x < len(sharelist):
                if re.search(
                        r'(smb-enum-shares)|(ADMIN\$)|(C\$)|(IPC\$)|(U\$)|(:)|(\$)',
                        sharelist[x]):
                    x += 7
                    continue
                sharedict = {'sharename': sharelist[x].strip()}
                x += 6
                if re.search(r'(access: READ)|(access: READ/WRITE)', sharelist[x]):
                    pass
                else:
                    sharedict['useraccess'] = sharelist[x].strip()
                    closedshares.append(sharedict)
                    x += 1
                    continue
                sharedict['useraccess'] = sharelist[x].strip()
                openshares.append(sharedict)
                x += 1
            for share in openshares:
                shares['openshares'].append(share['sharename'])
            for share in closedshares:
                shares['closedshares'].append(share['sharename'])
            smbshares.append(shares)
        return smbshares

    def get_host_ranges(self):
        cidr = []
        for ifacename in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(ifacename)
                addr = addrs[netifaces.AF_INET]
                ip = addr[0]['addr']
            except KeyError:
                continue
            if ip == '127.0.0.1' or ip == 'fe80::1%lo0':
                continue
            try:
                netmask = addr[0]['netmask'].split('.')
            except KeyError:
                cidr.append(ip + '/' + '32')
                continue
            ipaddr = ip.split('.')
            net_start = [str(int(ipaddr[x]) & int(netmask[x]))
                         for x in range(0, 4)]
            binary_str = ''
            for octet in netmask:
                binary_str += bin(int(octet))[2:].zfill(8)
            net_size = str(len(binary_str.rstrip('0')))
            cidr.append('.'.join(net_start) + '/' + net_size)
        hostlist = ' '.join(cidr)
        return hostlist

    def sniff_hosts(self):
        hostlist_nfs = []
        hostlist_smb = []
        if not self.hosts:
            logger.info('No hosts specified, finding your network info')
            hosts = self.get_host_ranges()
            logger.info('Networks found: %s', hosts)
        else:
            hosts = self.hosts
        logger.info('Starting network sniff...')
        logger.debug('nmap args: ' + self.nmapargs)
        if self.nfs:
            logger.info('Looking for nfs shares...')
            self.nm.scan(hosts=hosts, ports='111', arguments=self.nmapargs)
        elif self.smb:
            logger.info('Looking for smb shares...')
            self.nm.scan(hosts=hosts, ports='445', arguments=self.nmapargs)
        else:
            logger.info('Looking for nfs and smb shares...')
            self.nm.scan(hosts=hosts, ports='111,445', arguments=self.nmapargs)
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                lport = self.nm[host][proto].keys()
                for port in lport:
                    if self.nm[host][proto][port]['state'] == 'open':
                        if port == 111:
                            hostlist_nfs.append(host)
                        if port == 445:
                            hostlist_smb.append(host)
        return hostlist_nfs, hostlist_smb


class mounter:
    def __init__(self, shares, mountdir='./', nfsmntopt='ro,nodev,nosuid', smbmntopt='ro,nodev,nosuid',
                 smbtype='smbfs', smbuser='guest', smbpass='', max_workers=10):
        self.shares = shares
        self.mountdir = mountdir
        self.nfsmntopt = nfsmntopt
        self.smbmntopt = smbmntopt
        self.smbtype = smbtype
        self.smbuser = smbuser
        self.smbpass = smbpass
        self.max_workers = max_workers

    def mount_nfs_share(self, host, share):
        """ Mounts an NFS share and returns the result. """
        mountpoint = self.mountdir + '/'+args.mountprefix+'-nfs_' + host + '_' + share.replace('/', '_')
        mkdir = ['mkdir', '-p', mountpoint]
        subprocess.Popen(mkdir)
        mount = ['mount', '-v', '-o', self.nfsmntopt, '-t', 'nfs', host + ':' + share, mountpoint]
        logger.debug('mount cmd: %s', mount)
        process = subprocess.Popen(mount, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = process.communicate()
        if process.returncode > 0:
            logger.debug('mount cmd exit code: %s', process.returncode)
            mounted = False
            try:
                if os.path.exists(mountpoint):
                    os.rmdir(mountpoint)
            except OSError:
                raise OSError('error removing mountpoint directory')
        else:
            mounted = True
        return {'host': host, 'sharetype': 'nfs', 'sharename': share, 'mountpoint': mountpoint,
                'output': output, 'exitcode': process.returncode, 'mounted': mounted}

    def mount_smb_share(self, host, share):
        """ Mounts an SMB share and returns the result. """
        mountpoint = self.mountdir + '/'+args.mountprefix+'-smb_' + host + '_' + share.replace(' ', '_')
        mkdir = ['mkdir', '-p', mountpoint]
        subprocess.Popen(mkdir)
        mount = ['mount', '-v', '-o', self.smbmntopt, '-t', self.smbtype,
                 '//' + self.smbuser + ':' + self.smbpass + '@' + host + '/' + share.replace(' ', '%20'),
                 mountpoint]
        logger.debug('mount cmd: %s', mount)
        process = subprocess.Popen(mount, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = process.communicate()
        if process.returncode > 0:
            logger.debug('mount cmd exit code: %s', process.returncode)
            mounted = False
            try:
                if os.path.exists(mountpoint):
                    os.rmdir(mountpoint)
            except OSError:
                raise OSError('error removing mountpoint directory')
        else:
            mounted = True
        return {'host': host, 'sharetype': 'smb', 'sharename': share, 'mountpoint': mountpoint,
                'output': output, 'exitcode': process.returncode, 'mounted': mounted}

    def mount_shares(self):
        mount_status = []
        
        # Use ThreadPoolExecutor with max_workers set by user
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_mount = []
            
            for hostdict in self.shares['nfsshares']:
                for share in hostdict['openshares']:
                    future_to_mount.append(executor.submit(self.mount_nfs_share, hostdict['host'], share))
            
            for hostdict in self.shares['smbshares']:
                for share in hostdict['openshares']:
                    future_to_mount.append(executor.submit(self.mount_smb_share, hostdict['host'], share))
            
            for future in as_completed(future_to_mount):
                mount_status.append(future.result())
        
        return mount_status


def sniff_network():
    """This is the sniff network function.
    It sniffs for any nfs/smb shares
    on the network and outputs the results.
    Returns shares.
    """

    if os.geteuid():
        logger.warning('Not running as root, sniffing may be slower')
    logger.info('Sniffing for any network shares...')
    if args.hosts:
        logger.info('Hosts: %s', args.hosts)
    else:
        logger.info('Scanning all hosts we can find (ctrl-c to stop)')
    if args.excludehosts:
        logger.info('Excluded hosts: %s', args.excludehosts)

    sniff = sniffer(hosts=args.hosts, excludehosts=args.excludehosts,
                    nfs=args.nfs, smb=args.smb, smbuser=args.smbuser,
                    smbpass=args.smbpass, max_workers=args.maxworkers)
    shares = sniff.sniff_hosts()
    hostlist_nfs, hostlist_smb = sniff.sniff_hosts()
    shares = {'nfsshares': [], 'smbshares': []}
    if len(hostlist_nfs) > 0 or len(hostlist_smb) > 0:
        if len(hostlist_nfs) > 0:
            shares['nfsshares'] = sniff.get_nfs_shares(hostlist_nfs)
            if isinstance(shares['nfsshares'], list) and len(shares['nfsshares']) > 0 and not args.quiet:
                print('\n******************************* NFS SHARES ********************************\n')
                for host in shares['nfsshares']:
                    print('host: %s  open: %s  closed: %s' % (host['host'],
                                                                            host['openshares'],
                                                                            host['closedshares']))
                print('\n***************************************************************************\n')
            else:
                if not args.quiet:
                    print('\nNO NFS SHARES FOUND!\n')
        if len(hostlist_smb) > 0:
            shares['smbshares'] = sniff.get_smb_shares(hostlist_smb)
            if len(shares['smbshares']) > 0 and not args.quiet:
                print('\n******************************* SMB SHARES ********************************\n')
                print('smbuser used: %s' % args.smbuser)
                for host in shares['smbshares']:
                    print('host: %s  open: %s  closed: %s' % (host['host'],
                                                                            host['openshares'],
                                                                            host['closedshares']))
                print('\n***************************************************************************\n')
            else:
                if not args.quiet:
                    print('\nNO SMB SHARES FOUND!\n')
    else:
        logger.info('No hosts found with open ports, exiting')
        sys.exit(0)
    return shares


def auto_mounter(shares):
    """This is the auto mounter function.
    It tries to mount any sniffed out nfs/smb shares.
    Returns mountstocrawl list.
    """
    mountstocrawl = []

    if len(shares['nfsshares']) > 0 or len(shares['smbshares']) > 0:
        mounts = mounter(shares, mountdir=args.mountpoint, nfsmntopt=args.nfsmntopt,
                                     smbmntopt=args.smbmntopt, smbtype=args.smbtype,
                                     smbuser=args.smbuser, smbpass=args.smbpass)
        logger.info('Unmounting any existing mountpoints...')
        # unmount any existing mountpoint
        mounts.umount_shares()
        logger.info('Trying to mount shares...')
        mounts_status = mounts.mount_shares()
        hosts = []
        for h in mounts_status:
            if h['host'] not in hosts:
                hosts.append(h['host'])
        hostcount = len(hosts)
        mounted = 0
        for mount in mounts_status:
            if mount['mounted']:
                logger.info('Mounted \'%s\' %s share at %s' % (mount['sharename'], mount['sharetype'],
                                                                             mount['mountpoint']))
                mountstocrawl.append(mount['mountpoint'])
                mounted += 1
            else:
                logger.warning(
                    'Failed mounting \'%s\' %s share (%s)' % (mount['sharename'], mount['sharetype'],
                                                                            mount['output']))
    else:
        logger.warning('No open shares found, exiting')
        sys.exit(1)
    if mounted > 0:
        logger.info('Mounted %s shares (%s hosts)', mounted, hostcount)
    else:
        logger.warning('No shares could be mounted, exiting')
        sys.exit(1)
    return mountstocrawl


if __name__ == "__main__":
    # default mount options (optimized for crawling)
    mntopt_nfs = "ro,nosuid,nodev,noexec,udp,proto=udp,noatime,nodiratime,rsize=1024,dsize=1024,vers=3,rdirplus"
    mntopt_smb = "ro,nosuid,nodev,noexec,udp,proto=udp,noatime,nodiratime,rsize=1024,dsize=1024"

    # parse cli args
    parser = argparse.ArgumentParser()
    parser.add_argument("--maxworkers", type=int, default=10,
                    help="Maximum number of concurrent threads for scanning and mounting (default: 10)")
    parser.add_argument("--hosts", metavar="HOSTS",
                        help="Hosts to scan, example: 10.10.56.0/22 or 10.10.56.2 (default: scan all hosts)")
    parser.add_argument("-e", "--excludehosts", metavar="EXCLUDEHOSTS",
                        help="Hosts to exclude from scan, example: 10.10.56.1,10.10.56.254")
    parser.add_argument("-l", "--speedlevel", type=int, default=4,
                        help="Scan speed aggressiveness level from 3-5, lower for more accuracy (default: 4)")
    parser.add_argument("-n", "--nfs", action="store_true",
                        help="Scan network for nfs shares")
    parser.add_argument("--nfsmntopt", metavar="NFSMNTOPT", default=mntopt_nfs,
                        help="nfs mount options (default: "+mntopt_nfs+")")
    parser.add_argument("-s", "--smb", action="store_true",
                        help="Scan network for smb shares")
    parser.add_argument("--smbmntopt", metavar="SMBMNTOPT", default=mntopt_smb,
                        help="smb mount options (default: "+mntopt_smb+")")
    parser.add_argument("--smbtype", metavar='SMBTYPE', default="smbfs",
                        help="Can be smbfs (default) or cifs")
    parser.add_argument("--smbuser", metavar='SMBUSER', default="guest",
                        help="smb username (default: guest)")
    parser.add_argument("--smbpass", metavar='SMBPASS', default="",
                        help="smb password (default: none)")
    parser.add_argument("-a", "--automount", action="store_true",
                        help="Auto-mount any open nfs/smb shares")
    parser.add_argument("-m", "--mountpoint", metavar="MOUNTPOINT", default="./",
                        help="Mountpoint to mount shares (default: ./)")
    parser.add_argument("-p", "--mountprefix", metavar="MOUNTPREFIX", default="sharesniffer",
                        help="Prefix for mountpoint directory name (default: sharesniffer)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Increase output verbosity")
    parser.add_argument("--debug", action="store_true",
                        help="Debug message output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Run quiet and just print out any possible mount points for crawling")
    parser.add_argument("--nmapdatadir", metavar="NMAPDATADIR", default=None,
                        help="Path to the Nmap NSE script directory (optional)")
    parser.add_argument("-V", "--version", action="version",
                        version="sharesniffer v%s" % SHARESNIFFER_VERSION,
                        help="Prints version and exits")
    args = parser.parse_args()

    # set up logging
    logger = logging.getLogger('sharesniffer')
    logger.setLevel(logging.INFO)
    logging.addLevelName(
        logging.INFO, "\033[1;32m%s\033[1;0m"
                      % logging.getLevelName(logging.INFO))
    logging.addLevelName(
        logging.WARNING, "\033[1;31m%s\033[1;0m"
                         % logging.getLevelName(logging.WARNING))
    logging.addLevelName(
        logging.ERROR, "\033[1;41m%s\033[1;0m"
                       % logging.getLevelName(logging.ERROR))
    logging.addLevelName(
        logging.DEBUG, "\033[1;33m%s\033[1;0m"
                       % logging.getLevelName(logging.DEBUG))
    logformatter = '%(asctime)s [%(levelname)s][%(name)s] %(message)s'
    loglevel = logging.INFO
    logging.basicConfig(format=logformatter, level=loglevel)
    if args.verbose:
        logger.setLevel(logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.quiet:
        logger.disabled = True

    # print banner
    if not args.quiet:
        c = randint(1, 4)
        if c == 1:
            color = '31m'
        elif c == 2:
            color = '32m'
        elif c == 3:
            color = '33m'
        elif c == 4:
            color = '35m'

        banner = """\033[%s

         ____ _  _ ____ ____ ____          /
         ==== |--| |--| |--< |===         ["]  ,< ,,_      
         ____ __ _ _ ____ ____ ____ ____  [~]\\/   |__|      
         ==== | \| | |--- |--- |=== |--<  OOO
         v%s               

        \033[0m""" % (color, SHARESNIFFER_VERSION)
        print(banner + '\n')

    # check for Nmap nse scripts directory
    if args.nmapdatadir:
        if os.path.isdir(args.nmapdatadir):
            nmapdatadir = args.nmapdatadir
        else:
            print("Provided Nmap NSE script directory does not exist: %s" % args.nmapdatadir)
            sys.exit(1)
    else:
        nmapdatadir = None
        nmap_script_dirs = ['/usr/local/share/nmap/scripts', '/usr/share/nmap/scripts']
        for path in nmap_script_dirs:
            if os.path.isdir(path):
                nmapdatadir = path
                break
        if not nmapdatadir:
            print("Unable to locate nmap nse scripts directory")
            sys.exit(1)

    logger.debug('Nmap datadir: ' + nmapdatadir)

    # get shares and mountpoints
    shares = sniff_network()
    if args.automount:
        mmounts = mounter(shares, mountdir=args.mountpoint, nfsmntopt=args.nfsmntopt,
                         smbmntopt=args.smbmntopt, smbtype=args.smbtype,
                         smbuser=args.smbuser, smbpass=args.smbpass, max_workers=args.maxworkers)
        mountstocrawl = mounts.mount_shares()
        if args.quiet:
            for m in mountstocrawl:
                print(m)
    else:
        logger.info('Skipping auto-mount, exiting')

    sys.exit(0)
