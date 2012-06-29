#!/usr/bin/env bin/run-python

# MyTardis web service METS create experiment and file sftp
# Author: Steve Androulakis <steve.androulakis@gmail.com>
# Based on http://code.activestate.com/recipes/576810-copy-files-over-ssh-using-paramiko/
# requires: paramiko, poster

from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
import urllib2
from urlparse import urljoin

import os
import paramiko
import md5
import glob

cwd = os.getcwd()
# CONFIGURABLE VARIABLES

# WEB SERVICE
web_url = "http://localhost:8000/"
register_ws_url = "/experiment/register/"
ws_username = "mytardis"
ws_password = "mytardis"
experiment_owner = "mytardis"
#metsxml_path = "/Users/steve/Dropbox/TARDIS/MyTARDIS/METS/exports/mets_expid_636_example.xml"
metsxml_path = os.path.join(cwd, "mets_expid_636_example.xml")

# SECURE COPY (ssh login details)
username = "username"
password = "password"
# or
# rsa_private_key = r"/path/to/.ssh/rsa_private_key"
port = 22
hostname = "localhost"
glob_pattern = "*" # TODO: test

# Local and remote directory for file copy
local_file_dir = os.path.join(cwd, "examplefiles636/")
mytardis_store_dir = "/opt/mytardis/current/var/store"

def agent_auth(transport, username, rsa_private_key=None):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent or from a local private RSA key file (assumes no pass phrase).
    """
    agent_keys = {}
    try:
        ki = paramiko.RSAKey.from_private_key_file(rsa_private_key)
        
        agent = paramiko.Agent()
        agent_keys = agent.get_keys() + (ki,)
             
    except Exception, e:
        print 'RSA key invalid.. moving on'
        
    if len(agent_keys) == 0:
        return

    for key in agent_keys:
        print 'Trying ssh-agent key %s' % key.get_fingerprint().encode('hex'),
        try:
            transport.auth_publickey(username, key)
            print '... success!'
            return
        except paramiko.SSHException, e:
            print '... failed!', e        

def recursive_scopy(basedir):
    global sftp
    global files_copied #aw yeah global variable!

    for fname in glob.glob(basedir + os.sep + glob_pattern):
        local_file = os.path.join(basedir, fname)
        remote_file = dir_remote + '/' + fname.replace(dir_local, '')

        #if remote file exists            
        if os.path.isdir(local_file):
            print 'Creating directory ', remote_file
            sftp.mkdir(remote_file)
            recursive_scopy(local_file)
        else:
            print 'Copying', local_file, 'to ', remote_file
            sftp.put(local_file, remote_file)
            files_copied += 1

def create_experiment(metsxml_path, ws_username, ws_password, experiment_owner):
    # Register the streaming http handlers with urllib2
    register_openers()

    # /Users/steve/Dropbox/Public/examplefiles636
    # /Users/steve/Dropbox/TARDIS/MyTARDIS/METS/exports/mets_expid_636_example.xml

    params = {
        'xmldata': open(metsxml_path,"rb"),
        'username': ws_username,
        'password': ws_password,
        'experiment_owner': experiment_owner,
        }
    datagen, headers = multipart_encode(params)

    url_complete = urljoin(web_url, register_ws_url)

    # Create the Request object
    request = urllib2.Request(url_complete, datagen, headers)
    # Actually do the request, and get the response
    experiment_id = urllib2.urlopen(request).read()
    print "Experiment created: " + str(experiment_id)

    return experiment_id
    
def transfer_files(username, password, port, hostname,
    glob_pattern, dir_local, dir_remote):
    global sftp
    global files_copied

    # get host key, if we know one
    hostkeytype = None
    hostkey = None
    try:
        host_keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    except IOError:
        try:
            # try ~/ssh/ too, e.g. on windows
            host_keys = paramiko.util.load_host_keys(os.path.expanduser('~/ssh/known_hosts'))
        except IOError:
            print '*** Unable to open host keys file'
            host_keys = {}

    if host_keys.has_key(hostname):
        hostkeytype = host_keys[hostname].keys()[0]
        hostkey = host_keys[hostname][hostkeytype]
        print 'Using host key of type %s' % hostkeytype

    # now, connect and use paramiko Transport to negotiate SSH2 across the connection
    try:
        print 'Establishing SSH connection to:', hostname, port, '...'
        t = paramiko.Transport((hostname, port))

        agent_auth(t, username)

        if not t.is_authenticated():
            print 'RSA key auth failed! Trying password login...'
            t.connect(username=username, password=password, hostkey=hostkey)
        else:
            sftp = t.open_session()
        sftp = paramiko.SFTPClient.from_transport(t)

        try:
            sftp.mkdir(dir_remote)
        except IOError, e:
            print '(assuming ', dir_remote, 'exists)', e

        print dir_local
        recursive_scopy(dir_local)

        t.close()

    except Exception, e:
        print '*** Caught exception: %s: %s' % (e.__class__, e)
        try:
            t.close()
        except:
            pass
    print '=' * 60
    print 'Total files copied:',files_copied
    print 'All operations complete!'
    print '=' * 60

files_copied = 0

experiment_id = create_experiment(metsxml_path, ws_username, ws_password, experiment_owner)

dir_local = local_file_dir
dir_remote = os.path.join(mytardis_store_dir, experiment_id)
print "LOCAL DIR TO COPY IS: " + dir_local
print "REMOTE DIR IS: " + dir_remote

transfer_files(username, password, port, hostname,
    glob_pattern, dir_local, dir_remote)
