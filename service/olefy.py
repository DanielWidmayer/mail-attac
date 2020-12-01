#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###
#
#  mail-att is a service build on olefy socket usingh rspamd. (https://rspamd.com)
#
###

from subprocess import Popen, PIPE
import sys
import os
import logging
import asyncio
import time
import magic
import re
import wwwordlist as wwwordlist


# merge variables from /etc/olefy.conf and the defaults
olefy_listen_addr_string = os.getenv('OLEFY_BINDADDRESS', '127.0.0.1,::1')
olefy_listen_port = int(os.getenv('OLEFY_BINDPORT', '10050'))
olefy_tmp_dir = os.getenv('OLEFY_TMPDIR', '/tmp')
olefy_python_path = os.getenv('OLEFY_PYTHON_PATH', '/usr/bin/python3')
olefy_olevba_path = os.getenv('OLEFY_OLEVBA_PATH', '/usr/local/bin/olevba3')
# 10:DEBUG, 20:INFO, 30:WARNING, 40:ERROR, 50:CRITICAL
olefy_loglvl = int(os.getenv('OLEFY_LOGLVL', 20))
olefy_min_length = int(os.getenv('OLEFY_MINLENGTH', 50))
olefy_del_tmp = int(os.getenv('OLEFY_DEL_TMP', 1))
olefy_del_tmp_failed = int(os.getenv('OLEFY_DEL_TMP_FAILED', 1))

# internal used variables
request_time = '0000000000.000000'
olefy_protocol = 'OLEFY'
olefy_ping = 'PING'
olefy_protocol_sep = '\n\n'
olefy_headers = {}

# init logging
logger = logging.getLogger('olefy')
logging.basicConfig(stream=sys.stdout, level=olefy_loglvl, format='olefy %(levelname)s %(funcName)s %(message)s')

logger.debug('olefy listen address string: {} (type {})'.format(olefy_listen_addr_string, type(olefy_listen_addr_string)))

if not olefy_listen_addr_string:
    olefy_listen_addr = ""
else:
    addr_re = re.compile('[\[" \]]')
    olefy_listen_addr = addr_re.sub('', olefy_listen_addr_string.replace("'", "")).split(',')

# log runtime variables
logger.info('olefy listen address: {} (type: {})'.format(olefy_listen_addr, type(olefy_listen_addr)))
logger.info('olefy listen port: {}'.format(olefy_listen_port))
logger.info('olefy tmp dir: {}'.format(olefy_tmp_dir))
logger.info('olefy python path: {}'.format(olefy_python_path))
logger.info('olefy olvba path: {}'.format(olefy_olevba_path))
logger.info('olefy log level: {}'.format(olefy_loglvl))
logger.info('olefy min file length: {}'.format(olefy_min_length))
logger.info('olefy delete tmp file: {}'.format(olefy_del_tmp))
logger.info('olefy delete tmp file when failed: {}'.format(olefy_del_tmp_failed))

if not os.path.isfile(olefy_python_path):
    logger.critical('python path not found: {}'.format(olefy_python_path))
    exit(1)
if not os.path.isfile(olefy_olevba_path):
    logger.critical('olevba path not found: {}'.format(olefy_olevba_path))
    exit(1)

# olefy protocol function
def protocol_split( olefy_line ):
    header_lines = olefy_line.split('\n')
    for line in header_lines:
        if line == 'OLEFY/1.0':
            olefy_headers['olefy'] = line
        elif line != '':
            kv = line.split(': ')
            if kv[0] != '' and kv[1] != '':
                olefy_headers[kv[0]] = kv[1]
    logger.debug('olefy_headers: {}'.format(olefy_headers))

# calling oletools
def oletools( stream, tmp_file_name, lid ):
    if olefy_min_length > stream.__len__():
        logger.error('{} {} bytes (Not Scanning! File smaller than {!r})'.format(lid, stream.__len__(), olefy_min_length))
        out = b'[ { "error": "File too small" } ]'
    else:
        tmp_file = open(tmp_file_name, 'wb')
        tmp_file.write(stream)
        tmp_file.close()

        file_magic = magic.Magic(mime=True, uncompress=True)
        file_mime = file_magic.from_file(tmp_file_name)
        logger.info('{} {} (libmagic output)'.format(lid, file_mime))

        if stream[:4] == "\x50\x4b\x03\x04" or \
           stream[:4] == "\x50\x4b\x05\x06" or \
           stream[:4] == "\x50\x4b\x07\x08" or \
           'encrypted' in file_mime or 'zip' in file_mime:
               wordlist = '/tmp/{}-wordlist'.format(lid)
               for i in range(0,10):
                   try:
                       with open(wordlist, 'r') as wlf:
                           words = wlf.read()
                       logger.debug('Words from wordlist-file: {}:'.format(words))
                       break
                   except FileNotFoundError:
                       time.sleep(0.5)
                       logger.info('Attempt {}'.format(i))
                       pass
               if i >= 9:
                   logger.warning('Cannot read Wordlist - {} attempts!'.format(i))
               else:
                   # TODO - JOHN THINGS
                   os.system("~/john/run/zip2john {}".format(tmp_file))
                   logger.info("john")

        elif 'text' in file_mime:
            # extract the wordlist from the mail
            logger.debug('Mail-body: {}'.format(stream.decode('utf-8', 'ignore')))
            wordlist = wwwordlist.runwwwordlist(stream.decode('utf-8', 'ignore'),'mailfile')

            try:
                # write wordlist to file
                wFile = open(tmp_file_name, 'w+')
                for word in wordlist:
                    wFile.write(word + '\n')
                #wFile.seek(0)
                #logger.debug('File Content: {}'.format(wfile.read()))
                wFile.close()

                wordlist = '/tmp/{}-wordlist'.format(lid)
                type(lid)
                os.symlink(tmp_file_name, wordlist)
            except Exception as e:
                logger.error('An Error Occured!: ' + str(e))
                raise
        else:
            logger.info('Mime {} not processed!'.format(file_mime))
    # logger.debug('{} response: {}'.format(lid, out.decode('utf-8', 'ignore')))
    return b'\t\n\n\t '  #out + b'\t\n\n\t'

# Asyncio data handling, default AIO-Functions
class AIO(asyncio.Protocol):
    def __init__(self):
        self.extra = bytearray()

    def connection_made(self, transport):
        global request_time
        peer = transport.get_extra_info('peername')
        logger.debug('{} new connection was made'.format(peer))
        self.transport = transport
        request_time = str(time.time())

    def data_received(self, request, msgid=1):
        peer = self.transport.get_extra_info('peername')
        logger.debug('{} data received from new connection'.format(peer))
        self.extra.extend(request)

    def eof_received(self):
        peer = self.transport.get_extra_info('peername')
        olefy_protocol_err = False
        proto_ck = self.extra[0:2000].decode('utf-8', 'ignore')

        headers = proto_ck[0:proto_ck.find(olefy_protocol_sep)]

        if olefy_protocol == headers[0:5]:
            self.extra = bytearray(self.extra[len(headers)+2:len(self.extra)])
            protocol_split(headers)
        else:
            olefy_protocol_err = True

        lid = 'Rspamd-ID' in olefy_headers and '<'+olefy_headers['Rspamd-ID'][:6]+'>' or '<>'

        tmp_file_name = olefy_tmp_dir+'/'+request_time+'.'+str(peer[1])
        logger.debug('{} {} choosen as tmp filename'.format(lid, tmp_file_name))

        if olefy_ping == headers[0:4]:
            is_ping = True
        else:
            is_ping = False

        if not is_ping or olefy_loglvl == 10:
            logger.info('{} {} bytes (stream size)'.format(lid, self.extra.__len__()))

        if olefy_ping == headers[0:4]:
            logger.debug('{} PING request'.format(peer))
            out = b'PONG'
        elif olefy_protocol_err == True or olefy_headers['olefy'] != 'OLEFY/1.0':
            logger.error('{} Protocol ERROR: no OLEFY/1.0 found'.format(lid))
            out = b'[ { "error": "Protocol error" } ]'
        elif 'Method' in olefy_headers:
            if olefy_headers['Method'] == 'oletools':
                out = oletools(self.extra, tmp_file_name, lid)
        else:
            logger.error('Protocol ERROR: Method header not found')
            out = b'[ { "error": "Protocol error: Method header not found" } ]'

        self.transport.write(out)
        if not is_ping or olefy_loglvl == 10:
            logger.info('{} {} response send: {!r}'.format(lid, peer, out))
        self.transport.close()


# start the liste<<<ners
loop = asyncio.get_event_loop()
# each client connection will create a new protocol instance
coro = loop.create_server(AIO, olefy_listen_addr, olefy_listen_port)
server = loop.run_until_complete(coro)
for sockets in server.sockets:
    logger.info('serving on {}'.format(sockets.getsockname()))

# XXX serve requests until KeyboardInterrupt, not needed for production
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# graceful shutdown/reload
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
logger.info('stopped serving')
