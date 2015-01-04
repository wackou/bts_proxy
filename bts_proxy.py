#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# bts_proxy - Proxy providing RPC access control to the BitShares client
# Copyright (c) 2014 Nicolas Wack <wackou@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from http.server import BaseHTTPRequestHandler, HTTPServer
from os.path import expanduser, join, exists
import base64
import requests
import json
import sys


PORT = None
USER = None
PASS = None

CONFIG = None


class UnauthorizedError(Exception):
    pass


def default_data_dir():
    if sys.platform.startswith('linux'):
        return '~/.BitShares'
    elif sys.platform == 'darwin':
        return '~/Library/Application Support/BitShares'
    else:
        return None


DEFAULT_CONFIG = """
{
    "port": 5681,

    "users": [
        {
            "name": "name1",
            "password": "pass1",
            "methods_allowed": ["*"]
        }
    ]
}
"""


def load_config(data_dir=None):
    global CONFIG, PORT, USER, PASS

    data_dir = data_dir or default_data_dir()
    if not data_dir:
        print('You need to specify a data dir for the proxy to fetch RPC information!')
        print('Exiting...')
        sys.exit(1)

    data_dir = expanduser(data_dir)
    config_file = join(data_dir, 'proxy.json')

    if not exists(config_file):
        print('Could not find config file for proxy...')
        print('Creating default one in: %s' % config_file)
        print('Please edit and configure with your own values')
        with open(config_file, 'w') as f:
            f.write(DEFAULT_CONFIG)
        sys.exit(1)

    with open(config_file) as f:
        CONFIG = json.load(f)

    # TODO: validate config schema/values

    # get RPC connection info to client
    try:
        with open(join(data_dir, 'config.json')) as f:
            cfg = json.load(f)['rpc']
            PORT = int(cfg['httpd_endpoint'].split(':')[1])
            USER = cfg['rpc_user']
            PASS = cfg['rpc_password']
    except Exception:
        print('Failed to read bts client RPC config:')
        raise


def rpc_call(data):
    host = 'localhost'
    url = "http://%s:%d/rpc" % (host, PORT)
    headers = {'Content-Type': 'application/json'}

    response = requests.post(url,
                             auth=(USER, PASS),
                             data=data,
                             headers=headers,
                             stream=True)

    if response.status_code == 401:
        raise UnauthorizedError

    return response.raw.read()


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_AUTHHEAD(self):
        #print('send header AUTHHEAD')
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="bts wallet"')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def do_POST(self):
        ''' Present frontpage with user authentication. '''
        header = self.headers.get('Authorization')

        if header is None:
            self.do_AUTHHEAD()
            self.wfile.write(b'no auth header received')
            return

        header = header.encode('utf-8')

        for user in CONFIG['users']:
            auth_string = '%s:%s' % (user['name'], user['password'])
            auth_string = base64.b64encode(auth_string.encode('utf-8'))
            valid_auth_header = b' '.join([b'Basic', auth_string])

            if header == valid_auth_header:
                # properly authenticated
                length = int(self.headers['Content-Length'])
                request = self.rfile.read(length).decode('utf-8')

                # TODO: filter by method
                payload = json.loads(request)

                # forward rpc call to client
                try:
                    result = rpc_call(request)
                    self.do_HEAD()
                    self.wfile.write(result)
                    return

                except UnauthorizedError:
                    self.do_AUTHHEAD()
                    self.wfile.write(b'Unauthorized connection from proxy to client')
                    return


        # wrong authentication (no corresponding user/password)
        self.do_AUTHHEAD()
        self.wfile.write(b'Unauthorized')



def main():
    load_config()

    print('Starting proxy server on port: %d' % CONFIG['port'])
    httpd = HTTPServer(('', CONFIG['port']), Handler)

    httpd.serve_forever()

if __name__ == '__main__':
    main()