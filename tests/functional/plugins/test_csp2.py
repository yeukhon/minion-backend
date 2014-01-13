# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import sys
import time
import unittest

from flask import make_response

from base import TestPluginBaseClass, test_app
from minion.plugins.basic import CSPPlugin

CSP = {'default': "default-src 'self';"
}

def render_response(type, value):
    value = CSP[value]
    res = make_response("")
    if type.lower() == 'x':
        res.headers['X-Content-Security-Policy'] = value
    elif type.lower() == 'c':
        res.headers['Content-Security-Policy'] = value
    return res

@test_app.route('/no-csp')
def no_csp():
    res = make_response()
    return res

@test_app.route('/csp')
def csp():
    return render_response('c', 'default')

class TestCSPPlugin(TestPluginBaseClass):
    __test__ = True
    @classmethod
    def setUpClass(cls):
        super(TestCSPPlugin, cls).setUpClass()
        cls.pname = 'CSPPlugin'

    def _run(self, api_name):
        base = 'http://localhost:1234'
        API = base + api_name
        # first, examine via plugin-runner and then quickly make request to api
        runner_resp = self.run_plugin(self.pname, API)
        try:
            request_resp = requests.get(API, verify=False)
        except requests.exceptions.ConnectionError:
            request_resp = requests.exceptions.ConnectionError
        return runner_resp

    def _expecting_codes(self, resps, expects):
        codes = [item['data']['Code'] for item in resps 
                    if item.get('data') and item['data'].get('Code')]
        for expect in expects:
            self.assertEqual(True, expect in codes)

    def test_no_csp(self):
        api_name = "/no-csp"
        resp = self._run(api_name)
        self._expecting_codes(resp, ['CSP-8'])

    def test_csp(self):
        api_name = "/csp"
        resp = self._run(api_name)
        self._expecting_codes(resp, ['CSP-7'])
