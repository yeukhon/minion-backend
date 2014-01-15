# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import sys
import time
import unittest

from flask import make_response
from collections import namedtuple

from base import TestPluginBaseClass, test_app
from minion.plugins.basic import CSPPlugin

CSP = {
    'default': "default-src 'self';",
    'unknown': "default-src 'self'; unknown-src 'self';",
    'allow': "allow 'self';",
    'match-none': "default-src 'none';",
    'bad-none': "default-src 'self' 'none'",
    'eval': "default-src 'self'; script-src 'unsafe-eval' 'self';",
    'inline': "default-src 'self'; script-src 'unsafe-inline' 'self';"
}

def render_response(types, value):
    res = make_response("")
    value = CSP.get(value)
    for t in types:
        _t = t.lower()
        if t == 'xcsp':
            res.headers.add('X-Content-Security-Policy', value)
        elif t == 'csp':
            res.headers.add('Content-Security-Policy', value)
        elif t == 'csp-ro':
            res.headers.add('Content-Security-Policy-Report-Only', value)
        elif t == "xcsp-ro":
            res.headers['X-Content-Security-Policy-Report-Only'] = value
    return res

@test_app.route('/no-csp')
def no_csp():
    res = make_response()
    return res

@test_app.route('/csp')
def csp():
    return render_response(['csp'], 'default')

@test_app.route('/csp-ro-only')
def csp_ro_only():
    return render_response(['csp-ro'], 'default')

@ test_app.route('/xcsp')
def xcsp():
    return render_response(['xcsp'], 'default')

@test_app.route('/xcsp-ro-only')
def xcsp_ro_only():
    return render_response(['xcsp-ro'], 'default')

@test_app.route('/csp-csp-ro')
def csp_csp_ro():
    return render_response(['csp', 'csp-ro'], 'default')

@test_app.route('/xcsp-xcsp-ro')
def xcsp_xcsp_ro():
    return render_response(['xcsp', 'xcsp-ro'], 'default')

@test_app.route('/csp-unknown-directive')
def csp_unknown_directive():
    return render_response(['csp'], 'unknown')

@test_app.route('/csp-deprecated-directive')
def csp_deprecated_directive():
    return render_response(['csp'], 'allow')

@test_app.route('/match-none')
def good_none():
    return render_response(['csp'], 'match-none')

@test_app.route('/bad-none')
def bad_none():
    return render_response(['csp'], 'bad-none')

@test_app.route('/eval')
def eval():
    return render_response(['csp'], 'eval')

@test_app.route('/inline')
def inline():
    return render_response(['csp'], 'inline')

class TestCSPPlugin(TestPluginBaseClass):
    __test__ = True
    Issue = namedtuple('Issue', 'code summary severity')
    CSP = CSPPlugin()

    @classmethod
    def setUpClass(cls):
        super(TestCSPPlugin, cls).setUpClass()
        cls.pname = 'CSPPlugin'

    def _get_summary(self, key, fill_with=None):
        _summary = self.CSP.REPORTS[key]['Summary']
        if fill_with:
            return _summary.format(**fill_with)
        else:
            return _summary

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

    def _test_expecting_code(self, expect, issues):
        codes = [issue.code for issue in issues]
        self.assertEqual(True, expect in codes)
    
    def _test_expecting_summary(self, expect, issues):
        summaries = [issue.summary for issue in issues]
        self.assertEqual(True, expect in summaries)

    def _test(self, resps, code, summary):
        issues = []
        for issue in resps:
            if issue.get('data') and issue['data'].get('Code'):
                _issue = self.Issue(issue['data']['Code'],
                                    issue['data']['Summary'],
                                    issue['data']['Severity'])
                issues.append(_issue)
        self._test_expecting_code(code, issues)
        self._test_expecting_summary(summary, issues)

    def test_csp(self):
        api_name = "/csp"
        resp = self._run(api_name)
        code = 'CSP-1'
        summary = self._get_summary('csp-set')
        self._test(resp, code, summary)

    def test_no_csp(self):
        api_name = "/no-csp"
        resp = self._run(api_name)
        code = 'CSP-2'
        summary = self._get_summary('csp-not-set')
        self._test(resp, code, summary)

    def test_csp_ro_only(self):
        api_name = "/csp-ro-only"
        resp = self._run(api_name)
        code = 'CSP-3'
        summary = self._get_summary('csp-ro-only-set')
        self._test(resp, code, summary)

    def test_xcsp(self):
        api_name = "/xcsp"
        resp = self._run(api_name)
        code = 'CSP-4'
        summary = self._get_summary('xcsp-set')
        self._test(resp, code, summary)

    def test_no_xcsp(self):
        api_name = '/csp'
        resp = self._run(api_name)
        code = 'CSP-5'
        summary = self._get_summary('xcsp-not-set')
        self._test(resp, code, summary)

    def test_xcsp_ro_only(self):
        api_name = "/xcsp-ro-only"
        resp = self._run(api_name)
        code = 'CSP-6'
        summary = self._get_summary('xcsp-ro-only-set')
        self._test(resp, code, summary)

    def test_csp_csp_ro(self):
        api_name = "/csp-csp-ro"
        resp = self._run(api_name)
        code = 'CSP-7'
        summary = self._get_summary('csp-csp-ro-set')
        self._test(resp, code, summary)

    def test_xcsp_xcsp_ro(self):
        api_name = "/xcsp-xcsp-ro"
        resp = self._run(api_name)
        code = 'CSP-8'
        summary = self._get_summary('xcsp-xcsp-ro-set')
        self._test(resp, code, summary)

    def test_csp_unknown_directive(self):
        api_name = "/csp-unknown-directive"
        resp = self._run(api_name)
        code = 'CSP-9'
        summary = self._get_summary('unknown-directive',
                                    fill_with={"count": 1})
        self._test(resp, code, summary)

    def test_csp_deprecated_directive(self):
        api_name = "/csp-deprecated-directive"
        resp = self._run(api_name)
        code = 'CSP-10'
        summary = self._get_summary('deprecated-directive',
                                    fill_with={"count": 1})
        summary = summary.format({"count": str(1)})
        self._test(resp, code, summary)

    def test_match_none(self):
        api_name = '/match-none'
        resp = self._run(api_name)
        code = 'CSP-12'
        summary = self._get_summary('match-none',
                                    fill_with={"count": 1})
        self._test(resp, code, summary)

    def test_bad_none(self):
        api_name = '/bad-none'
        resp = self._run(api_name)
        code = 'CSP-13'
        summary = self._get_summary('bad-none',
                                    fill_with={"count": 1})
        self._test(resp, code, summary)

    def test_inline(self):
        api_name = '/inline'
        resp = self._run(api_name)
        code = 'CSP-14'
        summary = self._get_summary('inline')
        self._test(resp, code, summary)

    def test_eval(self):
        api_name = '/eval'
        resp = self._run(api_name)
        code = 'CSP-15'
        summary = self._get_summary('eval')
        self._test(resp, code, summary)
