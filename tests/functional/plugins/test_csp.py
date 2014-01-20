# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import sys
import time
import unittest

from flask import make_response, request
from collections import namedtuple

from base import TestPluginBaseClass, test_app
from minion.plugins.basic import CSPPlugin

@test_app.route('/test')
def endpoint():
    headers = request.args.getlist("headers")
    policy = request.args.get("policy", "default-src 'self';")
    res = make_response("")

    for h in headers:
        _h = h.lower()
        if _h == 'xcsp':
            res.headers.add('X-Content-Security-Policy', policy)
        elif _h == 'csp':
            res.headers.add('Content-Security-Policy', policy)
        elif _h == 'csp-ro':
            res.headers.add('Content-Security-Policy-Report-Only', policy)
        elif _h == "xcsp-ro":
            res.headers['X-Content-Security-Policy-Report-Only'] = policy
    return res
    
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

    def _run(self, headers=None, policy=None):
        API = "http://localhost:1234/test"
        r = requests.Request('GET', API, 
            params={"headers": headers, "policy": policy}).prepare()
        runner_resp = self.run_plugin(self.pname, r.url)
        return runner_resp

    def _get_issues(self, resps):
        issues = []
        for issue in resps:
            if issue.get('data') and issue['data'].get('Code'):
                _issue = self.Issue(issue['data']['Code'],
                                    issue['data']['Summary'],
                                    issue['data']['Severity'])
                issues.append(_issue)
        return issues

    def _test_expecting_codes(self, issues, expects, message):
        self.assertEqual(len(issues), len(expects), msg=message)
        for expect in expects:
            self._test_expecting_code(issues, expect, message)

    def _test_expecting_code(self, issues, expect, message):
        codes = [issue.code for issue in issues]
        self.assertEqual(True, expect in codes, msg=message)
    
    def _test_expecting_summary(self, issues, summary_name, message,
            fill_with=None):
        summaries = [issue.summary for issue in issues]
        expecting_summary = self._get_summary(summary_name, fill_with=fill_with)
        self.assertEqual(True, expecting_summary in summaries, msg=message)

    # Start testing
    # Testing pattern:
    # 1. first assert the main issue is raised for that test
    # 2. then assert other expecting issues
    #
    # NOTE: Good report should include {msg: start} and finish
    #       which adds 2 to the total number of expected
    #       issues returned in the response.

    def test_csp(self):
        resp = self._run(headers=['csp'])
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'csp-set',
            "CSP is set should be in issues")

        self._test_expecting_codes(issues,
            ['CSP-1', 'CSP-5'],
            "Expecting CSP is set, XCSP is not set and number of unspecified directives")

    def test_no_csp_and_no_xcsp(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'csp-not-set',
            "CSP is not set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-5'],
            "CSP is not set and XCSP is not set")

    def test_only_csp_ro_only(self):
        resp = self._run(headers=['csp-ro'])
        issues = self._get_issues(resp)

        self._test_expecting_summary(
            issues,
            'csp-ro-only-set',
            "CSP-Report-Only is set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-3', 'CSP-5'],
            "Expecting CSP is not set, CSP-RO is set and XCSP is not set")

    def test_only_xcsp_is_set(self):
        resp = self._run(headers=['xcsp'])
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'xcsp-set',
            "XCSP is set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-4'],
            "Expecting CSP is not set and XCSP is set.")

    def test_only_xcsp_ro_only(self):
        resp = self._run(headers=['xcsp-ro'])
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'xcsp-ro-only-set',
            "XCSP-Report-Only is set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-5', 'CSP-6'],
            "Expecting CSP and XCSP are not set but XCSP-RO is set")

    def test_csp_and_csp_ro_are_set(self):
        resp = self._run(headers=['csp', 'csp-ro'])
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'csp-csp-ro-set',
            "Both CSP and CSP-Report-Only are set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-7'],
            "Expecting CSP, CSP and CSP-RO are set but XCSP is not set")

    def test_xcsp_and_xcsp_ro_are_set(self):
        resp = self._run(headers=['xcsp', 'xcsp-ro'])
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'xcsp-xcsp-ro-set',
            "Both XCSP and XCSP-Report-Only are set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-4', 'CSP-8'],
            "Expecting XCSP, XCSP and XCSP-RO are set but CSP is not set")

    def test_unknown_directive_in_csp_only_header(self):
        resp = self._run(headers=['csp'],
            policy="default-src 'self'; unknown-directive 'self';")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'unknown-directive',
            "1 unknown directive should be in issues",
            fill_with={"count": 1})

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-9'],
            "Expecting CSP is set, XCSP is not set and 1 unknown directive")

    def test_csp_deprecated_directive(self):
        resp = self._run(headers=['csp'],
            policy="allow 'self'; xhr-src foobar.com;")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'deprecated-directive',
            "2 unknown directive should be in issues",
            fill_with={"count": 2})

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-10'],
            "Expecting CSP is set, XCSP is not set, 2 deprecated directives.")

    def test_none_used_with_other_source_expressions(self):
        resp = self._run(headers=['csp'],
            policy="default-src 'self'; style-src 'self' 'none';")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'bad-none',
            "'none' issue should be in issue")

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-11'],
            "Expecting CSP is set, XCSP is not set, and improper use of 'none'")

    def test_inline(self):
        resp = self._run(headers=['csp'],
            policy="default-src 'self'; style-src 'unsafe-inline';")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'inline',
            "unsafe-inline is enabled should be in issue")

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-12'],
            "Expecting CSP is set, XCSP is not set, and unsafe-inline is enabled")

    def test_eval(self):
        resp = self._run(headers=['csp'],
            policy="default-src 'self'; script-src 'unsafe-eval';")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'eval',
            "unsafe-eval is enabled should be in issue")

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-13'],
            "Expecting CSP is set, XCSP is not set, and unsafe-eval is enabled")
