# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import collections
import copy
import logging
import os
import re
import time
import sys
import urlparse

from collections import namedtuple
from twisted.internet.task import LoopingCall
from robots_scanner.scanner import scan

import minion.curly
from minion.plugins.base import AbstractPlugin,BlockingPlugin,ExternalProcessPlugin

#
# AlivePlugin
#

class AlivePlugin(BlockingPlugin):

    """
    This plugin checks if the site is alive or not. If any error occurs, the whole plan
    will be aborted. This is useful to have as the first plugin in a workflow. Anything
    non-200 will be seen as a fatal error.
    """

    PLUGIN_NAME = "Alive"
    PLUGIN_WEIGHT = "light"
    FURTHER_INFO = [ {
        "URL": "http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html",
        "Title": "W3C - Status Code Definitions" } ],

    REPORTS = {
        "good":
            {
                "Code": "ALIVE-0",
                "Summary": "Site is reachable",
                "Description": "The server has responded with {status_code} status_code. \
This indicates the site is reachable.",
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": FURTHER_INFO,
             },
        "bad":
            {
                "Code": "ALIVE-1",
                "Summary": "Site could not be reached",
                "Description": None,
                "Severity": "Fatal",
                "URLs": [ { "URL": None, "Extra": None} ],
                "FurtherInfo": FURTHER_INFO,
            }
    }

    def do_run(self):
        try:
            r = minion.curly.get(self.configuration['target'], connect_timeout=5, timeout=15)
            r.raise_for_status()
            issue = self._format_report('good', description_formats={'status_code': str(r.status)})
            self.report_issue(issue)
        except minion.curly.CurlyError as error:
            self.report_issue(error.issue)
            return AbstractPlugin.EXIT_STATE_ABORTED
        except minion.curly.BadResponseError as error:
            issue = self._format_report('bad', description=str(error))
            self.report_issue(issue)
            return AbstractPlugin.EXIT_STATE_ABORTED

#
# XFrameOptionsPlugin
#

class XFrameOptionsPlugin(BlockingPlugin):

    """
    This is a minimal plugin that does one http request to find out if
    the X-Frame-Options header has been set. It does not override anything
    except start() since that one check is quick and there is no point
    in suspending/resuming/terminating.

    All plugins run in a separate process so we can safely do a blocking
    HTTP request. The PluginRunner catches exceptions thrown by start() and
    will report that back as an error state of the plugin.
    """

    PLUGIN_NAME = "XFrameOptions"
    PLUGIN_WEIGHT = "light"

    FURTHER_INFO = [ {
        "URL": "https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options",
        "Title": "Mozilla Developer Network - The X-Frame-Options response header" }]

    REPORTS = {
        "set":
            {
                "Code": "XFO-0",
                "Summary": "X-Frame-Options header is set properly",
                "Description": "Site has the following X-Frame-Options set: {header}",
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": FURTHER_INFO
             },
        "invalid":
            {
                "Code": "XFO-1",
                "Summary": "Invalid X-Frame-Options header detected",
                "Description": "The following X-Frame-Options header value is detected and is invalid: {header}",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
        "not-set":
            {
                "Code": "XFO-2",
                "Summary": "X-Frame-Options header is not set",
                "Description": "X-Frame-Options header is not found. Sites can use this to avoid clickjacking attacks, \
by ensuring that their content is not embedded into other sites.",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },

    }
    def _allow_from_validator(self, value):
        """ Only accept the following basic forms::
        ACCEPT-FROM http://example.org[:port]/[path]
        ACCEPT-FORM https://example.org[:port]/[path]

        Reject those with colon, or uri containing query and/or
        fragement.

        For details, please refer to https://bugzilla.mozilla.org/show_bug.cgi?id=836132#c28
        """
        # for simplicity, keep everything uppercase
        value = value.upper()
        # reject allow-from with colon
        regex = re.compile("ALLOW-FORM:")
        matches = regex.findall(value)
        if matches:
            return False
        # verify url is present and valid
        regex = re.compile(r'(?P<tag>ALLOW-FROM)\s(?P<url>.+)')
        matches = regex.match(value)
        if not matches:
            return False
        url = matches.group('url')
        if url:
            scheme, domain, path, query, fragement = urlparse.urlsplit(url)
            if query or fragement:
                return False
            elif not scheme in ('http', 'https'):
                return False
            return True

    def do_run(self):
        r = minion.curly.get(self.configuration['target'], connect_timeout=5, timeout=15)
        r.raise_for_status()
        if 'x-frame-options' in r.headers:
            xfo_value = r.headers['x-frame-options']
            # 'DENY' and 'SAMEORIGIN' don't carry extra values
            if xfo_value.upper() in ('DENY', 'SAMEORIGIN'):
                issue = self._format_report('set', description_formats={'header': xfo_value})
                self.report_issues([issue])
            # only strict ALLOW-FROM syntax is allowed
            elif 'ALLOW-FROM' in xfo_value.upper():
                if self._allow_from_validator(xfo_value):
                    issue = self._format_report('set', description_formats={'header': xfo_value})
                    self.report_issues([issue])
                else:
                    issue = self._format_report('invalid', description_formats={'header': xfo_value})
                    self.report_issues([issue])
           # found invalid/unknown option value
            else:
                issue = self._format_report('invalid', description_formats={'header': xfo_value})
                self.report_issues([issue])
        else:
            issue = self._format_report('not-set')
            self.report_issues([issue])


class HSTSPlugin(BlockingPlugin):

    """
    This plugin checks if the site sends out an HSTS header if it is HTTPS enabled.
    """

    PLUGIN_NAME = "HSTS"
    PLUGIN_WEIGHT = "light"

    FURTHER_INFO = [ {
        "URL": "https://developer.mozilla.org/en-US/docs/Security/HTTP_Strict_Transport_Security",
        "Title": "Mozilla Developer Network - HTTP Strict Transport Security" }]

    REPORTS = {
        "set":
            {
                "Code": "HSTS-0",
                "Summary": "Strict-Transport-Security header is set properly",
                "Description": "Site has the following Strict-Transport-Security header set: {header}",
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": FURTHER_INFO
             },
        "invalid":
            {
                "Code": "HSTS-1",
                "Summary": "Invalid Strict-Transport-Security header detected",
                "Description": "The following Strict-Transport-Security header value is detected and is invalid: {header}",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
        "not-set":
            {
                "Code": "HSTS-2",
                "Summary": "Strict-Transport-Security header is not set",
                "Description": "Strict-Transport-Security header is not found. This header is a security feature that \
lets a web site tell browsers that it should only be communicated with using HTTPS, instead of using HTTP.",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
        "non-https":
            {
                "Code": "HSTS-3",
                "Summary": "Target is a non-HTTPS site",
                "Description": "Strict-Transport-Security header is only applicable on HTTPS-based site.",
                "Severity": "Info",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
        "negative":
            {
                "Code": "HSTS-3",
                "Summary": "max-age is negative",
                "Description": "Strict-Transport-Security header max-age must be a positive number.",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
    }

    def do_run(self):
        r = minion.curly.get(self.configuration['target'], connect_timeout=5, timeout=15)
        r.raise_for_status()
        if r.url.startswith("https://"):
            if 'strict-transport-security' in r.headers:
                regex = re.compile(r"^max-age=(?P<delta>\d+)(\s)?(;)?(?P<option> includeSubDomains)?$")
                match = regex.match(r.headers['strict-transport-security'])
                if match:
                    groups = match.groupdict()
                    if int(groups['delta']) < 0:
                        issue = self._format_report('negative')
                        self.report_issues([issue])
                    else:
                        issue = self._format_report('set', description_formats={'header': r.headers['strict-transport-security']})
                        self.report_issues([issue])
                else:
                    issue = self._format_report('invalid', description_formats={'header': r.headers['strict-transport-security']})
                    self.report_issues([issue])
            else:
                self.report_issues([self._format_report('not-set')])
        else:
            self.report_issues([self._format_report('non-https')])


class XContentTypeOptionsPlugin(BlockingPlugin):

    """
    This plugin checks if the site sends out a X-Content-Type-Options header
    """

    PLUGIN_NAME = "XContentTypeOptions"
    PLUGIN_WEIGHT = "light"

    FURTHER_INFO = [ {
        "URL": "http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx",
        "Title": "MIME-Handling Change: X-Content-Type-Options: nosniff" }]

    REPORTS = {
        "set":
            {
                "Code": "XCTO-0",
                "Summary": "X-Content-Type-Options is set properly",
                "Description": "Site has the following X-Content-Type-Options header set: {header}",
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": FURTHER_INFO
             },
        "invalid":
            {
                "Code": "XCTO-1",
                "Summary": "Invalid X-Content-Type-Options header detected",
                "Description": "The following X-Content-Type-Options header value is detected and is invalid: {header}",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
        "not-set":
            {
                "Code": "XCTO-2",
                "Summary": "X-Content-Type-Options header is not set",
                "Description": "X-Content-Type-Options header is not found. This header is a security feature that helps \
prevent attacks based on MIME-type confusion.",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },

    }

    def do_run(self):
        r = minion.curly.get(self.configuration['target'], connect_timeout=5, timeout=15)
        r.raise_for_status()
        value = r.headers.get('x-content-type-options')
        if not value:
            self.report_issues([self._format_report('not-set')])
        else:
            if value.lower() == 'nosniff':
                issue = self._format_report('set', description_formats={'header': value})
                self.report_issues([issue])
            else:
                issue = self._format_report('invalid', description_formats={'header': value})
                self.report_issues([issue])

class XXSSProtectionPlugin(BlockingPlugin):

    """
    This plugin checks if the site sends out a X-XSS-Protection header
    """

    PLUGIN_NAME = "XXSSProtection"
    PLUGIN_WEIGHT = "light"

    FURTHER_INFO = [ {
        "URL": "http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-iv-the-xss-filter.aspx",
        "Title": "IE8 Security Part IV: The XSS Filter" }]

    REPORTS = {
        "set":
            {
                "Code": "XXSSP-0",
                "Summary": "X-XSS-Protection is set properly",
                "Description": "Site has the following X-XSS-Protection header set: {header}",
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": FURTHER_INFO
             },
        "invalid":
            {
                "Code": "XXSSP-1",
                "Summary": "Invalid X-XSS-Protection header detected",
                "Description": "The following X-XSS-Protection header value is detected and is invalid: {header}",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
        "not-set":
            {
                "Code": "XXSSP-2",
                "Summary": "X-XSS-Protection header is not set",
                "Description": "X-XSS-Protection header is not found. \
This header enables Cross-site scripting (XSS) filter built into most recent web browsers.",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
        "disabled":
            {
                "Code": "XXSSP-3",
                "Summary": "X-XSS-Protection header is set to disable",
                "Description": "X-XSS-Protection header is set to 0 and consequent disabled Cross-site-scripting (XSS) filter.",
                "Severity": "High",
                "URLs": [ { "URL": None, "Title": None} ],
                "FurtherInfo": FURTHER_INFO
            },
    }

    def do_run(self):
        r = minion.curly.get(self.configuration['target'], connect_timeout=5, timeout=15)
        r.raise_for_status()
        value = r.headers.get('x-xss-protection')
        if not value:
            self.report_issues([self._format_report('not-set')])
        else:
            if value.lower() == '1; mode=block':
                self.report_issues([self._format_report('set', description_formats={'header': value})])
            elif value == '0':
                self.report_issues([self._format_report('disabled', description_formats={'header': value})])
            else:
                self.report_issues([self._format_report('invalid', description_formats={'header': value})])


class ServerDetailsPlugin(BlockingPlugin):

    """
    This plugin checks if the site sends out a Server or X-Powered-By header that exposes details about the server software.
    """

    PLUGIN_NAME = "ServerDetails"
    PLUGIN_WEIGHT = "light"

    FURTHER_INFO = [
        {
            "URL": "http://tools.ietf.org/html/rfc2616#section-14.38",
            "Title": 'RFC 2616 - "Server" header'
        },
        {
            "URL": "https://developer.mozilla.org/en-US/docs/HTTP/Headers",
            "Title": "Mozilla Developer Network - HTTP Headers"
        },
        {
            "URL": "https://en.wikipedia.org/wiki/List_of_HTTP_header_fields",
            "Title": "Wikipedia - List of HTTP header fields",
        }
]

    REPORTS = {
        "set":
            {
                "Code": "SD-0",
                "Summary": "",
                "Description": "Site has set {header} header",
                "Severity": "Medium",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": FURTHER_INFO
             },
         "none":
         {
             "Code": "SD-1",
             "Summary": "No server-detail-type headers set",
             "Description": "None of the following headers is present: {headers}",
             "Severity": "Info",
             "URLs": [ {"URL": None, "Extra": None} ],
             "FurtherInfo": FURTHER_INFO
         }
    }

    def do_run(self):
        r = minion.curly.get(self.configuration['target'], connect_timeout=5, timeout=15)
        r.raise_for_status()
        headers = ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Backend-Server')
        at_least_one = False
        for header in headers:
            if header.lower() in r.headers:
                at_least_one = True
                issue = self._format_report('set', description_formats={'header': header})
                issue['Summary'] = "'%s' header is found" % header
                self.report_issues([issue])
        if not at_least_one:
            self.report_issues([self._format_report('none', description_formats={'headers': headers})])

class RobotsPlugin(BlockingPlugin):

    """
    This plugin checks if the site has a robots.txt.
    """

    PLUGIN_NAME = "Robots"
    PLUGIN_WEIGHT = "light"

    FURTHER_INFO = [
        {
            "URL": "http://www.robotstxt.org/robotstxt.html",
            "Title": 'The Web Robots Pages - About /robots.txt',
        },
        {
            "URL": "https://developers.google.com/webmasters/control-crawl-index/docs/robots_txt",
            "Title": "Google Developers - Robots.txt Specification",
        },
]

    REPORTS = {
        "found":
        {
            "Code": "ROBOTS-0",
            "Summary": "robots.txt found",
            "Description": "Site has a valid robots.txt",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO
         },
         "not-found":
         {
             "Code": "ROBOTS-1",
             "Summary": "robots.txt not found",
             "Description": "Site has no robots.txt",
             "Severity": "Medium",
             "URLs": [ {"URL": None, "Extra": None} ],
             "FurtherInfo": FURTHER_INFO
         },
         "invalid":
         {
            "Code": "ROBOTS-2",
            "Summary": "Invalid entry found in robots.txt",
            "Description": "robots.txt may contain an invalid or unsupport entry.",
            "Severity": "Medium",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
         }
    }

    def validator(self, url):
        """ This validator performs the following checkes:

        1. Invalidate the scan if HTTP status code is not 200,
        2. Invalidate the scan if HTTP content-type header
        is not set to 'text/plain',
        3. Invalidate the scan if robots_scanner.scanner.scan
        finds 'Disallow:' appears before 'User-agent:' does at
        the beginning of the document.

        Known enhancement to be made:
        1. should limit the size of robots.txt acceptable by our
        scanner
        2. use more optimized regex
        """

        url_p = urlparse.urlparse(url)
        url = url_p.scheme + '://' + url_p.netloc + '/robots.txt'
        resp = minion.curly.get(url, connect_timeout=5, timeout=15)
        if resp.status != 200:
            return 'NOT-FOUND'
        if 'text/plain' not in resp.headers['content-type'].lower():
            return False
        try:
            if not scan(resp.body):
                return False
            return True
        except Exception:
            return False

    def do_run(self):
        result = self.validator(self.configuration['target'])
        if result is True:
            self.report_issues([self._format_report('found')])
        if result == 'NOT-FOUND':
            self.report_issues([self._format_report('not-found')])
        elif not result:
            self.report_issues([self._format_report('invalid')])


def format_report(self, issue_key, format_list):
    issue = copy.deepcopy(self.REPORTS[issue_key])
    for component in format_list:
        for component_name, kwargs in component.items():
            issue[component_name] = issue[component_name].format(**kwargs)
    return issue

#
# CSPPlugin
#
class CSPPlugin(BlockingPlugin):

    """
    This plugin checks if a CSP header is set.
    """

    PLUGIN_NAME = "CSP"
    PLUGIN_WEIGHT = "light"

    FURTHER_INFO = [
        {
            "URL": "http://www.w3.org/TR/CSP/",
            "Title": "W3C - Content-Security Policy 1.0"
        },
        {
            "URL": "https://developer.mozilla.org/en-US/docs/Security/CSP",
            "Title": 'Mozilla Developer Network - CSP (Content-Security Policy)',
        },
        {
            "URL": "https://www.owasp.org/index.php/Content_Security_Policy",
            "Title": "OWASP - Content-Security Policy"
        },
        {
            "URL": "https://blog.mozilla.org/security/2013/06/11/content-security-policy-1-0-lands-in-firefox/",
            "Title": "Mozilla Security Blog - Content Security Policy 1.0 Lands in Firefox",
        },
]

    DESCRIPTIONS = {
        "csp": "Content-Security-Policy (CSP) is an added layer of security that helps to detect and mitigate certain \
types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for \
everything from data theft to site defacement or distribution of malware.",
        "xcsp": "X-Content-Security-Policy header is now being deprecated by major browsers such as Firefox, Chrome and \
Opera. It is advised to add Content-Security-Policy header (currently is at 1.0 spec) for users using newer verions of \
browsers, and keep the X-Content-Security-Policy header intact so users who are using out-of-date browsers that support \
CSP can still benefit from the X-CSP protection.",
        "report-only": "The X/Content-Security-Policy-Report-Only header lets the developers to experiment CSP settings \
rather than actually enforcing the policy settings. Missing X/Content-Security-Policy is the same as not having CSP \
in the first place.",
        "unknown-directive": "This plugin checks CSP based on 1.0 specification. CSP 1.1 is a draft version and not all \
browsers support every feature of CSP 1.1. If this scan session has marked CSP 1.1 rules as invalid, you may ignore \
those warnings.",
        "unsafe-inline": "Unless specified in default-src or in script-src or in style-src, inline Javascript and inline \
CSS are not permitted. This default behavior is introduced to mitigate the risk of scripting attacks such as \
Cross Site Scripting (XSS) which take advantage of executing inline Javascript or CSS code during user time. By \
specifying 'unsafe-inline', inline scripting attack may be possible.",
        "unsafe-eval": "Unless specified in default-src or in script-src or in style-src, the eval() function is disabled \
to prevent creating and executing code from string, which is commonly used to create Cross Site Scripting (XSS) vector in \
XSS attack.",
        "none": "CSP allows developers to specify a whitelist of trusted source origins. For example, specifying \
img-src foobar.com means images can only be loaded from foobar.com. 'none' is a special keyword to indicate that no \
sources can be used for loading for the corresponding directive. For example, if an application does not need iframe, \
specifying frame-src 'none' will disallow iframe from being loaded on the target site. When 'none' is present, other \
sources must not be included in the whitelist of the corresponding directive.",
        "allow": "The current CSP 1.0 spec has renamed the directive 'allow' to 'default-src'. The deprecated header, \
X-Content-Security-Policy, works with the deprecated directive 'allow'.",
        "xhr-src": "The current CSP 1.0 spec has renamed the directive 'xhr-src' to 'connect-src'. The deprecated \
header, X-Content-Security-Policy, works with the deprecated directive 'xhr-connect'.",
}

    REPORTS = {
        "csp-set":
        {
            "Code": "CSP-1",
            "Summary": "Content-Security-Policy header is set",
            "Description": DESCRIPTIONS['csp'],
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "csp-not-set":
        {
            "Code": "CSP-2",
            "Summary": "Content-Security-Policy header is not set",
            "Description": DESCRIPTIONS['csp'],
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "csp-ro-only-set":
        {
            "Code": "CSP-3",
            "Summary": "Content-Security-Policy-Report-Only header is set but CSP is missing",
            "Description": DESCRIPTIONS['report-only'],
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "xcsp-set":
        {
            "Code": "CSP-4",
            "Summary": "X-Content-Security-Policy header is set",
            "Description": DESCRIPTIONS['xcsp'],
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "xcsp-not-set":
        {
            "Code": "CSP-5",
            "Summary": "X-Content-Security-Policy header is not set",
            "Description": DESCRIPTIONS['xcsp'],
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "xcsp-ro-only-set":
        {
            "Code": "CSP-6",
            "Summary": "X-Content-Security-Policy-Report-Only header is set but X-CSP is missing",
            "Description": DESCRIPTIONS['report-only'],
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "csp-csp-ro-set":
        {
            "Code": "CSP-7",
            "Summary": "Both Content-Security-Policy and Report-Only headers are set",
            "Description": "description of daul policy.",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "xcsp-xcsp-ro-set":
        {
            "Code": "CSP-8",
            "Summary": "Both X-Content-Security-Policy and Report-Only headers are set",
            "Description": "description of daul policy",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "unknown-directive":
        {
            "Code": "CSP-9",
            "Summary": "Found {count} unrecongized CSP directives",
            "Description": DESCRIPTIONS['unknown-directive'] + 
                           "The followings are the list of unrecongized CSP directives:\n{policies}",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "deprecated-directive":
        {
            "Code": "CSP-10",
            "Summary": "Found {count} deprecated CSP directives",
            "Description": "{description}",
            "Solution": "{solution}",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "bad-none":
        {
            "Code": "CSP-11",
            "Summary": "When 'none' is specify, no other source expressions can be specified",
            "Description": DESCRIPTIONS['none'] + "The following directives specify 'none' and other sources:\n{directives}",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "inline":
        {
            "Code": "CSP-12",
            "Summary": "unsafe-inline is enabled",
            "Description": DESCRIPTIONS['unsafe-inline'] + "The following policies have unsafe-inline specified:\n{policies}",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
        "eval":
        {
            "Code": "CSP-13",
            "Summary": "unsafe-eval is enabled",
            "Description": DESCRIPTIONS['unsafe-eval'] + "The following policies have unsafe-eval specified:\n{policies}",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None}],
            "FurtherInfo": FURTHER_INFO
        },
    }
    SCHEME_SOURCE = r"(https|http|data|blob|javascript|ftp)\:"
    HOST_SOURCE = r'((https|http|data|blob|javascript|ftp)\:\/\/)?((\*\.)?[a-z0-9\-]+(\.[a-z0-9\-]+)*|\*)(\:(\*|[0-9]+))?'
    KEYWORD_SOURCE = r"('self'|'unsafe-inline'|'unsafe-eval')"
    DIRECTIVES = ("default-src", "script-src", "style-src", "object-src", "img-src", \
        "media-src", "frame-src", "font-src", "connect-src", "report-uri")
    DEPRECATED_DIRECTIVES = ("allow", "xhr-src")
    DEPRECATED_DIRECTIVES_PAIR = dict(zip(DEPRECATED_DIRECTIVES, ["default-src", "connect-src"]))
    DESCRIPTIONS = {
        "allow": "allow is deprecated and should be replace with default-src.",
        "xhr-src": "xhr-connect is a deprecated directive name. Use connect-src for CSP 1.0 compliance."
    }
    Policy = namedtuple('Policy', 'directive source_list str')

    def _match(self, uri, regex):
        r = re.compile(regex)
        m = r.match(uri)
        if m and m.group() == uri:
            return True
        else:
            return False

    def _check_headers(self, headers):
        # get the header names
        headers = set(headers)
        csp = csp_ro = xcsp = xcsp_ro = False
        if "content-security-policy" in headers:
            csp = True
        if "content-security-policy-report-only" in headers:
            csp_ro = True
        if "x-content-security-policy" in headers:
            xcsp = True
        if "x-content-security-policy-report-only" in headers:
            xcsp_ro = True

        if csp:
            self.report_issues([self._format_report('csp-set')])
        else:
            self.report_issues([self._format_report('csp-not-set')])

        if csp and csp_ro:
            self.report_issues([self._format_report('csp-csp-ro-set')])
        elif csp_ro and not csp:
            self.report_issues([self._format_report('csp-ro-only-set')])

        if xcsp:
            self.report_issues([self._format_report('xcsp-set')])
        else:
            self.report_issues([self._format_report('xcsp-not-set')])

        if xcsp and xcsp_ro:
            self.report_issues([self._format_report('xcsp-xcsp-ro-set')])
        elif xcsp_ro and not xcsp:
            self.report_issues([self._format_report('xcsp-ro-only-set')])

    def _split_policy(self, csp):
        r1 = re.compile(';\s*')
        r2 = re.compile('\s+')

        # individual directives should be split by ;
        dir_split_list = r1.split(csp)
        # the last item could be empty if ; is present
        dir_split_list = filter(None, dir_split_list)
        
        # split by space so directive name is first element
        # follows by a list of source expressions
        self.policies = []
        for index, directive_group in enumerate(dir_split_list):
            d = r2.split(directive_group)
            self.policies.append(self.Policy(d[0], d[1:], " ".join(d)))

    def _check_directives(self):
        depr_dirs = []
        unknown_dirs = []
        for policy in self.policies:
            if policy.directive in self.DEPRECATED_DIRECTIVES:
                depr_dirs.append(policy)
            elif policy.directive not in self.DIRECTIVES:
                unknown_dirs.append(policy)
        if unknown_dirs:
            unknown_s = "\n".join(p.str for p in unknown_dirs)
            self.report_issues([
                format_report(self, 'unknown-directive', [
                    {'Summary': {"count": len(unknown_dirs)}},
                    {"Description": {"policies": unknown_s}}
                ])
            ])

        if depr_dirs:
            solutions = []
            descriptions = []
            for policy in depr_dirs:
                replacement = self.DEPRECATED_DIRECTIVES_PAIR[policy.directive]
                new_policy = " ".join([replacement] + policy.source_list)
                solution_str = "Replace {old_policy} with {new_policy}".format(
                    old_policy=policy.str, new_policy=new_policy)
                descriptions.append(self.DESCRIPTIONS[policy.directive])
                solutions.append(solution_str)
            self.report_issues([
                format_report(self, 'deprecated-directive', [
                    {'Summary': {"count": len(depr_dirs)}},
                    {"Description": {"description": "\n".join(descriptions)}},
                    {"Solution": {"solution": "\n".join(solutions)}}
                ])
            ])
    def _check_source_lists(self):
        bad_none = []
        inline = []
        eval = []
        for policy in self.policies:
            if "'none'" in policy.source_list:
                if len(policy.source_list) > 1:
                    bad_none.append(policy)
                    # something bad so skip to next directive
                    continue
            if policy.directive in ('style-src', 'script-src'):
                if "'unsafe-inline'" in policy.source_list:
                    inline.append(policy)
                if "'unsafe-eval'" in policy.source_list:
                    eval.append(policy)
        if bad_none:
            self.report_issues([
                format_report(self, 'bad-none', [
                    {'Summary': {'count': len(bad_none)}},
                    {'Description': {'directives': str(bad_none)}}
                ])
            ])
        if inline:
            self.report_issues([
                format_report(self, 'inline', [
                    {'Description': {"policies": "\n".join(p.str for p in inline)}}
                ])
            ])
        if eval:
            self.report_issues([
                format_report(self, 'eval', [
                    {'Description': {"policies": "\n".join(p.str for p in eval)}}
                ])
            ])

    def do_run(self):
        r = minion.curly.get(self.configuration['target'], connect_timeout=5, timeout=15)
        r.raise_for_status()

        self._check_headers(r.headers)
        if "content-security-policy" in r.headers:
            csp = r.headers["content-security-policy"]
            self._split_policy(csp)
            self._check_directives()
            self._check_source_lists()
