# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import json
import pprint
import requests
import shlex
import tempfile
import unittest
from subprocess import Popen, PIPE
from multiprocessing import Process

from flask import Flask
from pymongo import MongoClient

import minion.backend.utils as backend_utils

TEST_VIEW_ROOT = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
test_app = Flask(__name__)
@test_app.route('/')
def basic_app():
    res = make_response('')
    res.headers['X-Content-Type-Options'] = 'nosniff'
    res.headers['X-Frame-Options'] = 'SAMEORIGIN'
    res.headers['X-XSS-Protection'] = '1; mode=block'
    res.headers['Content-Security-Policy'] = 'default-src *'
    return res

BACKEND_KEY = backend_utils.backend_config()['api'].get('key')
BASE = 'http://localhost:8383'
APIS = {'users':
            {'POST': '/users',
             'GET': '/users'},
        'user':
            {'DELETE': '/users/{user_email}',
             'GET': '/users/{user_email}',
             'POST': '/users/{user_email}'},
        'login':
            {'PUT': '/login'},
        'invites':
            {'POST': '/invites',
             'GET': '/invites'},
        'invite': 
            {'POST': '/invites/{id}/control',
             'GET': '/invites/{id}',
             'DELETE': '/invites/{id}'},
        'resend_invite':
            {'POST': '/invites/{id}/resend'},
        'groups':
            {'POST': '/groups',
              'GET': '/groups'},
        'group':
            {'GET': '/groups/{group_name}',
             'DELETE': '/groups/{group_name}',
             'PATCH': '/groups/{group_name}'},
        'sites':
            {'GET': '/sites',
             'POST': '/sites'},
        'site':
            {'GET': '/sites/{site_id}',
             'POST': '/sites/{site_id}'},
        'plans':
            {'GET': '/plans',
             'POST': '/plans'},
        'plan':
            {'GET': '/plans/{plan_name}',
             'DELETE': '/plans/{plan_name}',
             'POST': '/plans/{plan_name}'},
        'get_plugins':
            {'GET': '/plugins'},
        'scans':
            {'POST': '/scans',},
        'scan':
            {'GET': '/scans/{scan_id}',
             'PUT': '/scans/{scan_id}/control'},
        'scan_summary':
            {'GET': '/scans/{scan_id}/summary'},
        'history':
            {'GET': '/reports/history'},
        'issues':
            {'GET': '/reports/issues'},
        'status':
            {'GET': '/reports/status'},
}

def get_api(api_name, method, args=None):
    """ Return a full url and map each key
    in args to the url found in APIS. """
    api = ''.join([BASE, APIS[api_name][method]])
    if args:
        return api.format(**args)
    else:
        return api

def _call(task, method, auth=None, data=None, url_args=None, jsonify=True, \
        headers=None, params=None):
    """
    Make HTTP request.

    Parameters
    ----------
    task : str
        The name of the api to call which corresponds
        to a key name in ``APIS``.
    method : str
        Accept 'GET', 'POST', 'PUT', or
        'DELETE'.
    auth : optional, tuple
        Basic auth tuple ``(username, password)`` pair.
    data : optional, dict
        A dictionary of data to pass to the API.
    url_args : optional, dict
        A dictionary of url arguments to replace in the
        URL. For example, to match user's GET URL which
        requires ``id``, you'd pass ``{'id': '3a7a67'}``.
    jsonify : bool
        If set to False, data will be sent as plaintext like GET.
    headers : dict
        Default to None. GET will send as plain/text while
        POST, PUT, and PATCH will send as application/json.

    Returns
    -------
    res : requests.Response
        The response object.

    """

    req_objs = {'GET': requests.get,
        'POST': requests.post,
        'PUT': requests.put,
        'DELETE': requests.delete,
        'PATCH': requests.patch}

    method = method.upper()
    api = APIS[task][method]
    if url_args:
        api = api.format(**url_args)
    # concatenate base and api
    api = os.path.join(BASE.strip('/'), api.strip('/'))

    req_objs = req_objs[method]
    if jsonify and data and method != 'GET':
        data = json.dumps(data)

    if headers is None:
        if jsonify:
            headers = {'Content-Type': 'application/json',
                    'X-Minion-Backend-Key': BACKEND_KEY}
        else:
            headers = {'X-Minion-Backend-Key': BACKEND_KEY}

    if method == 'GET' or method == 'DELETE':
        res = req_objs(api, params=data, auth=auth, headers=headers)
    else:
        res = req_objs(api, params=params, data=data, auth=auth, headers=headers)
    return res

class TestAPIBaseClass(unittest.TestCase):
    def setUp(self):
        self.mongodb = MongoClient()
        self.mongodb.drop_database("minion")
        self.db = self.mongodb.minion

        self.email = "bob@example.org"
        self.email2 = "alice@example.org"
        self.role = "user"
        self.group_name = "minion-test-group"
        self.group_description = "minion test group is awesome."
        self.group_name2 = "minion-test-group2"
        self.group_description2 = "minion test group 2 is super."

        self.target_url = "http://foo.com"
        self.site2 = "http://bar.com"

        self.target_url = 'http://localhost:1234'

    def tearDown(self):
        self.mongodb.drop_database("minion")

    def import_plan(self, plan_name='basic'):
        ROOT = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))))
        PLANS_ROOT = os.path.join(ROOT, 'plans')
        self.plans = self.db.plans
        self.scans = self.db.scans
        with open(os.path.join(PLANS_ROOT, '%s.plan' % plan_name), 'r') as f:
            self.plan = json.load(f)
            self.plans.remove({'name': self.plan['name']})
            resp = self.create_plan(self.plan)
            self.assertEqual(resp.json()['success'], True)

    @staticmethod
    def _get_plugin_name(full):
        """ Return the name of the plugin. """
        cls_name = full.split('.')[-1]
        return cls_name.split('Plugin')[0]

    def check_plugin_metadata(self, base, metadata):
        """ Given a base configuration, parse
        and verify the input metadata contains
        the following keys: 'version', 'class',
        'weight', and 'name' for each plugin. """

        for index, plugin in enumerate(metadata):
            p_name = self._get_plugin_name(base['workflow'][index]['plugin_name'])
            # the plugin list is either under the key plugin, plugins or
            # iself is already a list. We should consider using plugins
            # over plugin; that is, change the key name in /plugins endpoint.
            meta = plugin.get('plugin') or plugin.get('plugins') or plugin
            self.assertEqual('light', meta['weight'])
            self.assertEqual(p_name, meta['name'])
            self.assertEqual(base['workflow'][index]['plugin_name'], meta['class'])
            self.assertEqual("0.0", meta['version'])

    def login_user(self, email="bob@example.org"):
        data = {"email": email}
        return _call('login', 'PUT', headers={'content-type': 'application/json'}, data=data)

    def create_user(self, email="bob@example.org", name="Bob", role="user", groups=[], headers=None,
            invitation=None):
        data = {"email": email, "name": name, "role": role, "groups":groups, "invitation": invitation}
        return _call('users', 'POST', headers=headers, data=data)

    def update_user(self, user_email, user):
        return _call('user', 'POST', url_args={'user_email': user_email}, data=user)

    def get_user(self, user_email):
        return _call('user', 'GET', url_args={'user_email': user_email})

    def delete_user(self, user_email):
        return _call('user', 'DELETE', url_args={'user_email': user_email})

    def get_users(self):
        return _call('users', 'GET')

    def create_invites(self, recipient=None, sender=None, base_url="http://localhost:8080"):
        return _call('invites', 'POST', 
                data={'recipient': recipient, 'sender': sender, "base_url": "http://localhost:8080"})

    def get_invites(self, filters=None):
        return _call('invites', 'GET', data=filters)

    def get_invite(self, id):
        return _call('invite', 'GET', url_args={'id': id})

    def resend_invite(self, id):
        return _call('resend_invite', 'POST', 
            url_args={'id': id}, data={'base_url': "http://localhost:8080"})
    def update_invite(self, id, resend=None, accept=None, decline=None, base_url="http://localhost:8080", login=None):
        if resend:
            data = {'action': 'resend', "base_url": base_url}
        elif accept:
            data = {'action': 'accept'}
        elif decline:
            data = {'action': 'decline'}
        if login:
            data.update({'login': login})
        return _call('invite', 'POST', url_args={'id': id}, data=data)

    def delete_invite(self, id):
        return _call('invite', 'DELETE', url_args={'id': id})

    def create_group(self, group_name=None, group_description=None, users=None, \
        sites=None):
        if group_name is None:
            group_name = self.group_name
        if not group_description:
            group_description = self.group_description
        data = {'name': group_name, "description": self.group_description}
        if users:
            data.update({'users': users})
        if sites:
            data.update({'sites': sites})

        return _call('groups', 'POST', data=data)

    def get_groups(self):
        return _call('groups', 'GET', jsonify=False)

    def get_group(self, group_name):
        return _call('group', 'GET', url_args={'group_name': group_name},
            jsonify=False)

    def delete_group(self, group_name):
        return _call('group', 'DELETE', url_args={'group_name': group_name},
            jsonify=False)

    def modify_group(self, group_name, data=None):
        return _call('group', 'PATCH', url_args={'group_name': group_name},
            data=data)

    def create_site(self, groups=None, plans=None, site=None, verify=True):
        data = {'url': site or self.target_url}
        if plans:
            data.update({'plans': plans})
        if groups:
            data.update({'groups':groups})
        data.update({'verification': {'enabled': verify, 'value': None}})
        return _call('sites', 'POST', data=data)

    def update_site(self, site_id, site, verify=True):
        site.update({'verification': {'enabled': verify, 'value': None}})
        return _call('site', 'POST', url_args={'site_id': site_id}, data=site)

    def get_sites(self):
        return _call('sites', 'GET', jsonify=False)

    def get_site_by_id(self, site_id):
        return _call('site', 'GET', url_args={'site_id': site_id}, jsonify=False)

    def get_site_by_url(self, url):
        return _call('sites', 'GET', data={'url': url}, jsonify=False)

    def get_plans(self, email=None):
        return _call('plans', 'GET', jsonify=False, data=email)

    def create_plan(self, plan):
        return _call('plans', 'POST', data=plan)

    def update_plan(self, plan_name, plan):
        return _call('plan', 'POST', url_args={'plan_name': plan_name}, data=plan)

    def delete_plan(self, plan_name):
        return _call('plan', 'DELETE', url_args={'plan_name': plan_name}, jsonify=False)

    def get_plan(self, plan_name, email=None):
        return _call('plan', 'GET', url_args={'plan_name': plan_name}, \
            jsonify=False, data={'email': email})

    def get_plugins(self):
        return _call('get_plugins', 'GET', jsonify=False)

    def create_scan(self, email=None, target_url=None):
        if not target_url:
            target_url = self.target_url
        if not email:
            email = self.email
        return _call('scans', 'POST',
            data={'plan': 'basic',
                'configuration': {'target': target_url},
                'user': email})

    def get_scan(self, scan_id, email=None):
        if not email:
            email = None
        params = {'email': email}
        return _call('scan', 'GET', url_args={'scan_id': scan_id}, \
                data=params, jsonify=False)

    def control_scan(self, scan_id, state='START', email=None):
        if not email:
            email = self.email
        return _call('scan', 'PUT', url_args={'scan_id': scan_id},
            data=state, params={'email': email},jsonify=False)

    def get_scan_summary(self, scan_id, email=None):
        if not email:
            email = self.email
        return _call('scan_summary', 'GET', \
            url_args={'scan_id': scan_id}, data={'email': email}, jsonify=False)

    def get_reports_history(self, user=None):
        data = {}
        if user is not None:
            data = {'user': user}
        return _call('history', 'GET', data=data, jsonify=False)

    def get_reports_status(self, user=None, group_name=None):
        data = None
        if user is not None:
            data = {'user': user}
            if group_name is not None:
                data.update({'group_name': group_name})
        return _call('status', 'GET', data=data, jsonify=False)

    def get_reports_issues(self, user=None, group_name=None):
        data = None
        if user is not None:
            data = {'user': user}
            if group_name is not None:
                data.update({'group_name': group_name})
        return _call('issues', 'GET', data=data, jsonify=False)

    def _test_keys(self, target, expected):
        """
        Compare keys are in the response. If there
        is a difference (more or fewer) assertion
        will raise False.

        Parameters
        ----------
        target : tuple
            A tuple of keys from res.json().keys()
        expected : tuple
            A tuple of keys expecting to match
            against res.json().keys()

        """

        keys1 = set(expected)
        self.assertEqual(set(), keys1.difference(target))

    def assertSuccessfulResponse(self, r, success=True, reason=None):
        r.raise_for_status()
        self.assertEqual(r.json()['success'], success)
        if not success and reason is not None:
            self.assertEqual(r.json()['reason'], reason)

    """
    def start_smtp(self):
        # pid is a list, a hack so we can get back the pid in the caller frame
        self.stop_smtp()
        def start():
            p = Popen('/usr/bin/sudo /usr/bin/python -m smtpd -n -c DebuggingServer localhost:25',
                    stdin=PIPE, stdout=PIPE, shell=True)
            while True:
                out = p.stdout.read()
                err = p.stderr.read()
                if len(out) > 0:
                    with open('/tmp/minion_smtp_debug.txt', 'w+') as f:
                        f.write(out)
        p = Process(target=start)
        p.daemon = True
        p.start()

    def stop_smtp(self):
        def stop():
            p = Popen("/usr/bin/sudo kill -9 `ps aux | grep DebuggingServer | awk '{print $2}'`", shell=True)
            p.communicate()
        p = Process(target=stop)
        p.daemon = True
        p.start()
    """
    
