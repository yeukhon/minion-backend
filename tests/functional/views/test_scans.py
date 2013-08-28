# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint
import requests
import time
from flask import Flask, make_response
from multiprocessing import Process
from subprocess import Popen, PIPE

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

test_app = Flask(__name__)

@test_app.route('/')
def basic_app():
    res = make_response('')
    res.headers['X-Content-Type-Options'] = 'nosniff'
    res.headers['X-Frame-Options'] = 'SAMEORIGIN'
    res.headers['X-XSS-Protection'] = '1; mode=block'
    res.headers['Content-Security-Policy'] = 'default-src *'
    return res

class TestScanAPIs(TestAPIBaseClass):
    def setUp(self):
        super(TestScanAPIs, self).setUp()
        self.import_plan()
 
    def start_server(self):
        ''' Similar to plugin functional tests, we need
        to start server.'''
        def run_app():
            test_app.run(host='localhost', port=1234)
        self.server = Process(target=run_app)
        self.server.daemon = True
        self.server.start()
       
    def stop_server(self):
        self.server.terminate()

    def test_create_scan_with_credential(self):
        res1 = self.create_user(email=self.email)
        res2 = self.create_group(group_name='test', users=[self.email,])
        res3 = self.create_site(plans=['basic'], groups=['test'], verify=False)

        # we have to manually update group to contain a site
        res4 = self.modify_group('test', data={'addSites': [self.target_url,]})

        res5 = self.create_scan(email=self.email, target_url=self.target_url) 
        expected_top_keys = ('success', 'scan',)
        self._test_keys(res5.json().keys(), expected_top_keys)

        expected_scan_keys = ('id', 'state', 'created', 'queued', 'started', \
                'finished', 'plan', 'configuration', 'sessions', 'meta',)
        self._test_keys(res5.json()['scan'].keys(), expected_scan_keys)
        # since ticket 106, scans keeps track of who started the scan now
        meta = res5.json()['scan']['meta']
        self.assertEqual(meta['user'], self.email)
        self.assertEqual(meta['tags'], [])
        self.assertEqual(res5.json()['scan']['configuration']['target'],
            self.target_url)

        scan = res5.json()['scan']
        for session in scan['sessions']:
            expected_session_keys = ('id', 'state', 'plugin', 'configuration', \
                    'description', 'artifacts', 'issues', 'created', 'started', \
                    'queued', 'finished', 'progress',)
            self._test_keys(session.keys(), expected_session_keys)
            self.assertEqual(session['configuration']['target'], self.target_url)

            self.assertEqual(session['state'], 'CREATED')
            self.assertEqual(session['artifacts'], {})
            self.assertEqual(session['issues'], [])
            for name in ('queued', 'started', 'finished', 'progress'):
                self.assertEqual(session[name], None)

    def test_get_scan(self):
        res1 = self.create_user(email=self.email)
        res2 = self.create_group(group_name='test', users=[self.email,])
        res3 = self.create_site(plans=['basic'], groups=['test'])
        # update group so it has the site as well
        res4 = self.modify_group('test', data={'addSites': [self.target_url,]})
        res5 = self.create_scan(email=self.email, target_url=self.target_url)
        scan_id = res5.json()['scan']['id']
        res6 = self.get_scan(scan_id, email=self.email)
        # since scan hasn't started, should == res5
        self.assertEqual(res5.json(), res6.json())

        # get scan detail without supplying email in the query (issue #140, #146)
        res7 = self.get_scan(scan_id)
        self.assertEqual(res7.json(), res6.json())
    
    # issue#140 and issue #146
    def test_get_scan_with_bad_permission(self):
        res0 = self.create_user(email='fakeuser@example.org')
        res1 = self.create_user(email=self.email)
        res2 = self.create_group(group_name='test', users=[self.email,])
        res3 = self.create_site(plans=['basic'], groups=['test'])
        # update group so it has the site as well
        res4 = self.modify_group('test', data={'addSites': [self.target_url,]})
        res5 = self.create_scan(email=self.email, target_url=self.target_url)
        scan_id = res5.json()['scan']['id']
        res6 = self.get_scan(scan_id, email='fakeuser@example.org')
        self.assertEqual(res6.json()['success'], False)
        self.assertEqual(res6.json()['reason'], 'not-found')
    
    def test_start_basic_scan(self):
        """
        This test is very comprehensive. It tests
        1. POST /scans
        2. GET /scans/<scan_id>
        3. PUT /scans/<scan_id>/control
        4. GET /scans/<scan_id>/summary
        5. GET /reports/history
        6. GET /reports/status
        7. GET /reports/issues

        ** some apis are checked with and without email.
        """
        self.start_server()

        res1 = self.create_user(email=self.email)
        res2 = self.create_group(users=[self.email,], group_name='test_group')
        res3 = self.create_site(plans=['basic'], groups=['test_group'], verify=False)
        res3 = self.modify_group('test_group', data={'addSites': [self.target_url,]})

        # POST /scans
        res4 = self.create_scan(email=self.email)
        scan_id = res4.json()['scan']['id']
        #pprint.pprint(res4.json(), indent=3)

        # PUT /scans/<scan_id>/control
        res5 = self.control_scan(scan_id, 'START')
        self.assertEqual(len(res5.json().keys()), 1)
        self.assertEqual(res5.json()['success'], True)
        #pprint.pprint(res5.json(), indent=3)

        # GET /scans/<scan_id>
        res6 = self.get_scan(scan_id)
        self._test_keys(res6.json().keys(), set(res4.json().keys()))
        self._test_keys(res6.json()['scan'].keys(), set(res4.json()['scan'].keys()))
        self.assertEqual(res6.json()['scan']['state'], 'QUEUED')
        #pprint.pprint(res6.json(), indent=3)
        
        # give scanner a few seconds
        time.sleep(10)
        # GET /scans/<scan_id>
        # now check if the scan has completed or not
        res7 = self.get_scan(scan_id, email=self.email)
        #pprint.pprint(res7.json(), indent=3)
        self.assertEqual(res7.json()['scan']['state'], 'FINISHED')
        
        # GET /scans/<scan_id>/summary
        res8 = self.get_scan_summary(scan_id, email=self.email)
        self.assertEqual(res8.json()['summary']['meta'], 
            {'user': self.email, 'tags': []}) # ticket 106
        # check without email supplied
        res81 = self.get_scan_summary(scan_id)
        self.assertEqual(res81.json(), res8.json())
     
        # GET /reports/history
        res9 = self.get_reports_history()
        expected_top_keys = ('report', 'success',)
        self._test_keys(res9.json().keys(), expected_top_keys)
        expected_inner_keys = ('configuration', 'created', 'finished', 'id',
                'issues', 'plan', 'queued', 'sessions', 'state',)
        self._test_keys(res9.json()['report'][0].keys(), expected_inner_keys)
        self.assertEqual(res9.json()['report'][0]['id'], scan_id)
        
        #pprint.pprint(res9.json(), indent=3)
        # GET /reports/status
        res10 = self.get_reports_status(user=self.email)
        expected_top_keys = ('success', 'report',)
        self._test_keys(res10.json().keys(), expected_top_keys)
        expected_inner_keys = ('plan', 'scan', 'target',)
        #pprint.pprint(res10.json(), indent=2)
        self._test_keys(res10.json()['report'][0].keys(), expected_inner_keys)
        self.assertEqual(res10.json()['report'][0]['plan'], 'basic')
        self.assertEqual(res10.json()['report'][0]['target'], self.target_url)

        # GET /reports/issues
        res11 = self.get_reports_issues(user=self.email)
        expected_top_keys = ('report', 'success', )
        self._test_keys(res11.json().keys(), expected_top_keys)
        expected_inner_keys = ('issues', 'target',)
        self._test_keys(res11.json()['report'][0].keys(), expected_inner_keys)

        issues = res11.json()['report'][0]['issues']
        # total of 8 basic plugins. they should all return something even if info
        self.assertEqual(len(issues), 8)

        # alive scan
        self.assertEqual('Site is reachable', issues[0]['summary'])
        self.assertEqual('Info', issues[0]['severity'])

        # x-frame-options scan
        self.assertEqual('X-Frame-Options header is set properly', issues[1]['summary'])
        self.assertEqual('Info', issues[1]['severity'])

        # strict-transport
        self.assertEqual('Target is a non-HTTPS site', issues[2]['summary'])
        self.assertEqual('Info', issues[2]['severity'])

        # x-content-type-options
        self.assertEqual('X-Content-Type-Options is set properly', issues[3]['summary'])
        self.assertEqual('Info', issues[3]['severity'])

        # x-xss-protection
        self.assertEqual('X-XSS-Protection is set properly', issues[4]['summary'])
        self.assertEqual('Info', issues[4]['severity'])

        # server details headers
        self.assertEqual("'Server' header is found", issues[5]['summary'])
        self.assertEqual('Medium', issues[5]['severity'])

        # robots
        self.assertEqual("robots.txt not found", issues[6]['summary'])
        self.assertEqual('Medium', issues[6]['severity'])

        # CSP
        self.assertEqual('Content-Security-Policy header set properly', issues[7]['summary'])
        self.assertEqual('Info', issues[7]['severity'])

        self.assertEqual(res11.json()['report'][0]['target'], self.target_url)
        self.stop_server()
        #pprint.pprint(res11.json(), indent=3)

        
