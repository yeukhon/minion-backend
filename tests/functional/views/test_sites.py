# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

class TestSitesAPIs(TestAPIBaseClass):
    def setUp(self):
        super(TestSitesAPIs, self).setUp()
        self.import_plan(plan_name='basic')
        # bug #144 (won't fix until future)
        #self.import_plan(plan_name='nmap')
        #self.import_plan(plan_name='zap')

    def test_create_site(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.create_site()
        expected_top_keys = ('success', 'site',)
        #pprint.pprint(res2.json(), indent=2)
        self._test_keys(res2.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'url', 'plans', 'created',)
        self._test_keys(res2.json()['site'].keys(), expected_inner_keys)
        self.assertEqual(res2.json()['site']['url'], self.target_url)
        #self.assertEqual(res2.json()['site']['groups'], [self.group_name])
        self.assertEqual(res2.json()['site']['plans'], [])

    def test_create_duplicate_site(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.create_site()
        res3 = self.create_site()
        expected_top_keys = ('success', 'reason',)
        self._test_keys(res3.json().keys(), expected_top_keys)
        self.assertEqual(res3.json()['success'], False)
        self.assertEqual(res3.json()['reason'], 'site-already-exists')

    def test_get_all_sites(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.create_site()
        res3 = self.get_sites()
        expected_top_keys = ('success', 'sites', )
        self._test_keys(res3.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'url','groups', 'created', 'plans')
        self._test_keys(res3.json()['sites'][0].keys(), expected_inner_keys)
        self.assertEqual(res3.json()['sites'][0]['url'], self.target_url)
        self.assertEqual(res3.json()['sites'][0]['groups'], [])
        self.assertEqual(res3.json()['sites'][0]['plans'], [])

    def test_get_site(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.create_site()
        site_id = res2.json()['site']['id']
        res3 = self.get_site(site_id)
        expected_top_keys = ('success', 'site', )
        self._test_keys(res3.json().keys(), expected_top_keys)
        # until #49, #50, #51 are resolved, this is commented
        self.assertEqual(res3.json()['site'], res2.json()['site'])


    def test_update_site_with_plan_and_groups(self):
        res = self.create_user()
        res1 = self.create_group('foo')
        res1 = self.create_group('bar')
        res1 = self.create_group('baz')
        res2 = self.create_site(groups=[], plans=[])
        original_site = res2.json()['site']
        # Verify that the new site has no plans and no groups
        self.assertEqual(original_site['plans'], [])
        self.assertEqual(original_site['groups'], [])
        # Update the site, add a plan and group
        self.update_site(original_site['id'], {'plans':['basic'], 'groups': ['foo']})
        # Verify that the site has these new settings
        r = self.get_site(original_site['id'])
        site = r.json()['site']
        self.assertEqual(sorted(site['plans']), sorted(['basic']))
        self.assertEqual(sorted(site['groups']), sorted(['foo']))
        self.assertEqual(original_site['url'], site['url'])
        # Update the site, replace plans and groups
        self.update_site(site['id'], {'groups': ['bar','baz']})  #bug #144
        #self.update_site(site['id'], {'plans':['nmap','zap'], 'groups': ['bar','baz']})  #bug #144
        # Verify that the site has these new settings
        r = self.get_site(original_site['id'])
        site = r.json()['site']
        #self.assertEqual(sorted(site['plans']), sorted(['nmap', 'zap']))  #bug #144
        self.assertEqual(sorted(site['plans']), ['basic'])
        self.assertEqual(sorted(site['groups']), sorted(['bar', 'baz']))
        self.assertEqual(original_site['url'], site['url'])

    def test_update_unknown_site(self):
        r = self.update_site('e22dbe0c-b958-4050-a339-b9a88fa7cd01',
                             {'plans':['nmap','zap'], 'groups': ['bar','baz']})
        r.raise_for_status()
        j = r.json()
        self.assertEqual(j, {'success': False, 'reason': 'no-such-site'})

    def test_update_site_with_unknown_group(self):
        r = self.create_site(groups=[], plans=[])
        r.raise_for_status()
        site = r.json()['site']
        r = self.update_site(site['id'], {'plans':[], 'groups': ['doesnotexist']})
        r.raise_for_status()
        j = r.json()
        self.assertEqual(j, {'success': False, 'reason': 'unknown-group'})

    def test_update_site_with_unknown_plan(self):
        r = self.create_site(groups=[], plans=[])
        r.raise_for_status()
        site = r.json()['site']
        r = self.update_site(site['id'], {'plans':['doesnotexist'], 'groups': []})
        r.raise_for_status()
        j = r.json()
        self.assertEqual(j, {'success': False, 'reason': 'unknown-plan'})

    def test_update_change_site_url(self):
        res1 = self.create_user()
        res2 = self.create_group('foo')
        res3 = self.create_site(site='http://foo.com', groups=['foo'])
        res4 = self.update_site(res3.json()['site']['id'], 
            {'url': 'http://bar.com'})
        self.assertEqual(res4.json()['site']['url'], 'http://bar.com')
        # group should have the new url as well
        res5 = self.get_group('foo')
        self.assertEqual(1, len(res5.json()['group']['sites']))
        self.assertEqual('http://bar.com', res5.json()['group']['sites'][0])

    def test_update_only_change_plans(self):
        r = self.create_group(group_name='foo')
        r.raise_for_status()
        r = self.create_site(groups=['foo'], plans=['basic'])
        r.raise_for_status()
        original_site = r.json()['site']
        # Verify that the new site is correct
        self.assertEqual(['basic'], original_site['plans'])
        self.assertEqual(['foo'], original_site['groups'])
        # Update just the plans
        r = self.update_site(original_site['id'], {'plans':['nmap']})
        r.raise_for_status()
        # Make sure the groups have not been changed
        r = self.get_site(original_site['id'])
        site = r.json()['site']
        #self.assertEqual(sorted(['nmap']), sorted(site['plans'])) #bug 144
        self.assertEqual(['basic'], site['plans'])
        self.assertEqual(sorted(['foo']), sorted(site['groups']))

    def test_update_only_change_groups(self):
        r = self.create_group(group_name='foo')
        r = self.create_group('bar')
        r.raise_for_status()
        r = self.create_site(groups=['foo'], plans=['basic'])
        r.raise_for_status()
        original_site = r.json()['site']
        # Verify that the new site is correct
        self.assertEqual(['basic'], original_site['plans'])
        self.assertEqual(['foo'], original_site['groups'])
        # Update just the groups
        r = self.update_site(original_site['id'], {'groups':['bar']})
        r.raise_for_status()
        # Make sure the plans have not been changed
        r = self.get_site(original_site['id'])
        site = r.json()['site']
        self.assertEqual(sorted(['basic']), sorted(site['plans']))
        self.assertEqual(sorted(['bar']), sorted(site['groups']))

