# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import copy
import pprint
import uuid

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

# issue #114
class TestInviteAPIs(TestAPIBaseClass):
    def random_email(self):
        name = str(uuid.uuid4())
        name = ''.join(name.split('-'))
        return name + '@example.org'

    def assertSMTPReceived(self, actual_msg, user_email, invite_url):
        msgs = actual_msg.split('\n')
        # the first and last elements must be '------- MESSAGE BEGING/END -------'
        # [2] --> From ,  [3] --> To,   [4] --> Subject ,  [5] --> X-Peer,
        # [6] --> len(actual_msg)-2  ---> rest of body
        self.assertEqual(True, user_email in msgs[1])
        self.assertEqual(True, invite_url in '\n'.join(msgs[6:-1]))

    def test_post_invite(self):
        recipient = self.random_email()
        # must create both sender and user
        res1 = self.create_user()
        res2 = self.create_user(email=recipient, name='Alice', invitation=True)

        res3 = self.create_invites(recipient=recipient, sender=self.email)
        self.assertSuccessfulResponse(res3)
        expected_top_keys = ('success', 'invite',)
        self._test_keys(res3.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'recipient', 'sender', 'sent_on', 'accepted_on', \
                'sender_name', 'recipient_name')
        self._test_keys(res3.json()['invite'].keys(), expected_inner_keys)
        self.assertEqual(res3.json()['invite']['recipient'], recipient)
        self.assertEqual(res3.json()['invite']['sender'], self.email)
        self.assertEqual(res3.json()['invite']['recipient_name'], 'Alice')
        self.assertEqual(res3.json()['invite']['sender_name'], 'Bob')
        self.assertEqual(True, res3.json()['invite']['accepted_on'] is None)
        self.assertEqual(True, res3.json()['invite']['sent_on'] is not None)
        self.assertEqual(True, res3.json()['invite']['id'] is not None)
        # issue 172
        self.assertEqual(res3.json()['invite']['status'], 'pending')


    # bug #133
    def test_send_invite_with_groups_and_sites(self):
        recipient = self.random_email()
        res1 = self.create_user()
        res2 = self.create_user(email=recipient, name='Alice', invitation=True)
        res2 = self.create_invites(recipient=recipient, sender=self.email)
        invite_id = res2.json()['invite']['id']
        # also create a group and a site
        res3 = self.create_site()
        site_id = res3.json()['site']['id']
        res4 = self.create_group(group_name='test')
        res5 = self.modify_group('test', data={'addSites': [self.target_url]})
        # update user to the group and site
        res6 = self.modify_group('test', data={'addUsers': [recipient,]})
        res7 = self.update_site(site_id, {'users': ['test'],})
        # check user belongs to them
        res8 = self.get_group('test')
        self.assertEqual(res8.json()['group']['users'], [recipient,])
        res9 = self.get_site_by_id(site_id)

        # remove invitation
        res10 = self.delete_invite(invite_id)
        self.assertEqual(res10.json()['success'], True)
        # check user is removed from sites and groups association
        res11 = self.get_group('test')
        self.assertEqual(res11.json()['group']['users'], [])

    def test_invite_existing_recipient(self):
        # I know. Create yourself again?
        recipient = self.random_email()
        res1 = self.create_user(email=recipient)
        res2 = self.create_invites(recipient=recipient, sender=recipient)
        self.assertEqual(res2.json()['success'], False)
        self.assertEqual(res2.json()['reason'], 'recipient-already-joined')

    def test_duplicate_invitations(self):
        recipient = self.random_email()
        res1 = self.create_user()
        res2 = self.create_user(email=recipient, invitation=True)
        res3 = self.create_invites(recipient=recipient, sender=self.email)
        res4 = self.create_invites(recipient=recipient, sender=self.email)
        self.assertEqual(res3.json()['success'], True)
        self.assertEqual(res4.json()['success'], False)
        self.assertEqual(res4.json()['reason'], 'duplicate-invitation-not-allowed')

    def test_sender_not_found(self):
        recipient = self.random_email()
        res1 = self.create_user(email=recipient, invitation=True)
        res2 = self.create_invites(recipient=recipient, sender=self.email)
        self.assertEqual(res2.json()['success'], False)
        self.assertEqual(res2.json()['reason'], 'sender-not-found-in-user-record')

    def test_get_all_invites(self):
        recipient1 = self.random_email()
        recipient2 = self.random_email()
        recipient3 = self.random_email()
        res1 = self.create_user()
        res1 = self.create_user(email=recipient1, name='Alice', invitation=True)
        res1 = self.create_user(email=recipient2, name='Betty', invitation=True)
        res1 = self.create_user(email=recipient3, name='Cathy', invitation=True)

        res2 = self.create_invites(recipient=recipient1, sender=self.email)
        res3 = self.create_invites(recipient=recipient2, sender=self.email)
        res4 = self.create_invites(recipient=recipient3, sender=self.email)

        res5 = self.get_invites()
        self.assertEqual(len(res5.json()['invites']), 3)
        self.assertEqual(res5.json()['invites'][0]['recipient'], recipient1)
        self.assertEqual(res5.json()['invites'][1]['recipient'], recipient2)
        self.assertEqual(res5.json()['invites'][2]['recipient'], recipient3)

    def test_get_invites_filter_by_sender_and_or_recipient(self):
        recipient1 = self.random_email()
        recipient2 = self.random_email()
        recipient3 = self.random_email()
        sender2 = self.random_email()

        # create senders
        res1 = self.create_user()
        res2 = self.create_user(email=sender2)

        # create recipients in the user table
        res2 = self.create_user(email=recipient1, name='Alice', invitation=True)
        res2 = self.create_user(email=recipient2, name='Betty', invitation=True)
        res2 = self.create_user(email=recipient3, name='Cathy', invitation=True)

        # create recipients
        res3 = self.create_invites(recipient=recipient1, sender=self.email)
        res4 = self.create_invites(recipient=recipient2, sender=sender2)
        res5 = self.create_invites(recipient=recipient3, sender=self.email)

        # only recipient2 is returned given filter by sender
        res6 = self.get_invites(filters={'sender': sender2})
        self.assertEqual(len(res6.json()['invites']), 1)
        self.assertEqual(res6.json()['invites'][0]['recipient'], recipient2)
        self.assertEqual(res6.json()['invites'][0]['sender'], sender2)

        # recipient2 is not returned given filter by sender
        res7 = self.get_invites(filters={'sender': self.email})
        self.assertEqual(len(res7.json()['invites']), 2)
        self.assertEqual(res7.json()['invites'][0]['recipient'], recipient1)
        self.assertEqual(res7.json()['invites'][1]['recipient'], recipient3)

        # only recipient1 is returned given filter by recipient
        res8 = self.get_invites(filters={'recipient': recipient1})
        self.assertEqual(len(res8.json()['invites']), 1)
        self.assertEqual(res8.json()['invites'][0]['recipient'], recipient1)

        # only recipient1 is returned given filter by recipient AND sender
        res9 = self.get_invites(
            filters={'recipient': recipient1, 'sender': self.email})
        self.assertEqual(len(res9.json()['invites']), 1)
        self.assertEqual(res9.json()['invites'][0]['recipient'], recipient1)

    def test_get_invite_by_id(self):
        recipient1 = self.random_email()
        recipient2 = self.random_email()

        # create senders
        res1 = self.create_user()

        # create recipients in the user table
        res1 = self.create_user(email=recipient1, name='Alice', invitation=True)
        res1 = self.create_user(email=recipient2, name='Betty', invitation=True)

        # create invites
        res2 = self.create_invites(recipient=recipient1, sender=self.email)
        res3 = self.create_invites(recipient=recipient2, sender=self.email)

        # get recipient1
        recipient1_id = res2.json()['invite']['id']
        res4 = self.get_invite(id=recipient1_id)
        self.assertEqual(res4.json().get('invite'), res2.json()['invite'])
        self.assertEqual(res4.json()['invite']['recipient'], recipient1)
        self.assertEqual(res4.json()['invite']['sender'], self.email)
        self.assertEqual(res4.json()['invite']['id'], recipient1_id)

    def test_resent_invite(self):
        recipient = self.random_email()
        # create senders
        res1 = self.create_user()

        # create recipients in the user table
        res1 = self.create_user(email=recipient, name='Alice', invitation=True)

        res2 = self.create_invites(recipient=recipient, sender=self.email)
        res3 = self.update_invite(id=res2.json()['invite']['id'],
                resend=True)
        # should not equal
        self.assertNotEqual(res2.json(), res3.json())
        self.assertNotEqual(res2.json()['invite']['id'], res3.json()['invite']['id'])

    def test_decline_invite(self):
        recipient = self.random_email()
        res1 = self.create_user()
        res2 = self.create_user(email=recipient, name='Alice', invitation=True)
        # create a group (bug #175)
        res3 = self.create_group(group_name='test_group')
        self.assertEqual(res3.json()['success'], True)
        self.assertEqual(res3.json()['group']['name'], 'test_group')

        # add user to a group (bug #175)
        res4 = self.update_user(recipient, {'groups': ['test_group']})
        self.assertEqual(res4.json()['user']['groups'], ['test_group'])

        res5 = self.create_invites(recipient=recipient, sender=self.email)
        res6 = self.update_invite(id=res5.json()['invite']['id'],
                decline=True)
        self.assertEqual(res6.json()['invite']['status'], 'declined')

        # check user is no longer in the group (bug #175)
        res7 = self.get_group('test_group')
        self.assertEqual(res7.json()['group']['users'], [])

        # check user no longer exist  (bug #176)
        res8 = self.get_user(recipient)
        self.assertEqual(res8.json()['success'], False)
        self.assertEqual(res8.json()['reason'], 'no-such-user')

    def test_delete_invite(self):
        # Delete recipient1's invitation.
        recipient1 = self.random_email()
        recipient2 = self.random_email()

        res1 = self.create_user()
        # create recipients in the user table
        res1 = self.create_user(email=recipient1, name='Alice', invitation=True)
        res1 = self.create_user(email=recipient2, name='Betty', invitation=True)

        res2 = self.create_invites(recipient=recipient1, sender=self.email)
        recipient1_id = res2.json()['invite']['id']
        res3 = self.create_invites(recipient=recipient2, sender=self.email)
        recipient2_id = res3.json()['invite']['id']

        # ensure we have two records
        res4 = self.get_invites()
        self.assertEqual(len(res4.json()['invites']), 2)
        self.assertEqual(res4.json()['invites'][0]['recipient'], recipient1)
        self.assertEqual(res4.json()['invites'][1]['recipient'], recipient2)

        # we need to ensure users are created and are marked as 'invited' (bug #123)
        res4 = self.get_user(recipient1)
        self.assertEqual(res4.json()['user']['email'], recipient1)
        self.assertEqual(res4.json()['user']['status'], 'invited')
        res4 = self.get_user(recipient2)
        self.assertEqual(res4.json()['user']['email'], recipient2)
        self.assertEqual(res4.json()['user']['status'], 'invited')

        # now delete recipient1
        res5 = self.delete_invite(id=recipient1_id)
        self.assertEqual(res5.json()['success'], True)

        # re-delete should yield false
        res6 = self.delete_invite(id=recipient1_id)
        self.assertEqual(res6.json()['success'], False)
        self.assertEqual(res6.json()['reason'], 'no-such-invitation')

        # recipient1 should not even be in users table anymore
        res7 = self.get_user(recipient1)
        self.assertEqual(res7.json()['success'], False)
        self.assertEqual(res7.json()['reason'], 'no-such-user')

        # we should only get one back
        res8 = self.get_invites()
        self.assertEqual(len(res8.json()['invites']), 1)
        self.assertEqual(res8.json()['invites'][0]['recipient'], recipient2)

    # bug #123
    def test_delete_invite_does_not_delete_accepted_user(self):
        #Delete recipient1's invite does not delete the user if
        #recipient1 has already accepted the invitation.

        recipient1 = self.random_email()

        res1 = self.create_user() # create sender
        res2 = self.create_user(email=recipient1, invitation=True)

        # send invitation
        res3 = self.create_invites(recipient=recipient1, sender=self.email)
        invite_id = res3.json()['invite']['id']
        res4 = self.update_invite(invite_id, accept=True, login=recipient1)
        # check user is no longer invited
        res5 = self.get_user(recipient1)
        self.assertEqual(res5.json()['user']['email'], recipient1)
        self.assertEqual(res5.json()['user']['status'], 'active')

        # now delete invitation
        res6 = self.delete_invite(invite_id)
        # check invitation is gone
        res7 = self.get_invite(invite_id)
        self.assertEqual(res7.json()['success'], False)
        self.assertEqual(res7.json()['reason'], 'invitation-does-not-exist')

        # finally, check user still exist
        res8 = self.get_user(recipient1)
        self.assertEqual(res8.json()['success'], True)
        self.assertEqual(res8.json()['user']['email'], recipient1)
        self.assertEqual(res8.json()['user']['status'], 'active')

    # bug #155
    def test_accept_invite_with_differnet_login(self):
        # accept invite and login with a different persona account provided
        # the new email address is not in the db already.
        recipient = self.random_email()
        persona = self.random_email()
        res1 = self.create_user() # create sender
        res2 = self.create_user(email=recipient, invitation=True)
        userid = res2.json()['user']['id']

        # create a group (bug #170)
        res3 = self.create_group(group_name='test_group')
        self.assertEqual(res3.json()['success'], True)
        self.assertEqual(res3.json()['group']['name'], 'test_group')

        # add user to a group (bug #170)
        res4 = self.update_user(recipient, {'groups': ['test_group']})
        self.assertEqual(res4.json()['user']['groups'], ['test_group'])

        # now send an invite
        res5 = self.create_invites(recipient=recipient, sender=self.email)
        invite_id = res5.json()['invite']['id']

        # accept invite and login with a different email
        res6 = self.update_invite(invite_id, accept=True, login=persona)
        self.assertEqual(res6.json()['success'], True)

        # this should raise not found
        res7 = self.get_user(recipient)
        self.assertEqual(res7.json()['success'], False)
        self.assertEqual(res7.json()['reason'], 'no-such-user')

        # get user by persona email
        res8 = self.get_user(persona)
        self.assertEqual(res8.json()['user']['email'], persona)
        self.assertEqual(res8.json()['user']['status'], 'active')
        # the userid should be the same as the one created through invite
        self.assertEqual(userid, res8.json()['user']['id'])

        # bug #170
        # check original email recipient is not in group anymore
        res9 = self.get_group('test_group')
        self.assertEqual(res9.json()['group']['users'], [persona])

    def test_accept_invite_with_an_existing_email(self):
        # accept an invite with an existing account in Minion should
        # remove the invite account created and reassociate everything
        # to the existing user account.

        invited_user = self.random_email()
        existing_user = self.random_email()
        res1 = self.create_user() # create sender
        res2 = self.create_user(email=invited_user, invitation=True)
        res3 = self.create_user(email=existing_user)
        userid = res2.json()['user']['id']

        res4 = self.create_group(group_name='test_group1')
        self.assertEqual(res4.json()['success'], True)
        self.assertEqual(res4.json()['group']['name'], 'test_group1')

        res5 = self.create_group(group_name='test_group2')
        self.assertEqual(res5.json()['success'], True)
        self.assertEqual(res5.json()['group']['name'], 'test_group2')

        # add invited_user to test_group1
        # add existing_user to test_group2
        res6 = self.update_user(invited_user, {'groups': ['test_group1']})
        self.assertEqual(res6.json()['user']['groups'], ['test_group1'])
        res7 = self.update_user(existing_user, {'groups': ['test_group2']})
        self.assertEqual(res7.json()['user']['groups'], ['test_group2'])

        # now send an invite
        res8 = self.create_invites(recipient=invited_user, sender=self.email)
        invite_id = res8.json()['invite']['id']

        # accept invite and login with a different email (and this email already exists)
        res9 = self.update_invite(invite_id, accept=True, login=existing_user)
        self.assertEqual(res9.json()['success'], True)

        # this should raise not found
        res10 = self.get_user(invited_user)
        self.assertEqual(res10.json()['success'], False)
        self.assertEqual(res10.json()['reason'], 'no-such-user')

        # see whats going on with the existing user
        res10 = self.get_user(existing_user)
        self.assertEqual(res10.json()['user']['email'], existing_user)
        self.assertEqual(res10.json()['user']['status'], 'active')

        # check invited user is not in test_group1 anymore
        res11 = self.get_group('test_group1')
        self.assertEqual(True, invited_user not in res11.json()['group']['users'])
    
        # check existing user now in test_group1
        res12 = self.get_group('test_group1')
        self.assertEqual(res12.json()['group']['users'], [existing_user])
        # check existing user is still in test_group2
        res13 = self.get_group('test_group2')
        self.assertEqual(res13.json()['group']['users'], [existing_user])

