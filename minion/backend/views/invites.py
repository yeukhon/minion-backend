#!/usr/bin/env python

import calendar
import datetime
import uuid
import smtplib
from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.views.base import api_guard, backend_config, invites, users, groups, sites
from minion.backend.views.users import _find_groups_for_user, _find_sites_for_user, update_group_association, remove_group_association

def send_email(action_type, data, extra_data=None):
    if action_type == 'invite':
        data = send_invite(data, extra_data['base_url'])
    elif action_type in ('accept', 'decline'):
        data = notify_on_action(action_type, data)
    try:
        backend_utils.email(action_type, data)
    except smtplib.SMTPSenderRefused:
        return jsonify(success=False, reason="Sender email requires authentication.")
    except smtplib.SMTPRecipientsRefused:
        return jsonify(success=False, reason="Recipient refused to receive email.")
    except smtplib.SMTPException:
        return jsonify(success=False, reason="Unable to send email.")

def send_invite(invite_data, base_url):
    # if it doesn't have '/' url will be inaccessible
    invite_url = base_url.strip('/') + '/' + invite_data['id']
    email_data = {
        'from_name': invite_data['sender_name'],
        'from_email': invite_data['sender'],
        'to_name': invite_data['recipient_name'],
        'to_email': invite_data['recipient'],
        'invite_url': invite_url,
        'subject': '%s invited you to try Minion' % invite_data['sender_name']}
    return email_data

def notify_on_action(action_type, invite_data):
    if action_type == 'accept':
        subject = invite_data['recipient_name'] + ' just joined Minion'
    elif action_type == 'decline':
        subject = invite_data['recipient_name'] + ' has declined your invitation'
    email_data = {
        "from_email": backend_config['email'].get('admin_email') \
            or invite_data['sender'],
        "from_name": backend_config['email'].get('admin_email_name') \
            or invite_data['sender_name'],
        "to_name": invite_data['sender_name'],
        "to_email": invite_data['sender'],
        "new_user_name": invite_data['recipient_name'],
        "subject": subject}
    return email_data

def search(model, filters=None):
    if filters:
        filters = {field: value for field, value in filters.iteritems() if value is not None}
        return model.find(filters)
    else:
        return model.find()

def sanitize_invite(invite):
    if invite.get('_id'):
        del invite['_id']
    if invite.get('sent_on'):
        invite['sent_on'] = calendar.timegm(invite['sent_on'].utctimetuple())
    if invite.get('accepted_on'):
        invite['accepted_on'] = calendar.timegm(invite['accepted_on'].utctimetuple())
    if invite.get('expire_on'):
        invite['expire_on'] = calendar.timegm(invite['expire_on'].utctimetuple())
    return invite

def sanitize_invites(invite_results):
    results = []
    for invite in invite_results:
        results.append(sanitize_invite(invite))
    return results

def load_user_and_invite(invite_id):
    """
    Return a tuple invitation and user if the invitation
    and user are found. Otherwise, a non-success response
    will be returned.
    """
    invitation = invites.find_one({'id': invite_id})
    if not invitation:
        raise Exception("Invitation not found.")
    user = users.find_one({'email': invitation['recipient']})
    if not user:
        raise Exception("User not found.")
    if invitation["accepted_on"]:
        raise Exception("Used invitation is not reusable.")
    return invitation, user

def invite_has_expired(invitation):
    """ Given the invitation document from the database,
    verify whether the invitation has expired or not. """
    if (invitation['expire_on'] - datetime.datetime.utcnow()).seconds < 0:
        return True
    else:
        return False

#
#
# Create a new invite
#
#  POST /invites
# 
#  {'recipient': 'recipient@example.org,
#    'sender': 'sender@example.org'}
#
#
#  Returns (id, recipient, recipient_name, 
#           sender, sender_name, sent_on, accepted_on,
#           expire_on, status)

@app.route('/invites', methods=['POST'])
@api_guard('application/json')
def create_invites():
    recipient = request.json['recipient']
    sender = request.json['sender']
    recipient_user = users.find_one({'email': recipient})
    recipient_invite = invites.find_one({'recipient': recipient})
    sender_user = users.find_one({'email': sender})
    # issue #120
    # To ensure no duplicate invitation is allowed, and to ensure
    # we don't corrupt user record in user table, any POST invitation
    # must check
    # (1) if user is not created in users collection - FALSE
    # (2) if user is created, BUT status is not 'invited' - FALSE
    # (3) recipient email is found in existing invitation record - FALSE
    if not recipient_user:
        return jsonify(success=False, 
                reason='recipient-not-found-in-user-record')
    elif recipient_user.get('status') != 'invited':
        return jsonify(success=False, 
                reason='recipient-already-joined')
    if recipient_invite:
        return jsonify(success=False,
                reason='duplicate-invitation-not-allowed')
    if not sender_user:
        return jsonify(success=False,
                reason='sender-not-found-in-user-record')

    invite_id = str(uuid.uuid4())
    # some users may not have name filled out?
    invite = {'id': invite_id,
              'recipient': recipient,
              'recipient_name': recipient_user['name'] or recipient,
              'sender': sender,
              'sender_name': sender_user['name'] or sender,
              'sent_on': None,
              'accepted_on': None,
              'status': 'pending',
              'expire_on': None,
              'max_time_allowed': request.json.get('max_time_allowed') \
                      or backend_config.get('email').get('max_time_allowed'),
              'notify_when': request.json.get('notify_when', [])}
    send_email('invite', invite, extra_data={'base_url': request.json['base_url']})
     
    invite['sent_on'] = datetime.datetime.utcnow()
    invite['expire_on'] = invite['sent_on'] + \
        datetime.timedelta(seconds=invite['max_time_allowed'])
    invites.insert(invite)
    return jsonify(success=True, invite=sanitize_invite(invite))


# 
# Get a list of invites based on filters.
# 
# GET /invites
# GET /invites?sender=<sender_email>
# GET /invites?recipient=<recipient_email>
#
# Returns a list of invites based on filters. Default to no filter.
# [{'id': 7be9f3b0-ca70-45df-a78a-fc86e541b5d6,
#   'recipient': 'recipient@example.org',
#   'recipient_name': 'recipient',
#   'sender': 'sender@example.org',
#   'sender_name': 'sender',
#   'sent_on': '1372181278',
#   'accepted_on': '1372181279',
#   'expire_on': 1372191288',
#   'status': 'used/expired/declined',
#   ....]
#

@app.route('/invites', methods=['GET'])
@api_guard
def get_invites():
    recipient = request.args.get('recipient', None)
    sender = request.args.get('sender', None)
    results = search(invites, filters={'sender': sender, 'recipient': recipient})
    return jsonify(success=True, invites=sanitize_invites(results))

# 
# GET an invitation record given the invitation id
#
# GET /invites/<id>
#
# Returns the invites data structure
# {'id': 7be9f3b0-ca70-45df-a78a-fc86e541b5d6,
#   'recipient': 'recipient@example.org',
#   'recipient_name': 'recipient',
#   'sender': 'sender@example.org',
#   'sender_name': 'sender',
#   'sent_on': '1372181278',
#   'accepted_on': '1372181279',
#   'expire_on': 1372191288',
#   'status': 'used/expired/declined'}
#

@app.route('/invites/<id>', methods=['GET'])
@api_guard
def get_invite(id):
    invitation = invites.find_one({'id': id})
    if invitation:
        return jsonify(success=True, invite=sanitize_invite(invitation))
    else:
        return jsonify(success=False, reason='Invitation not found.')

#
# DELETE an invitation given the invitation id
#

@app.route('/invites/<id>', methods=['DELETE'])
@api_guard
def delete_invite(id):
    invitation = invites.find_one({'id': id})
    if not invitation:
        return jsonify(success=False, reason='Invitation not found.')
    # do not delete users that are not invite pending (bug #123)
    email = invitation['recipient']
    user = users.find_one({'email': email})
    if user and user.get('status') == "invited":
        users.remove(user)
        # bug #133 delete user associations
        remove_group_association(email)
        
    invites.remove({'id': id})
    return jsonify(success=True)

@app.route('/invites/<invite_id>/decline', methods=['POST'])
@api_guard('application/json')
def decline_invitation(invite_id):
    """ Set invitation to declined and send out notification if necessary. """
    try:
        invitation, user = load_user_and_invite(invite_id)
    except Exception as e:
        return jsonify(success=False, reason=str(e))
    invitation['status'] = 'declined'
    remove_group_association(invitation['recipient'])
    users.remove(user)
    invites.save(invitation)
 
    # notify inviter if he chooses to
    if "decline" in invitation['notify_when']:
        send_email('decline', invitation)
    return jsonify(success=True, invite=sanitize_invite(invitation))

# POST a new invitation email again
# {'base_url': 'http://foobar.com/'}
@app.route('/invites/<invite_id>/resend', methods=['POST'])
@api_guard('application/json')
def resend_invitation(invite_id):
    """ Send a new invitation email to the recipient. """
    timenow = datetime.datetime.utcnow()
    try:
        invitation, user = load_user_and_invite(invite_id)
    except Exception as e:
        return jsonify(success=False, reason=str(e))
    send_email('invite', invitation, extra_data={'base_url': request.json['base_url']})

    # update the invitation record
    invitation['sent_on'] = timenow
    max_time_allowed = invitation.get('max_time_allowed') or \
        backend_config.get('invitation').get('max_time_allowed')
    invitation['expire_on'] = invitation['sent_on'] + datetime.timedelta(seconds=max_time_allowed)
    invites.save(invitation)
    return jsonify(success=True, invite=sanitize_invite(invitation))

# POST /invites/<invite_id>/accept
# {'login': login_email_address}
@app.route('/invites/<invite_id>/accept', methods=['POST'])
@api_guard('application/json')
def accept_invite(invite_id): 
    """ Accept an invitation with either the invited email,
    an existing Minion user account, or a new email account. """

    timenow = datetime.datetime.utcnow()
    try:
        invitation, user = load_user_and_invite(invite_id)
    except Exception as e:
        return jsonify(success=False, reason=str(e))

    if invite_has_expired(invitation):
        invitation['status'] = 'expired'
        invites.save(invitation)
    else:
        invitation['status'] = 'accepted'
        invitation['accepted_on'] = timenow

        # case1: login with invited email account
        if invitation['recipient'] == request.json['login']:
            user['status'] = 'active'
            users.save(user)
        # case2&3: login with a different email account
        else:
            update_group_association(invitation['recipient'], request.json['login'])
            # if login already exists, remove the invited user account
            if users.find_one({'email': request.json['login']}):
                users.remove({'email': invitation['recipient']})
            else: 
                user['email'] = request.json['login']
                user['status'] = 'active'
                users.save(user) 
        invites.save(invitation)

        # now user joined, notify inviter if inviter enabled it
        if "accept" in invitation['notify_when']:
            send_email('accept', invitation)

    return jsonify(success=True, invite=sanitize_invite(invitation))
