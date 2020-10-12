#!/usr/bin/env python3
# Needs python 3.6 or greater

import argparse
import json
import logging
import os
import requests
import sys
import traceback

LOG_WEBHOOK = os.environ.get('LOG_WEBHOOK', None)
MC = os.environ.get('MC', 'https://console.mobiledgex.net')
SLACK = 'https://slack.com/api/'

TEST_MODE_FORMAT = "slacktest2+{}@venky.duh-uh.com".format
SLACK_RESP_LIMITS = 200
MEX_EMAIL_SUFFIX = '@mobiledgex.com'
SPECIAL_MC_ORGS = {
    'MobiledgeX',
    'GDDT',
}
SPECIAL_ORG_USERS = set()
START_FROM = os.environ.get('START_FROM', '2019-12-03')
LOG_LEVEL = logging.DEBUG if os.environ.get('LOG_LEVEL', None) == 'debug' else logging.WARNING
LOOKUPS = {}
SKIP_CHANNELS = set()

logging.basicConfig(level=LOG_LEVEL,
                    format='%(asctime)s [%(levelname)s] {%(pathname)s:%(lineno)d} %(message)s')

def slack_log(message):
    if LOG_WEBHOOK:
        requests.post(LOG_WEBHOOK, json={'text': message})
    logging.warning(message)

def login(username, password):
    r = requests.post(f"{MC}/api/v1/login",
                      data={'username': username,
                            'password': password})
    if r.status_code != requests.codes.ok:
        raise Exception(f"login: {r.status_code} {r.text}")

    return r.json()['token']

def apicall(path, token, data={}):
    r = requests.post(f"{MC}/api/v1/auth/{path}",
                      headers={
                          'Authorization': f"Bearer {token}"
                      },
                      data=data)
    if r.status_code != requests.codes.ok:
        raise Exception(f"{path}: {r.status_code} {r.text}")

    return r

def orglist(token, newer_than=None):
    r = apicall('org/show', token)

    orglist = r.json()
    if newer_than:
        orglist = [ x for x in orglist if x['CreatedAt'] > newer_than ]

    return orglist

def userlist(token, args, newer_than=None):
    r = apicall('user/show', token)

    userlist = [ x for x in r.json() if not x['Email'].lower().endswith(MEX_EMAIL_SUFFIX) ]
    if newer_than:
        userlist = [ x for x in userlist if x['CreatedAt'] > newer_than ]

    if args.test_mode:
        for user in userlist:
            nemail = TEST_MODE_FORMAT(user['Email'].split('@')[0].replace('+', '-'))
            logging.info(f"Test mode email switch: {user['Email']} -> {nemail}")
            user['Email'] = nemail

    return userlist

def userorglist(token):
    r = apicall('role/assignment/show', token)

    rolelist = r.json()
    users = {}
    for role in rolelist:
        org = role['org']
        roleuser = role['username']
        if not org or org in SPECIAL_MC_ORGS:
            logging.info(f"Skipping special org: {roleuser}: {org}")
            SPECIAL_ORG_USERS.add(roleuser)
            continue

        if roleuser not in users:
            users[roleuser] = set()
        users[roleuser].add(org)

    return users

def slack_api_get(path, token,
                  content_type='application/x-www-form-urlencoded',
                  params={}):
    rparams = {'token': token}
    rparams.update(params)
    r = requests.get(f"{SLACK}/{path}",
                     params=rparams,
                     headers={
                         'Content-Type': content_type,
                     })
    if r.status_code != requests.codes.ok:
        raise Exception(f"{path}: {r.status_code} {r.text}")

    return r

def slack_api_get_paginated(path, token, list_item,
                            content_type='application/x-www-form-urlencoded',
                            params={}):
    resp_list = []
    if 'limit' not in params:
        params['limit'] = str(SLACK_RESP_LIMITS)
    cursor = None
    while (True):
        if cursor:
            params['cursor'] = cursor
        r = slack_api_get(path, token, content_type=content_type, params=params)
        resp = r.json()
        try:
            resp_list.extend(resp[list_item])
        except KeyError as e:
            logging.exception(f"{list_item} not found in response: {resp}")
            raise e

        meta = resp['response_metadata']
        if not meta['next_cursor']:
            break

        logging.info(f"slack {path}: loading next page of {params['limit']} results")
        cursor = meta['next_cursor']

    return resp_list

def slack_api_post(path, token, data={}):
    rdata = {'token': token}
    rdata.update(data)
    logging.debug(rdata)
    r = requests.post(f"{SLACK}/{path}", data=rdata)
    if r.status_code != requests.codes.ok:
        raise Exception(f"{path}: {r.status_code} {r.text}")

    logging.debug(r.text)
    return r

def slack_channels(token):
    r = slack_api_get_paginated('conversations.list', token, 'channels',
                                params={'types': 'private_channel'})
    channels = {
        'by_name': {},
        'by_id': {},
    }
    for channel in r:
        cname = channel['name']
        cid = channel['id']
        cpriv = channel['is_private']
        carch = channel['is_archived']

        channels['by_name'][cname] = {
            'id': cid,
            'name': cname,
            'is_private': cpriv,
            'is_archived': carch,
        }
        channels['by_id'][cid] = channels['by_name'][cname]

    return channels

def slack_users(token):
    r = slack_api_get_paginated('users.list', token, 'members')
    users = {
        'by_email': {},
        'by_id': {},
    }
    for user in r:
        if user['is_bot'] or user['name'] == 'slackbot':
            logging.info(f"Skipping bot user: {user['name']}")
            continue
        email = user['profile'].get('email', False)
        if not email:
            logging.warning(f"Skipping user with no email: {user['name']}")
            continue
        email = email.lower()
        userid = user['id']
        username = user['name']
        users['by_email'][email] = {
            'id': userid,
            'name': username,
            'email': email,
        }
        users['by_id'][userid] = users['by_email'][email]

    return users

def slack_channel_members(token, channel, usermap={}):
    r = slack_api_get_paginated('conversations.members', token, 'members',
                                params={'channel': channel})
    members = []

    if usermap:
        def mapped_user(u):
            if u in usermap:
                return usermap[u]['email']
            logging.debug(f"Ignoring channel member not in usermap: {u}")
            return None
    else:
        def mapped_user(u):
            return u

    for member in r:
        member = mapped_user(member)
        if member:
            members.append(member.lower())

    return members

def slack_channel_create(token, name, args):
    slack_log(f"Creating channel: {name}")
    if args.dry_run:
        logging.debug("DRYRUN: Pretending to create channel")
        return f"DRYRUN-{name}"

    r = slack_api_post('groups.create', token, data={'name': name})
    logging.debug(r.text)
    data = r.json()
    try:
        return data['group']['id']
    except KeyError as e:
        error = data.get("error", e)
        logging.exception(f"channel create: {name}: {error}")
        slack_log(f"Unable to create channel: {name}: {error}")
        return (None, error)

def slack_channel_invite_member(token, channel, userid, args):
    channame = LOOKUPS['channel'](channel)
    username = LOOKUPS['user'](userid)
    slack_log(f"Adding user '{username}' to channel '{channame}'")
    if args.dry_run:
        logging.debug("DRYRUN: Not adding user")
        return
    r = slack_api_post('groups.invite', token, data={
        'channel': channel,
        'user': userid,
    })
    logging.debug(r.text)

def slack_channel_invite_new_user(token, channels, email, args):
    channames = LOOKUPS['channel'](channels)

    if args.skip_invites:
        slack_log(f"Skipped inviting new user '{email}' to channels: {channames}")
        return

    slack_log(f"Inviting new user '{email}' to channels: {channames}")
    if args.dry_run:
        logging.debug("DRYRUN: Not sending invite")
        return

    # XXX: This is an unsupported private API and requires legacy Slack tokens
    r = slack_api_post('users.admin.invite', token, data={
        'email': email,
        'channels': channels,
        'restricted': true,
    })
    logging.debug(r.text)

def main():
    parser = argparse.ArgumentParser(
        description='Set up Slack orgs and users based on MC details')
    parser.add_argument('--support', '-s', nargs='+', required=True,
                        help='List of users (emails) to add to each org on creation' )
    parser.add_argument('--dry-run', '-n', action='store_true',
                        help='Do not make any changes in Slack')
    parser.add_argument('--test-mode', '-t', action='store_true',
                        help='Substitute test emails for real user account invites')
    parser.add_argument('--skip-invites', '-I', action='store_true',
                        help='Skip inviting new members')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Print debug messages')
    parser.add_argument('--skip-channels', '-C',
                        help='File listing the set of channels to skip processing')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.skip_channels:
        with open(args.skip_channels) as f:
            for line in f.readlines():
                SKIP_CHANNELS.add(line.strip())
        logging.debug("Skipped channels: {SKIP_CHANNELS}")

    mc_user = os.environ['MC_USER']
    mc_pass = os.environ['MC_PASS']
    mc_token = login(mc_user, mc_pass)

    slack_token = os.environ['SLACK_TOKEN']
    slack_legacy_token = os.environ['SLACK_LEGACY_TOKEN']

    orgs = orglist(mc_token, newer_than=START_FROM)
    users = userlist(mc_token, args, newer_than=START_FROM)
    userorgs = userorglist(mc_token)

    nusers = {}

    # Get a list of MC orgs and the users in each
    for user in users:
        username = user['Name']
        useremail = user['Email'].lower()
        if username not in userorgs:
            if username in SPECIAL_ORG_USERS:
                logging.info(f"user in special orgs: {username}")
            else:
                logging.info(f"user {username} not in role assignment list")
            continue

        for userorg in userorgs[username]:
            orgchan = userorg.lower()
            if orgchan not in nusers:
                nusers[orgchan] = set()
            nusers[orgchan].add(useremail)

    channels = slack_channels(slack_token)
    logging.info(json.dumps(channels, indent=4))
    def channel_lookup(clist):
        return ','.join([ channels['by_id'][x]['name'] for x in clist.split(',') ])
    LOOKUPS['channel'] = channel_lookup

    users = slack_users(slack_token)
    logging.info(json.dumps(users, indent=4))
    def user_lookup(ulist):
        return ','.join([ users['by_id'][x]['name'] for x in ulist.split(',') ])
    LOOKUPS['user'] = user_lookup

    need_invite = {}
    for norg in nusers:
        if norg in SKIP_CHANNELS:
            logging.debug(f"Skipping org: {norg}")
            continue
        channelid = None
        if norg not in channels['by_name']:
            channelid = slack_channel_create(slack_token, norg, args)
            if isinstance(channelid, tuple):
                # Could not create private channel for org
                if channelid[1] == 'name_taken':
                    logging.warning(f"Channel exists: {norg}")
                    SKIP_CHANNELS.add(norg)
                else:
                    logging.warning(f"Unknown error creating channel: {norg}: {channelid}")
                continue
            channels['by_name'][norg] = {
                'id': channelid,
                'name': norg,
                'is_private': True,
                'is_archived': False
            }
            channels['by_id'][channelid] = channels['by_name'][norg]
        else:
            channel = channels['by_name'][norg]
            if channel['is_archived']:
                logging.info(f"Ignoring archived channel: {norg}")
                continue
            channelid = channel['id']

        # Add all necessary users (developer in org as well as MobiledgeX community members)
        members = slack_channel_members(slack_token, channelid, users['by_id'])
        logging.info(f"Channel members: {norg}: {members}")
        reqd_members = set(args.support) | nusers[norg]
        for nuser in reqd_members:
            logging.info(f"Checking if {nuser} is in channel {norg}")
            if nuser not in members:
                if nuser in users['by_email']:
                    # Add existing slack user to org channel
                    logging.info(f"Adding user to org: {nuser}: {norg}")
                    userid = users['by_email'][nuser]['id']
                    slack_channel_invite_member(slack_token, channelid, userid, args)
                else:
                    # Send invite to new developer email
                    logging.info(f"Need to invite new user to org: {nuser}: {norg}")
                    if nuser not in need_invite:
                        need_invite[nuser] = set()
                    need_invite[nuser].add(channelid)

    for nuser in need_invite:
        nuserchannels = ','.join(need_invite[nuser])
        slack_channel_invite_new_user(slack_legacy_token, nuserchannels, nuser, args)

    # Persist skipped channel list
    if args.skip_channels:
        with open(args.skip_channels, "w") as f:
            f.write("\n".join(sorted(SKIP_CHANNELS)) + "\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        slack_log(f"ERROR: {sys.argv[0]}\n```{traceback.format_exc()}```")
