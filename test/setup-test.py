#!/usr/bin/env python

import os
from stormpath.client import Client

APP_NAME = 'nginxtest'
GROUP_NAME = 'nginxtest'
PRIMARY_ACC_NAME = 'nginx'
SECONDARY_ACC_NAME = 'nginx2'
ACC_PASSWORD = 'Nginx4eva!'

NGINX_CONF_IN = 'conf/nginx.conf.in'
NGINX_CONF = 'conf/nginx.conf'

APIKEY_PROPERTIES_IN = 'conf/apikey.properties.in'
APIKEY_PROPERTIES = 'conf/apikey.properties'


def ensure_test_app(c):
    apps = list(c.applications.search({'name': APP_NAME}))
    if len(apps) == 1:
        return apps[0]

    print "Creating new test application:", APP_NAME
    return c.applications.create({
        'name': APP_NAME,
        'description': 'Nginx Test application',
        'status': 'enabled'
    }, create_directory=True)

def ensure_test_group(app):
    groups = list(app.groups.search({'name': GROUP_NAME}))
    if len(groups) == 1:
        return groups[0]

    print "Creating new test group:", GROUP_NAME
    return app.groups.create({
        'name': GROUP_NAME,
        'description': 'Nginx Test group',
        'status': 'enabled'
    })

def ensure_test_account(app, name):
    accs = list(app.accounts.search({'username': name}))
    if len(accs) == 1:
        return accs[0]

    print "Creating new test account:", name
    return app.accounts.create({
        'username': name,
        'email': name + '@example.com',
        'given_name': name,
        'surname': name,
        'password': ACC_PASSWORD
    })

def ensure_account_in_group(c, group, acc):
    accs = list(group.accounts.search({'username': acc.username}))
    if len(accs) == 1:
        return

    print "Adding test account to group"
    c.group_memberships.create({
        'account': acc,
        'group': group
    })

def render_nginx_conf(app, group):
    tpl = open(NGINX_CONF_IN).read()
    conf = tpl % {
        'app_href': app.href,
        'group_href': group.href
    }
    with open(NGINX_CONF, 'w') as fp:
        fp.write(conf)

def render_apikey_properties():
    tpl = open(APIKEY_PROPERTIES_IN).read()
    prop = tpl % os.environ
    with open(APIKEY_PROPERTIES, 'w') as fp:
        fp.write(prop)

# if id/secret are not in environment, this will terminate the setup script
c = Client()

app = ensure_test_app(c)
group = ensure_test_group(app)
primary = ensure_test_account(app, PRIMARY_ACC_NAME)
secondary = ensure_test_account(app, SECONDARY_ACC_NAME)
ensure_account_in_group(c, group, primary)

render_nginx_conf(app, group)
render_apikey_properties()
