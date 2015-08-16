"""
Unit Tests for Auth Systems
"""

import unittest
import models

from django.db import IntegrityError, transaction

from django.test.client import Client
from django.test import TestCase

from django.core import mail

from auth_systems import AUTH_SYSTEMS

class UserModelTests(unittest.TestCase):

    def setUp(self):
        pass

    def test_unique_users(self):
        """
        there should not be two users with the same user_type and user_id
        """
        for auth_system, auth_system_module in AUTH_SYSTEMS.iteritems():
            models.User.objects.create(user_type = auth_system, user_id = 'foobar', info={'name':'Foo Bar'})
            
            def double_insert():
                models.User.objects.create(user_type = auth_system, user_id = 'foobar', info={'name': 'Foo2 Bar'})
                
            self.assertRaises(IntegrityError, double_insert)
            transaction.rollback()

    def test_create_or_update(self):
        """
        shouldn't create two users, and should reset the password
        """
        for auth_system, auth_system_module in AUTH_SYSTEMS.iteritems():
            u = models.User.update_or_create(user_type = auth_system, user_id = 'foobar_cou', info={'name':'Foo Bar'})

            def double_update_or_create():
                new_name = 'Foo2 Bar'
                u2 = models.User.update_or_create(user_type = auth_system, user_id = 'foobar_cou', info={'name': new_name})

                self.assertEquals(u.id, u2.id)
                self.assertEquals(u2.info['name'], new_name)


    def test_status_update(self):
        """
        check that a user set up with status update ability reports it as such,
        and otherwise does not report it
        """
        for auth_system, auth_system_module in AUTH_SYSTEMS.iteritems():
            u = models.User.update_or_create(user_type = auth_system, user_id = 'foobar_status_update', info={'name':'Foo Bar Status Update'})

            if hasattr(auth_system_module, 'send_message'):
                self.assertNotEquals(u.update_status_template, None)
            else:
                self.assertEquals(u.update_status_template, None)

    def test_eligibility(self):
        """
        test that users are reported as eligible for something

        FIXME: also test constraints on eligibility
        """
        for auth_system, auth_system_module in AUTH_SYSTEMS.iteritems():
            u = models.User.update_or_create(user_type = auth_system, user_id = 'foobar_status_update', info={'name':'Foo Bar Status Update'})

            self.assertTrue(u.is_eligible_for({'auth_system': auth_system}))

    def test_eq(self):
        for auth_system, auth_system_module in AUTH_SYSTEMS.iteritems():
            u = models.User.update_or_create(user_type = auth_system, user_id = 'foobar_eq', info={'name':'Foo Bar Status Update'})
            u2 = models.User.update_or_create(user_type = auth_system, user_id = 'foobar_eq', info={'name':'Foo Bar Status Update'})

            self.assertEquals(u, u2)


import views
import auth_systems.password as password_views
from django.core.urlresolvers import reverse

# FIXME: login CSRF should make these tests more complicated
# and should be tested for

class UserBlackboxTests(TestCase):

    def setUp(self):
        # create a bogus user
        self.test_user = models.User.objects.create(user_type='password',user_id='foobar-test@adida.net',name="Foobar User", info={'password':'foobaz'})

    def test_password_login(self):
        ## we can't test this anymore until it's election specific
        pass

        # get to the login page
        # login_page_response = self.client.get(reverse(views.start, kwargs={'system_name':'password'}), follow=True)

        # log in and follow all redirects
        # response = self.client.post(reverse(password_views.password_login_view), {'username' : 'foobar_user', 'password': 'foobaz'}, follow=True)

        # self.assertContains(response, "logged in as")
        # self.assertContains(response, "Foobar User")

    def test_logout(self):
        response = self.client.post(reverse(views.logout), follow=True)
        
        self.assertContains(response, "not logged in")
        self.assertNotContains(response, "Foobar User")

    def test_email(self):
        """using the test email backend"""
        self.test_user.send_message("testing subject", "testing body")

        self.assertEquals(len(mail.outbox), 1)
        self.assertEquals(mail.outbox[0].subject, "testing subject")
        self.assertEquals(mail.outbox[0].to[0], "\"Foobar User\" <foobar-test@adida.net>")


import auth_systems.ldapauth as ldap_views


class LDAPAuthTests(TestCase):
    """
    These tests relies on OnLine LDAP Test Server, provided by forum Systems:
    http://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
    """

    def setUp(self):
        """ set up necessary django-auth-ldap settings """
        self.password = 'password'
        self.username = 'euclid'

    def test_backend_login(self):
        """ test if authenticates using the backend """
        from helios_auth.auth_systems.ldapbackend import backend
        auth = backend.CustomLDAPBackend()
        user = auth.authenticate(self.username, self.password)
        self.assertEqual(user.username, 'euclid')

    def test_ldap_view_login(self):
        """ test if authenticates using the auth system login view """
        resp = self.client.post(reverse(ldap_views.ldap_login_view), {
            'username' : self.username,
            'password': self.password
            }, follow=True)
        self.assertEqual(resp.status_code, 200)

    def test_logout(self):
        """ test if logs out using the auth system logout view """
        response = self.client.post(reverse(views.logout), follow=True)
        self.assertContains(response, "not logged in")
        self.assertNotContains(response, "euclid")

