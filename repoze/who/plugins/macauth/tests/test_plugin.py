# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest2
import urllib2
import time

from webob import Request
from webob.exc import HTTPNotFound
from webtest import TestApp

from zope.interface.verify import verifyClass

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger
from repoze.who.middleware import PluggableAuthenticationMiddleware

from tokenlib import TokenManager

from repoze.who.plugins.macauth import MACAuthPlugin, make_plugin
from repoze.who.plugins.macauth.utils import sign_request, parse_authz_header


def make_environ(**kwds):
    environ = {}
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = "http"
    environ["SERVER_NAME"] = "localhost"
    environ["SERVER_PORT"] = "80"
    environ["REQUEST_METHOD"] = "GET"
    environ["SCRIPT_NAME"] = ""
    environ["PATH_INFO"] = "/"
    environ.update(kwds)
    return environ


def dotted_name(name):
    """Return full dotted name of something in this module."""
    return "repoze.who.plugins.macauth.tests.test_plugin:" + name


def stub_application(environ, start_response):
    """Simple WSGI app that requires authentication.

    This is a simple testing app that returns the userid if the environment
    contains a repoze.who identity, and denies access if it does not. URLs
    containing the string "forbidden" will get a 403 response, while other
    URLs will get a 401 response.

    The special path "/public" can be viewed without authentication.
    """
    headers = [("Content-Type", "text/plain")]
    if environ["PATH_INFO"] == "/public":
        body = "public"
    else:
        if "repoze.who.identity" not in environ:
            if "forbidden" in environ["PATH_INFO"]:
                start_response("403 Forbidden", headers)
            else:
                start_response("401 Unauthorized", headers)
            return ["Unauthorized"]
        body = environ["repoze.who.identity"]["repoze.who.userid"]
        body = body.encode("utf8")
    start_response("200 OK", headers)
    return [body]


def stub_request_classifier(environ):
    """Testing request classifier; all requests are are just 'web' requests."""
    return "web"


def stub_challenge_decider(environ, status, headers):
    """Testing challenge decider; 401 and 403 responses get a challenge."""
    return status.split(None, 1)[0] in ("401", "403")


class StubTokenManager(TokenManager):
    """TokenManager subclass to test correct class loading."""


class TestMACAuthPlugin(unittest2.TestCase):
    """Testcases for the main MACAuthPlugin class."""

    def setUp(self):
        self.plugin = MACAuthPlugin(token_manager=StubTokenManager())
        application = PluggableAuthenticationMiddleware(stub_application,
                                 [["mac", self.plugin]],
                                 [["mac", self.plugin]],
                                 [["mac", self.plugin]],
                                 [],
                                 stub_request_classifier,
                                 stub_challenge_decider)
        self.app = TestApp(application)

    def _get_credentials(self, **data):
        token = self.plugin.token_manager.make_token(data)
        secret = self.plugin.token_manager.get_token_secret(token)
        return {"token": token, "secret": secret}

    def test_implements(self):
        verifyClass(IIdentifier, MACAuthPlugin)
        verifyClass(IAuthenticator, MACAuthPlugin)
        verifyClass(IChallenger, MACAuthPlugin)

    def test_make_plugin_can_explicitly_set_all_properties(self):
        plugin = make_plugin(
            token_manager=dotted_name("StubTokenManager"),
            nonce_timeout=17,
            token_timeout=42)
        self.assertTrue(isinstance(plugin.token_manager, StubTokenManager))
        self.assertEquals(plugin.nonce_timeout, 17)
        self.assertEquals(plugin.token_timeout, 42)

    def test_make_plugin_passes_on_args_to_token_manager(self):
        plugin = make_plugin(
            token_manager=dotted_name("StubTokenManager"),
            token_manager_secret="BAZINGA")
        self.assertTrue(isinstance(plugin.token_manager, StubTokenManager))
        self.assertEquals(plugin.token_manager.secret, "BAZINGA")
        self.assertRaises(TypeError, make_plugin, 
            token_manager=dotted_name("StubTokenManager"),
            token_manager_invalid_arg="WHAWHAWHAWHA")

    def test_make_plugin_errors_out_on_unexpected_keyword_args(self):
        self.assertRaises(TypeError, make_plugin,
                                     unexpected="spanish-inquisition")

    def test_make_plugin_errors_out_on_args_to_a_non_callable(self):
        self.assertRaises(ValueError, make_plugin,
                                      token_manager=dotted_name("unittest2"),
                                      token_manager_arg="invalidarg")

    def test_make_plugin_produces_sensible_defaults(self):
        plugin = make_plugin()
        self.assertTrue(isinstance(plugin.token_manager, TokenManager))
        self.assertEquals(plugin.nonce_timeout, 60)
        self.assertEquals(plugin.token_timeout, plugin.token_manager.timeout)

    def test_token_timeout_defaults_to_nonce_timeout(self):
        token_manager = TokenManager()
        del token_manager.timeout
        plugin = MACAuthPlugin(token_manager=token_manager, nonce_timeout=17)
        self.assertEquals(plugin.nonce_timeout, plugin.token_timeout)

    def test_remember_does_nothing(self):
        self.assertEquals(self.plugin.remember(make_environ(), {}), [])

    def test_forget_gives_a_challenge_header(self):
        headers = self.plugin.forget(make_environ(), {})
        self.assertEquals(len(headers), 1)
        self.assertEquals(headers[0][0], "WWW-Authenticate")
        self.assertTrue(headers[0][1] == "MAC")

    def test_unauthenticated_requests_get_a_challenge(self):
        # Requests to most URLs generate a 401, which is passed through
        # with the appropriate challenge.
        r = self.app.get("/", status=401)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith("MAC"))
        # Requests to URLs with "forbidden" generate a 403 in the downstream
        # app, which should be converted into a 401 by the plugin.
        r = self.app.get("/forbidden", status=401)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith("MAC"))

    def test_authenticated_request_works(self):
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/")
        sign_request(req, **creds)
        r = self.app.request(req)
        self.assertEquals(r.body, "test@moz.com")

    def test_authentication_fails_when_token_has_no_userid(self):
        creds = self._get_credentials(hello="world")
        req = Request.blank("/")
        sign_request(req, **creds)
        r = self.app.request(req, status=401)

    def test_authentication_with_non_mac_scheme_fails(self):
        req = Request.blank("/")
        req.authorization = "OpenID hello=world"
        self.app.request(req, status=401)

    def test_authentication_without_token_id_fails(self):
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/")
        sign_request(req, **creds)
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("id", "idd")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_timestamp_fails(self):
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/")
        sign_request(req, **creds)
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("ts", "typostamp")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_nonce_fails(self):
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/")
        sign_request(req, **creds)
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("nonce", "typonce")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_with_expired_timestamp_fails(self):
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/")
        # Do an initial request so that the server can
        # calculate and cache our clock skew.
        ts = str(int(time.time()))
        req.authorization = ("MAC", {"ts": ts})
        sign_request(req, **creds)
        self.app.request(req, status=200)
        # Now do one with a really old timestamp.
        ts = str(int(time.time() - 1000))
        req.authorization = ("MAC", {"ts": ts})
        sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_far_future_timestamp_fails(self):
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/")
        # Do an initial request so that the server can
        # calculate and cache our clock skew.
        ts = str(int(time.time()))
        req.authorization = ("MAC", {"ts": ts})
        sign_request(req, **creds)
        self.app.request(req, status=200)
        # Now do one with a far future timestamp.
        ts = str(int(time.time() + 1000))
        req.authorization = ("MAC", {"ts": ts})
        sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_reused_nonce_fails(self):
        creds = self._get_credentials(username="test@moz.com")
        # First request with that nonce should succeed.
        req = Request.blank("/")
        req.authorization = ("MAC", {"nonce": "PEPPER"})
        sign_request(req, **creds)
        r = self.app.request(req)
        self.assertEquals(r.body, "test@moz.com")
        # Second request with that nonce should fail.
        req = Request.blank("/")
        req.authorization = ("MAC", {"nonce": "PEPPER"})
        sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_busted_token_fails(self):
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/")
        sign_request(req, **creds)
        token = parse_authz_header(req)["id"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(token, "XXX" + token)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_with_busted_signature_fails(self):
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/")
        sign_request(req, **creds)
        signature = parse_authz_header(req)["mac"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_access_to_public_urls(self):
        # Request with no credentials is allowed access.
        req = Request.blank("/public")
        resp = self.app.request(req)
        self.assertEquals(resp.body, "public")
        # Request with valid credentials is allowed access.
        creds = self._get_credentials(username="test@moz.com")
        req = Request.blank("/public")
        sign_request(req, **creds)
        resp = self.app.request(req)
        self.assertEquals(resp.body, "public")
        # Request with invalid credentials gets a 401.
        req = Request.blank("/public")
        sign_request(req, **creds)
        signature = parse_authz_header(req)["mac"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        resp = self.app.request(req, status=401)

    def test_authenticate_only_accepts_mac_credentials(self):
        # Yes, this is a rather pointless test that boosts line coverage...
        self.assertEquals(self.plugin.authenticate(make_environ(), {}), None)
