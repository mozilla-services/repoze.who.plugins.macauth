# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

A repoze.who plugin for MAC Access Authentication:

    http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01

"""

__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


from zope.interface import implements

from webob import Request, Response

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger
from repoze.who.utils import resolveDotted

import tokenlib

from repoze.who.plugins.macauth.noncemanager import NonceManager
from repoze.who.plugins.macauth.utils import (parse_authz_header,
                                              check_mac_signature)


class MACAuthPlugin(object):
    """Plugin to implement MAC Access Auth in repoze.who.

    This class provides an IIdentifier, IChallenger and IAuthenticator
    implementation for repoze.who.  Authentication is based on signed
    requests using the MAC Access Authentication standard with pre-shared
    MAC credentials.

    The class takes the following parameters:

      token_manager:  the tokenlib.TokenManager instance used to validate
                      client MAC credentials.

      token_manager_factory:  a callable selecting the tokenlib.TokenManager
                              instance to use on a per-request basis.

      nonce_timeout:  the timeout after which nonces are removed from
                      the cache; defaults to 60 seconds.

      token_timeout:  the timeout after which all nonce for a token are
                      removed from the cache; defaults to nonce_timeout.

    """

    implements(IIdentifier, IChallenger, IAuthenticator)

    def __init__(self, token_manager=None, token_manager_factory=None,
                 nonce_timeout=None, token_timeout=None):
        # Sanity-check the arguments.
        if token_manager is not None and token_manager_factory is not None:
            msg = "Cannot specify both token_manager and token_manager_factory"
            raise ValueError(msg)
        # Fill in default values for any unspecified arguments.
        # I'm not declaring defaults on the arguments themselves because
        # we would then have to duplicate those defaults into make_plugin.
        if token_manager is None and token_manager_factory is None:
            token_manager = tokenlib.TokenManager()
        if nonce_timeout is None:
            nonce_timeout = 60
        if token_timeout is None:
            try:
                token_timeout = token_manager.timeout
            except AttributeError:
                token_timeout = nonce_timeout
        self.token_manager = token_manager
        self.token_manager_factory = token_manager_factory
        self.nonce_timeout = nonce_timeout
        self.token_timeout = token_timeout
        self.nonce_manager = NonceManager(nonce_timeout, token_timeout)
        assert self.token_manager or self.token_manager_factory

    def identify(self, environ):
        """Extract the authentication info from the request.

        We extract the MAC params from the Authorization header and return
        those directly as the identity.

        Note that this method does *not* validate the MAC signature.
        """
        request = Request(environ)
        params = parse_authz_header(request, None)
        if params is None:
            return None
        if params.get("scheme") != "MAC":
            return None
        # Check that various parameters are as expected.
        token = params.get("id")
        if token is None:
            msg = "missing MAC id"
            return self._respond_unauthorized(request, msg)
        # Check the timestamp and nonce for freshness or reuse.
        try:
            timestamp = int(params["ts"])
        except (KeyError, ValueError):
            msg = "missing or malformed MAC timestamp"
            return self._respond_unauthorized(request, msg)
        nonce = params.get("nonce")
        if nonce is None:
            msg = "missing MAC nonce"
            return self._respond_unauthorized(request, msg)
        if not self.nonce_manager.is_fresh(token, timestamp, nonce):
            msg = "MAC has stale token or nonce"
            return self._respond_unauthorized(request, msg)
        # OK, they seem like sensible MAC paramters.
        return params

    def challenge(self, environ, status, app_headers=(), forget_headers=()):
        """Challenge the user for credentials.

        This simply sends a 401 response using the WWW-Authenticate field
        as constructed by forget().
        """
        resp = Response()
        resp.status = 401
        resp.headers = self.forget(environ, {})
        for headers in (app_headers, forget_headers):
            for name, value in headers:
                resp.headers[name] = value
        resp.content_type = "text/plain"
        resp.body = "Unauthorized"
        return resp

    def authenticate(self, environ, identity):
        """Authenticate the extracted identity.

        The identity must be a set of MAC auth credentials extracted from
        the request.  This method checks the MAC signature, and if valid
        extracts the user metadata from the token.
        """
        request = Request(environ)
        # Check that these are MAC auth credentials.
        # They may not be if we're using multiple auth methods.
        if identity.get("scheme") != "MAC":
            return None
        token = identity["id"]
        # Decode the token and get its associated secret.
        token_manager = self._get_token_manager(request)
        try:
            data = token_manager.parse_token(token)
            secret = token_manager.get_token_secret(token)
        except ValueError:
            msg = "invalid MAC id"
            return self._respond_unauthorized(request, msg)
        # Check the MAC signature.
        if not check_mac_signature(request, secret, identity):
            msg = "invalid MAC signature"
            return self._respond_unauthorized(request, msg)
        # Store the nonce to avoid re-use.
        # We do this *after* successul auth to avoid DOS attacks.
        nonce = identity["nonce"]
        timestamp = int(identity["ts"])
        self.nonce_manager.add_nonce(token, timestamp, nonce)
        # Find something we can use as repoze.who.userid.
        if "repoze.who.userid" not in data:
            for key in ("username", "userid", "uid", "email"):
                if key in data:
                    data["repoze.who.userid"] = data[key]
                    break
            else:
                msg = "token contains no userid"
                return self._respond_unauthorized(request, msg)
        # Update the identity with the data from the token.
        identity.update(data)
        return identity["repoze.who.userid"]

    def remember(self, environ, identity):
        """Remember the user's identity.

        This is a no-op for this plugin; the client is supposed to remember
        its MAC credentials and use them for all requests.
        """
        return []

    def forget(self, environ, identity):
        """Forget the user's identity.

        This simply issues a new WWW-Authenticate challenge, which should
        cause the client to forget any previously-provisioned credentials.
        """
        return [("WWW-Authenticate", "MAC")]

    def _get_token_manager(self, request):
        """Get the TokenManager to use for the given request."""
        token_manager = self.token_manager
        if token_manager is None:
            token_manager = self.token_manager_factory(request)
        return token_manager

    def _respond_unauthorized(self, request, message="Unauthorized"):
        """Generate a "401 Unauthorized" error response."""
        resp = Response()
        resp.status = 401
        resp.headers = self.forget(request.environ, {})
        resp.content_type = "text/plain"
        resp.body = message
        request.environ["repoze.who.application"] = resp
        return None


def make_plugin(**kwds):
    """Make a MACAuthPlugin using values from a .ini config file.

    This is a helper function for loading a MACAuthPlugin via the
    repoze.who .ini config file system.  It converts its arguments from
    strings to the appropriate type then passes them on to the plugin.
    """
    token_manager = _load_from_callable("token_manager", kwds)
    token_manager_factory = kwds.pop("token_manager_factory", None)
    if token_manager_factory is not None:
        token_manager_factory = resolveDotted(token_manager_factory)
    nonce_timeout = kwds.pop("nonce_timeout", None)
    if nonce_timeout is not None:
        nonce_timeout = int(nonce_timeout)
    token_timeout = kwds.pop("token_timeout", None)
    if token_timeout is not None:
        token_timeout = int(token_timeout)
    for unknown_kwd in kwds:
        raise TypeError("unknown keyword argument: %s" % unknown_kwd)
    plugin = MACAuthPlugin(token_manager, token_manager_factory,
                           nonce_timeout, token_timeout)
    return plugin


def _load_from_callable(name, kwds):
    """Load a plugin argument from dotted python name of callable.

    This function is a helper to load and possibly instanciate an argument
    to the plugin.  It grabs the value from the dotted python name found in
    kwds[name].  If this is a callable, it looks for arguments of the form
    kwds[name_*] and calls the object with them.
    """
    # See if we actually have the named object.
    dotted_name = kwds.pop(name, None)
    if dotted_name is None:
        return None
    obj = resolveDotted(dotted_name)
    # Extract any arguments for the callable.
    obj_kwds = {}
    prefix = name + "_"
    for key in kwds.keys():
        if key.startswith(prefix):
            obj_kwds[key[len(prefix):]] = kwds.pop(key)
    # Call it if callable.
    if callable(obj):
        obj = obj(**obj_kwds)
    elif obj_kwds:
        raise ValueError("arguments provided for non-callable %r" % (name,))
    return obj
