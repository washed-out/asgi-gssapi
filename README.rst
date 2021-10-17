ASGI-GSSAPI
==============

ASGI-GSSAPI is `ASGI`_ Middleware which implements `Kerberos`_ authentication.
It makes it easy to add Kerberos authentication to any ASGI application.

Its only dependency is `python-gssapi`_ and it's been tested up to version 1.7.2

Unfortunately, as is the case with most things kerberos, it requires a kerberos
environment as well as a keytab. Setting that up is outside the scope of this
document.

The official copy of this documentation is available at `Read the Docs`_.

Installation
------------

Install the extension with pip:

    $ pip install ASGI-GSSAPI

How to Use
----------

To integrate ``ASGI-GSSAPI`` into your application you'll need to generate
your keytab and set the environment variable ``KRB5_KTNAME`` in your shell to
the location of the keytab file.

After that, it should be as easy as passing your application to the
``SPNEGOAuthMiddleware`` constructor.  All requests destined for the
application will first be authenticated by the middleware, and the authenticated
users principal will be available as the ``principal`` key in the ASGI
scope dictionary, under ``gssapi`` key.

For example::

    import uvicorn
    from asgi_gssapi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        await send({
            'type': 'http.response.start',
            'status': 200,
            'headers': [
                [b'content-type', b'text/plain'],
            ],
        })
        await send({
            'type': 'http.response.body',
            'body': b'Hello, {}'.format(scope['gssapi']['principal']),
        })

    app = SPNEGOAuthMiddleware(example)

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)


``ASGI-GSSAPI`` assumes that every request should be authenticated. If this is
not the case, you can override it by passing in a callback named
``auth_required_callback`` to the
``SPNEGOAuthMiddleware`` constructor. This callback will be called for every
request and passed the ASGI scope dictionary::

    import uvicorn
    from asgi_gssapi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        ... # same as above

    def authenticate(scope):
        return scope['path'].startswith('/protected')

    app = SPNEGOAuthMiddleware(example,
                               auth_required_callback=authenticate)

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)


By default, when ``ASGI-GSSAPI`` responds with a ``401`` to indicate that
authentication is required, it generates a very simple page with a
``Content-Type`` of ``text/plain`` that includes the string ``Unauthorized``.

Similarly, when it responds with a ``403`` indicating that authentication has
failed, it generates another simple page with a ``Content-Type`` of
``text/plain`` that includes the string ``Forbidden``.

These can be customized::

    import uvicorn
    from asgi_gssapi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        ... # same as above

    app = SPNEGOAuthMiddleware(example,
                               unauthorized='Authentication Required',
                               forbidden='Authentication Failed')

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)

You can also change the ``Content-Types`` by passing in full ASGI event
tuples::

    import uvicorn
    from asgi_gssapi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        ... # same as above

    forbidden=({
        'type': 'http.response.start',
        'status': 403,
        'headers': [
            [b'content-type', b'text/html'],
        ],
    }, {
        'type': 'http.response.body',
        'body': b'<html><body><h1>GO AWAY</h1></body></html>'
    })

    unauthorized=({
        'type': 'http.response.start',
        'status': 401,
        'headers': [
            [b'content-type', b'text/html'],
            [b'www-authenticate', b'negotiate'],
        ],
    }, {
        'type': 'http.response.body',
        'body': b'<html><body><h1>LOGIN FIRST</h1></body></html>'
    })

    app = SPNEGOAuthMiddleware(example,
                               unauthorized=unauthorized,
                               forbidden=forbidden)

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)

Hopefully, you are not using raw ASGI, and your framework of choice provides
a saner alternatives to full event definitions (like Starlette's Response class).


``ASGI-GSSAPI`` will authenticate the request using auto-resolved hostname.
You can change it, by providing the ``hostname`` argument to the constructor,
or defer to any hostname, present in keytab file, by providing an empty 
string ``hostname`` argument to the constructor::

    import uvicorn
    from asgi_gssapi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        ... # same as above

    app = SPNEGOAuthMiddleware(example, hostname='example.com')

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)


``ASGI-GSSAPI`` provides support for delegation. You do not need to
configure anything server-side, and it's up to the client to delegate the credentials.
When it does so, you'll receive a ``gssapi.Credentials`` object in ASGI scope dictionary,
under ``delegate_creds`` key::

    async def example(scope, receive, send):
        creds = scope['gssapi']['delegate_creds']

Such creds can be exported to a token cache file (using the ``.export()`` method), 
e.g. ``/tmp/krb5cc_0``, or passed directly to any other GSSAPI-powered python code, 
such as `requests-gssapi`_!


How it works
------------

When an application which uses the middleware is accessed by a client, it will
check to see if the request includes authentication credentials in an
``Authorization`` header. If there are no such credentials, the application will
respond immediately with a ``401 Unauthorized`` response which includes a
``WWW-Authenticate`` header field with a value of ``Negotiate`` indicating to
the client that they are currently unauthorized, but that they can authenticate
using Negotiate authentication.

If credentials are presented in the ``Authorization`` header, the credentials
will be validated, the principal of the authenticating user will be extracted
and added to the ASGI scope using the key ``principal`` in the ``gssapi`` dictionary,
and the application will be called to serve the request. Send event will be hijacked
to append ``WWW-Authenticate`` header which identifies the server to
the client.  This allows ``ASGI-GSSAPI`` to support mutual authentication.


Full Example
------------

To see a simple example, you can download the code `from github
<http://github.com/washed-out/asgi-gssapi>`_. It is in the example directory.

Changes
-------

0.1.0 (2021-10-16)
``````````````````

-     initial implementation


API References
--------------

The full API reference:


.. automodule:: asgi_gssapi
   :members:

.. _ASGI: http://asgi.readthedocs.org/en/latest/
.. _Kerberos: http://wikipedia.org/wiki/Kerberos_(protocol)
.. _python-gssapi: https://pypi.org/project/gssapi
.. _Read the Docs: https://asgi-gssapi.readthedocs.org/
.. _requests-gssapi: https://github.com/pythongssapi/requests-gssapi

History
=======
Although this plugin shares no code with `WSGI-Kerberos
<https://github.com/deshaw/wsgi-kerberos>`_ ,
whole repository layout, including the README file you're reading now,
was shamelessly stolen from it. Thus, I'm keeping contributors and license intact.
