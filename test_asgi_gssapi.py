from asgi_gssapi import SPNEGOAuthMiddleware
from async_asgi_testclient import TestClient
import mock
import pytest
import unittest
import base64


async def index(scope, receive, send):
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"text/plain"],
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": ("Hello {}".format(scope["gssapi"].get("principal") or "ANONYMOUS")).encode(),
        }
    )


def quick_error(code: int, content: bytes, content_type: bytes, www_auth_header: bool = False):
    return (
        {
            "type": "http.response.start",
            "status": code,
            "headers": [
                [b"content-type", content_type],
                [b"content-length", str(len(content)).encode()],
                *([[b"www-authenticate", b"negotiate"]] if www_auth_header else []),
            ],
        },
        {
            "type": "http.response.body",
            "body": content,
        },
    )


@mock.patch("asgi_gssapi.SPNEGOAuthMiddleware._gssapi_authenticate")
@pytest.mark.asyncio
async def test_authentication_missing_but_not_required(do_auth):
    """
    Ensure that when a user's auth_required_callback returns False,
    and the request is missing an auth token,
    authentication is not performed.
    """
    false = lambda x: False
    async with TestClient(SPNEGOAuthMiddleware(index, service="http", auth_required_callback=false)) as app:
        r = await app.get("/")
        assert r.status_code == 200
        assert r.content == b"Hello ANONYMOUS"
        assert r.headers.get("WWW-Authenticate") == None

        assert do_auth.mock_calls == []


@mock.patch("gssapi.SecurityContext.initiator_name", "user@EXAMPLE.ORG")
@mock.patch("gssapi.SecurityContext.complete", False)
@mock.patch("gssapi.SecurityContext.step")
@mock.patch("base64.b64decode")
@pytest.mark.asyncio
async def test_authentication_invalid_but_not_required(decode, step):
    """
    Ensure that when a user's auth_required_callback returns False,
    and the request includes an invalid auth token,
    the invalid auth is ignored and the request
    is allowed through to the app.
    """
    decode.return_value = "CTOKEN"
    false = lambda x: False
    async with TestClient(
        SPNEGOAuthMiddleware(
            index,
            service="http",
            # hostname='example.org',
            auth_required_callback=false,
        )
    ) as app:
        r = await app.get("/", headers={"Authorization": "Negotiate CTOKEN"})
        assert r.status_code == 200
        assert r.content == b"Hello ANONYMOUS"
        assert r.headers.get("WWW-Authenticate", None) == None

        assert step.mock_calls != []  # We tried


@mock.patch("gssapi.SecurityContext.initiator_name", "user@EXAMPLE.ORG")
@mock.patch("gssapi.SecurityContext.complete", True)
@mock.patch("gssapi.SecurityContext.step")
@mock.patch("base64.b64decode")
@pytest.mark.asyncio
async def test_authentication_valid_but_not_required(decode, step):
    """
    Ensure that when a users auth_required_callback returns False,
    but the request does include a valid auth token,
    the authenticated user is passed through to the app.
    """
    decode.return_value = "CTOKEN"
    step.return_value = b"STOKEN"
    false = lambda x: False
    async with TestClient(
        SPNEGOAuthMiddleware(
            index,
            service="http",
            # hostname='example.org',
            auth_required_callback=false,
        )
    ) as app:
        r = await app.get("/", headers={"Authorization": "Negotiate CTOKEN"})
        assert r.status_code == 200
        assert r.content == b"Hello user@EXAMPLE.ORG"
        assert r.headers["WWW-Authenticate"] == "Negotiate {}".format(base64.b64encode(b"STOKEN").decode())

        assert step.mock_calls != []  # We tried


@pytest.mark.asyncio
async def test_unauthorized():
    """
    Ensure that when the client does not send an authorization token, they
    receive a 401 Unauthorized response which includes a www-authenticate
    header field which indicates the server supports Negotiate
    authentication.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http")) as app:
        r = await app.get("/")

        assert r.status_code == 401
        assert r.content == b"Unauthorized"
        assert r.headers["www-authenticate"] == "Negotiate"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_unauthorized_when_missing_negotiate():
    """
    Ensure that when the client sends an Authorization header that does
    not start with "Negotiate ", they receive a 401 Unauthorized response
    with a "WWW-Authenticate: Negotiate" header.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http")) as app:
        r = await app.get("/", headers={"Authorization": "foo"})

        assert r.status_code == 401
        print(r.content, type(r.content))
        assert r.content.startswith(b"Unauthorized")
        assert r.headers["www-authenticate"] == "Negotiate"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_unauthorized_custom():
    """
    Ensure that when the client does not send an authorization token, they
    receive a 401 Unauthorized response which includes a www-authenticate
    header field which indicates the server supports Negotiate
    authentication. If configured, they should also receive customized
    content.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http", unauthorized="CUSTOM")) as app:
        r = await app.get("/")

        assert r.status_code == 401
        assert r.content == b"CUSTOM"
        assert r.headers["www-authenticate"] == "Negotiate"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_unauthorized_custom_content_type():
    """
    Ensure that when the client does not send an authorization token, they
    receive a 401 Unauthorized response which includes a www-authenticate
    header field which indicates the server supports Negotiate
    authentication. If configured, they should also receive customized
    content and content type.
    """
    async with TestClient(
        SPNEGOAuthMiddleware(index, service="http", unauthorized=quick_error(401, b"401!", b"text/html", True))
    ) as app:
        r = await app.get("/")

        assert r.status_code == 401
        assert r.content == b"401!"
        assert r.headers["www-authenticate"].lower() == "negotiate"
        assert r.headers["content-type"] == "text/html"
        assert r.headers["content-length"] == str(len(r.content))


@mock.patch("gssapi.SecurityContext.initiator_name", "user@EXAMPLE.ORG")
@mock.patch("gssapi.SecurityContext.complete", True)
@mock.patch("gssapi.SecurityContext.step")
@mock.patch("base64.b64decode")
@pytest.mark.asyncio
async def test_authorized(decode, step):  # self):#, clean, name, response, step, init):
    """
    Ensure that when the client sends a correct authorization token,
    they receive a 200 OK response and the user principal is extracted and
    passed on to the routed method.
    """

    decode.return_value = "CTOKEN"
    step.return_value = b"STOKEN"

    async with TestClient(SPNEGOAuthMiddleware(index, service="http")) as app:
        r = await app.get("/", headers={"Authorization": "Negotiate CTOKEN"})

        assert r.status_code == 200
        assert r.content == b"Hello user@EXAMPLE.ORG"
        assert r.headers["WWW-Authenticate"] == "Negotiate {}".format(base64.b64encode(b"STOKEN").decode())

        assert step.mock_calls != []
        
        
@mock.patch("gssapi.SecurityContext.initiator_name", "user@EXAMPLE.ORG")
@mock.patch("gssapi.SecurityContext.complete", True)
@mock.patch("gssapi.SecurityContext.step")
@mock.patch("base64.b64decode")
@pytest.mark.asyncio
async def test_authorized_any_hostname(decode, step):  # self):#, clean, name, response, step, init):
    """
    Ensure that the server can find matching hostname entry from the keytab.
    We set hostname="" in this test to achive this.
    """

    decode.return_value = "CTOKEN"
    step.return_value = b"STOKEN"

    async with TestClient(SPNEGOAuthMiddleware(index, service="http", hostname="")) as app:
        r = await app.get("/", headers={"Authorization": "Negotiate CTOKEN"})

        assert r.status_code == 200
        assert r.content == b"Hello user@EXAMPLE.ORG"
        assert r.headers["WWW-Authenticate"] == "Negotiate {}".format(base64.b64encode(b"STOKEN").decode())

        assert step.mock_calls != []



@pytest.mark.asyncio
async def test_forbidden():
    """
    Ensure that when the client sends an incorrect authorization token,
    they receive a 403 Forbidden response.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http")) as app:
        r = await app.get("/", headers={"Authorization": "Negotiate CTOKEN"})

        assert r.status_code == 403
        assert r.content, b"Forbidden"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_forbidden_custom():
    """
    Ensure that when the client sends an incorrect authorization token,
    they receive a 403 Forbidden response. If configured, they should
    receive customized content.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http", forbidden="CUSTOM")) as app:
        r = await app.get("/", headers={"Authorization": "Negotiate CTOKEN"})

        assert r.status_code == 403
        assert r.content == b"CUSTOM"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_forbidden_custom_content_type():
    """
    Ensure that when the client sends an incorrect authorization token,
    they receive a 403 Forbidden response. If configured, they should
    receive customized content and content-type.
    """
    async with TestClient(
        SPNEGOAuthMiddleware(index, service="http", forbidden=quick_error(403, b"CUSTOM", b"text/html"))
    ) as app:
        r = await app.get("/", headers={"Authorization": "Negotiate CTOKEN"})

        assert r.status_code == 403
        assert r.content == b"CUSTOM"
        assert r.headers["content-type"] == "text/html"
        assert r.headers["content-length"] == str(len(r.content))
