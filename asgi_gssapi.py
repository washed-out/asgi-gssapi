import base64
import logging
import socket
from typing import Optional, Callable, Union, List

import gssapi

__version__ = '0.1.1'

logger = logging.getLogger(__name__)


class SPNEGOAuthMiddleware:
    def __init__(
        self,
        app,
        service: str = "HTTP",
        hostname: Optional[str] = None,
        service_principal: Optional[str] = None,
        auth_required_callback: Optional[Callable] = None,
        gssapi_mech: gssapi.MechType = gssapi.MechType.kerberos,
        unauthorized: Optional[Union[str, List[dict]]] = None,
        forbidden: Optional[Union[str, List[dict]]] = None,
    ) -> None:
        """
        :param app: ASGI Application.
        :param service: Service name (defaults to "HTTP"). Note: those are case-sensitive.
        :param hostname: Service host (defaults to `socket.gethostname()`).
        :param service_principal: Service principal (defaults to "{service}@{hostname}").
        :param auth_required_callback: Optional callback with (scope: dict)->bool signature.
        :param gssapi_mech: GSSAPI Auth mechanism, defaults to kerberos.
        :param unauthorized: Override 'unauthrozied' response. Can be a list of ASGI events or a string.
                            Note: if you provide ASGI events here, your HTTP headers **MUST** include
                            (b"www-authenticate": b"Negotiate").
        :param forbidden: Override 'forbidden' response. Can be a list of ASGI events or a string.
        """
        self._app = app

        if service_principal is not None:
            self.service_principal = service_principal
        else:
            self.service_principal = "{}@{}".format(service, hostname if hostname is not None else socket.gethostname())

        self._auth_required_callback = auth_required_callback or (lambda x: True)
        self._unauthorized_events = unauthorized
        self._forbidden_events = forbidden

        # Prepare re-usable GSSAPI objects.
        self._service_name = gssapi.Name(self.service_principal, gssapi.NameType.hostbased_service)
        self._service_cname = self._service_name.canonicalize(gssapi_mech)
        self._service_creds = gssapi.Credentials(name=self._service_cname, usage="accept")

    def _error_response(self, status_code: int, headers: dict = None, message: Union[str, bytes] = ""):
        if not headers:
            headers = {}
        if not isinstance(message, bytes):
            message = message.encode("utf-8")
        length = len(message)
        return [
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-length", str(length).encode("ascii")),
                    (b"content-type", b"text/plain"),
                    *[(k, v) for k, v in headers.items()],
                ],
            },
            {"type": "http.response.body", "body": message},
        ]

    def _unauthorized(self, message: str = ""):
        if self._unauthorized_events:
            if not isinstance(self._unauthorized_events, (str, bytes)):
                return self._unauthorized_events
            else:
                message = self._unauthorized_events
        return self._error_response(401, {b"www-authenticate": b"Negotiate"}, message or "Unauthorized")

    def _forbidden(self, message: str = ""):
        if self._forbidden_events:
            if not isinstance(self._forbidden_events, (str, bytes)):
                return self._forbidden_events
            else:
                message = self._forbidden_events
        return self._error_response(403, None, message or "Forbidden")

    async def _send_error(self, send, error, message: str = ""):
        for event in error(message):
            await send(event)

    def _gssapi_authenticate(self, ctx: dict, token: str) -> bool:
        """
        Invokes GSSAPI SecurityContext and runs auth steps.

        :param ctx: a dict to store state.
        :param token: base64-encoded input token.

        Returns True if authentication was complete,
        Returns False if authentication must continue,
        Raises an exception on authentication failure.
        """
        in_token = base64.b64decode(token)

        sec_ctx = gssapi.SecurityContext(creds=self._service_creds)

        out_token = sec_ctx.step(in_token)
        if out_token:
            ctx["token"] = base64.b64encode(out_token).decode("ascii")

        if sec_ctx.initiator_name:
            ctx["principal"] = str(sec_ctx.initiator_name)

        if sec_ctx.delegated_creds:
            ctx["delegate_creds"] = sec_ctx.delegated_creds.export()

        return sec_ctx.complete

    async def __call__(self, scope, receive, send) -> None:
        """ ASGI entry-point. """
        scope["gssapi"] = ctx = {
            "token": None,
            "principal": None,
            "delegate_creds": None,
        }

        if scope["type"] != "http":
            return await self._app(scope, receive, send)

        auth_required = self._auth_required_callback(scope)
        auth_attempted = False
        auth_complete = False
        www_auth_header = []

        headers = {k: v for k, v in scope["headers"] if k == b"authorization"}
        header = headers.get(b"authorization", b"").decode("utf-8")
        if header:
            if header.lower().startswith("negotiate "):
                token = header[len("negotiate "):]
                auth_attempted = True
                try:
                    auth_complete = self._gssapi_authenticate(ctx, token)
                except Exception:
                    logger.exception("GSSAPI Auth failure.")

        async def wrapped_send(event):
            if event["type"] == "http.response.start":
                event["headers"] = [*event["headers"], *www_auth_header]
            await send(event)

        # Select response
        if auth_complete:
            if ctx.get("token", None):  # Finish mutual auth
                www_auth_header = [
                    (
                        b"www-authenticate",
                        "Negotiate {}".format(ctx["token"]).encode("utf-8"),
                    )
                ]
            return await self._app(scope, receive, wrapped_send)
        elif auth_required:
            if auth_attempted:
                return await self._send_error(send, self._forbidden)
            else:
                return await self._send_error(send, self._unauthorized)
        else:
            return await self._app(scope, receive, send)
