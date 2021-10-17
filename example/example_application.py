#!/usr/bin/env python
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
