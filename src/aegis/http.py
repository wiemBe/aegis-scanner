import httpx


async def bounded_body(response: httpx.Response, limit: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            raise ValueError("RESPONSE_SIZE_LIMIT")
    return bytes(body)
