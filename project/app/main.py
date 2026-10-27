import base64
import hmac
import secrets
import time
from typing import Optional

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI()

CLIENT_ID = "aka-webhook-7f3c9a2e41b8d605"
CLIENT_SECRET = "Xk9mQ2vR8tLp4WnZ7yBc3HdJ6sFa1UeO5gTi0VoNxMq"
TOKEN_TTL_SECONDS = 3600

tokens: dict[str, float] = {}  # access_token -> expires_at (lost on restart)

bearer_scheme = HTTPBearer()


# Token URL (client_credentials grant)
@app.post("/oauth/token")
async def token(
    grant_type: str = Form(...),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None),
):
    # Credentials can arrive via HTTP Basic header or in the form body
    if authorization and authorization.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(authorization[6:]).decode()
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            return JSONResponse({"error": "invalid_client"}, status_code=401)

    if grant_type != "client_credentials":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    if not (
        client_id
        and client_secret
        and hmac.compare_digest(client_id, CLIENT_ID)
        and hmac.compare_digest(client_secret, CLIENT_SECRET)
    ):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    access_token = secrets.token_urlsafe(32)
    tokens[access_token] = time.time() + TOKEN_TTL_SECONDS
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
    }


def require_token(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    expires_at = tokens.get(creds.credentials)
    if not expires_at or expires_at < time.time():
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Your webhook
@app.post("/test/", dependencies=[Depends(require_token)])
async def test_func(request: Request):
    body = await request.body()

    headers = dict(request.headers)
    if "authorization" in headers:
        headers["authorization"] = "***"

    print("webhook body:", body)
    print("webhook headers:", headers)

    return {"status": "received"}
