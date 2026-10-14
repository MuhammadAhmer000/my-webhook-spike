from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/test/")
async def test_func(request: Request):
    body = await request.body()

    headers = dict(request.headers)
    if "authorization" in headers:
        headers["authorization"] = "***"

    print("webhook body:", body)
    print("webhook headers:", headers)

    return {"status": "received"}
