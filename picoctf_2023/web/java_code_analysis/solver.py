import jwt

private_key = "1234"

payload = {"role":"Admin","iss":"bookshelf","exp":1687316533,"iat":1686711733,"userId":2,"email":"admin"}

token: str = jwt.encode(  # type: ignore
    payload=payload,
    key=private_key,
    algorithm="HS256"
)

print(token)