# jwt-qrcode

## run

```bash
$ go run main.go
`````

## generate jwt

```bash
$ curl -X POST \
       -H "Content-Type: application/json" \
       -H "Content-Type: application/json" \
       -d '{"item_code":"ITEM123", "price":100, "amount":2}' \
        http://localhost:8080/generate_qr > output.png
```

## verify jwt

```bash
$ curl -s \
       -X POST \
       -H "Authorization: Bearer [Your_JWT_Token_Here]" \
        http://localhost:8080/verify_token |jq .
{
  "message": "Successfully authenticated!"
}
```

