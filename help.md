
Getting a redis key value pair.
```bash
docker ps
docker exec -it [redis id] redis-cli --scan --pattern '*'
docker exec -it [redis id] redis-cli GET [key]
```

Connecting to psql.
```bash
docker exec -it [docker container name | postgres] psql -U postgres
```

Writing an auth server in go:
https://www.sohamkamani.com/golang/2019-01-01-jwt-authentication/

Generating RS256 keys with bash:
```bash
openssl genrsa -out jwtRS256.rsa 4096
openssl rsa -in jwtRS256.rsa -pubout > jwtRS256.rsa.pub
```