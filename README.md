# deteco

Simple auth server using JWT and public key cryptography.
deteco can use for API Authorization with nginx auth_request module.

## Usage

```
Usage:
  deteco [OPTIONS]

Application Options:
  -v, --version        Show version
      --listen=        Address to listen to. (default: 127.0.0.1:8080)
      --conf=          path to services toml file
      --dry-run        check services toml file only
      --jwt-freshness= time in seconds to allow generated jwt tokens (default: 1h)

Help Options:
  -h, --help           Show this help message
 ```

## sample toml file & client

See sample.toml and cli/jwtgen/main.go

## sample nginx.conf

```
location / {
    auth_request /auth;
    auth_request_set $deteco_user upstream_http_x_deteco_user
    proxy_set_header X-Remote-User $deteco_user;
}

location = /auth {
    internal;
    proxy_pass http://127.0.0.1;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;

}
```
