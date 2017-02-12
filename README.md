# Wake On Lan Server

Based on the work of (qybl)[https://github.com/qybl] - (repository)[https://github.com/qybl/wol-server]

## Attention!

There is no HTTPS support currently planed. So you need to run it behind a reverse proxy and add some security credentials (Basic Auth). 

## Current feature

* Central configuration file
  * Define webprefix via `WebPrefix`, very useful when you run this service in a subdirectory
  * Custom template usage via `TemplateDir`
  * Scheduler configuration `Scheduler = "1m"` or `Scheduler = "1h30m"` ...
  * Workstation support `LINK`, `NAME` for a better usage on the template 

## Examples

### Caddy

Change the value of the `WebPrefix` configuration attribute to `/wol/`

Here the caddy config entries

```
basicauth muster MaxMuster {
  /wol
}

redir /wol /wol/
proxy /wol http://127.0.0.1:8080
```

### Nginx

### Apache