# Introduction

**http-basic-auth** is designed to run as a sidecar container that will secure a service with basic authentication. Because of the way it works it reduces latency and resources required to secure a service.

# Code Guides

- https://github.com/uber-go/guide
- https://google.github.io/styleguide/go/

# Generate a random string

```
openssl rand -hex 32
```

# Generate a random password

```
openssl rand -base64 32
```

# Generate a random password with special characters

```
openssl rand -base64 32 | tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?='
```

# Generate a random password with special characters and no quotes

```
openssl rand -base64 32 | tr -dc a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=
```

# Htpasswd

https://httpd.apache.org/docs/2.4/misc/password_encryptions.html

```
htpasswd -nbB {user} {password}
```
