# Introduction

**http-basic-auth** is designed to run as a sidecar container that will secure a service with basic authentication. Because of the way it works it reduces latency and resources required to secure a service. It is not meant to fully replace nginx ingress or other ingress controllers but to be used in conjunction with them.

## Supported Hashing Algorithms

- bcrypt
- Apache md5

# Code Guides

- https://github.com/uber-go/guide
- https://google.github.io/styleguide/go/

# Docker

https://hub.docker.com/r/cutetarantula/http-basic-auth
