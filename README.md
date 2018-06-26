## libevent tls server example

understanding openssl with libevent

### deps:
* libevent
* openssl

### usage:

default running port on 9090

```
$ make

$ EVTLS_CA=your cert path with ca chain \
EVTLS_KEY=yout key path \
./tlsev
```
