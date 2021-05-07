Building Scylla with the frozen toolchain `dbuild` is as easy as:

```bash
$ git submodule update --init --force --recursive
$ ./tools/toolchain/dbuild ./configure.py
$ ./tools/toolchain/dbuild ninja build/release/scylla
```

Run scylla with RestAuthenticator

```bash
$ ./tools/toolchain/dbuild ./build/release/scylla --workdir tmp --smp 1 --developer-mode 1 --logger-log-level rest_authenticator=debug --authenticator com.criteo.scylladb.auth.RestAuthenticator --rest-authenticator-endpoint-host localhost --rest-authenticator-endpoint-port 8000 --rest-authenticator-endpoint-cafile-path ./tools/rest_authenticator_server/ssl/ca.crt
```

Run FastAPI rest server

```bash
$ ./tools/rest_authenticator_server/rest_server.sh
```

Run Test client

```bash
$ ./tools/rest_authenticator_server/scylla_client.sh
```