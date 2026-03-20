# Assignment 2, Task 4

## Running

To setup the machines in the network, `Docker Compose` is used. Which file to run depends on your CPU architecture.

1. Open a shell, and run the appropriate command:

    - for x86_64: `docker compose -f x86.compose.yml up`
    - for ARM64: `docker compose -f arm.compose.yml up`

1. Open a `bash` shell on containers: `server-router` (server), `client-10.9.0.5` (client), and `host-192.168.60.5` (host).
1. On the server container, run `cd volumes && python3 tun_server.py`
1. On the client container, run `cd volumes && python3 tun_client.py`
1. On the server container, enter the passphrase: `secret`
1. On the host container, run `ping 192.168.53.99` - you should receive replies!
1. (Optional) Open new `bash` shell containers on the server and client and run `tcpdump -i eth0 -n` in order to watch the traffic.

## Certificate

The key and certificate are generated with OpenSSL using:

```sh
openssl req -x509 -newkey rsa:4096 -keyout volumes/key.pem -out volumes/cert.pem -sha256 -days 365
```

and the PEM pass phrase is "`secret`".
