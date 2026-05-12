# Attacking and defending networks

## Your Task(s)

The assignment has *four* tasks, covering both constructive and destructive aspect of networks: (1) the first deals with implementing an encrypted covert channel; (2) the second with implementing a TCP throttling/DoS tool; (3) the third with implementing a session hijacking attack against a TCP connection; and (4) the fourth with implementing a small VPN tunneling program.

### Task 1: Encrypted covert channel

For this part, you will need to have some familiarity with the IP protocol to write low-level networking code using a library. Suggestions are the `libnet/libpcap` library in the C programming language or the equivalent `socket` package in Python.

We assume the following scenario: a whistleblower inside a network needs to transmit sensitive information to the outside, but without being detected by a draconian firewall. The firewall is configured to not allow much traffic to pass, but the system administrator has allowed some types of packets to go through because they can be used for debugging purposes. Our whistleblower has then decided to send non-standard ICMP packets containing encrypted data, in hope they can claim software error and plausibly deny the transmission in case they are detected.

The objective of this task is to implement an one-way encrypted covert channel using the [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) (Internet Control Message Protocol) protocol.
Communication is one-way to follow the typical use case of covert channels for _exfiltration_ of sensitive data.
ICMP is an error-reporting protocol that network devices use to inform of error messages to the source IP address when network problems prevent an IP packet to be delivered.
The most familiar contact we have with the ICMP protocol is the `ping` tool using the `Echo Request` and `Echo Reply` messages. While these packets are typically small, it is not well-known that ICMP packets can carry much larger pieces of data.

You will implement client/server programs to exchange encrypted covert channel through the network. For this, use ICMP messages with type `47` (among the reserved numbers). The client program should receive a destination IP address from the command-line to transmit messages and wait for input from the keyboard at the client-side. The server program should listen to the network for such messages and print them in the console as they arrive. For encryption, you are free to use a preshared symmetric key to protect the transmitted payload. Choose algorithms and modes of operation wisely.

![Screenshot of a possible solution](icmp-covert-channel.png)

### Task 2: Throttling TCP connections

For this part, you will need to have some familiarity with the TCP protocol to write low-level networking code using a library. Suggestions again are the `libnet/libpcap` library in the C programming language or the equivalent `Scapy` package in Python.

The objective of this task is to slow down and interrupt existing TCP connections by forcing retransmission of packets. An illustrative example of such an approach is the `tcpnice` program in the `dsniff` package which reduces windows advertised to artificially decrease bandwidth. We will adopt two different approaches: [sending 3 duplicate ACK packets](https://datatracker.ietf.org/doc/html/rfc2581) to simulate packet loss and force retransmission; and sending a TCP reset packet to drop the connection altogether.

You will implement a tool that receives a source and destination IP addresses to listen for TCP connections and what approach for throttling should be used. The tool should be executed on a third node with access to the traffic. Whenever such a packet is captured, RST or 3 duplicate ACK packets should be sent back to the origin and/or destination (depending on the approach).
For the experimental setup, you can try using virtual machines, or leveraging the VM used for practical exercises as a malicious node to interfere with connections between the host machine and another device.
Collect experimental evidence of the malicious behavior through Wireshark, and screenshots of the time taken to transmit a file using a file transfer (FTP or SSH) to show that it is indeed slower or interrupted when under attack.

**Note**: The experimental part in this task can be difficult to assemble. We suggest having the destination as an Internet host, to guarantee some latency; and the source and attacker to be in the same local network, with the attacker being the router that receives all traffic from the source (as in the network security lab exercise). This allows the attacker to get their ACKs accepted before the legitimate ones arrive. You may face countermeasures along the way that negate the attack, but in that case make sure to *document* your negative results.

### Task 3: TCP Session hijacking

This part overlaps with the previous task, in the sense that the experimental setup is similar and requires the same tools, so doing the two tasks together might be beneficial for a group.

The objective of this task is to hijack an ongoing TCP connection to perform traffic manipulation attacks. One way for an attacker to leverage a privileged network position is monitoring TCP sequence numbers and introduce new traffic that is accepted by one of the connection endpoints.
You will implement a tool that receives a source and destination IP addresses to listen for TCP connections carrying HTTP traffic. The tool should be executed on a third node with access to the traffic. Whenever a HTTP packet is captured, the tool should inspect the payload in search of an HTTP session cookie, steal it and perform an HTTP method on behalf of the source.
For the experimental setup, you can try using virtual machines, or leveraging the VM used for practical exercises as a malicious node to interfere with connections between the host machine and the HTTP server.
Collect experimental evidence of the malicious behavior through Wireshark, showing that the forged request was indeed send to the HTTP server.

**Note**: The experimental part in this task can be difficult to assemble. We suggest having the destination as an Internet host running an HTTP server, with the source and attacker in the same local network. The attacker should be the router that receives all traffic from the source (as in the network security lab exercise). You can use the simple-website application made available in the network security lab exercises as a simple web server.
For your convenience, the web server has been included here, in the subfolder "simple-website".
Run the web server with the command:

```sh
flask --app main.py run
```

Observe that when you log in, the server gives you a cookie.

### Task 4: Mini TLS-based VPN tunneling

For this part, less familiarity with low-level networking programming details is necessary. In particular, this [SEED lab](https://seedsecuritylabs.org/Labs_20.04/Networking/VPN_Tunnel/) has starting code for reference.
The objective of this task is to implement a small VPN tunneling program that will allow hosts to communicate over an encrypted connection. Follow the tutorial from the SEED lab above up to Task 5 (while ignoring the instructions to write a report) until you have a functional implementation able to transmit unencrypted traffic.

Your task is then to finalize the implementation by replacing the UDP socket with a TLS/SSL connection. A simple certificate structure must be deployed for mutually authenticating the client and server, where a common self-signed certificate will be available on both endpoints.
Collect evidence of the correct behavior through Wireshark and screenshots showing that traffic is correctly forwarded.
You are not supposed to write your own TLS/SSL implementation and a library should be used for that.
