Android SSL Vulnerability Detection Tools
=========================================

Introduction
------------

A set of tools for detecting if Android applications are vulnerable to common
SSL certificate validation security vulnerabilities which allow
man-in-the-middle attackers to intercept and modify encrypted network traffic.

One tool uses static analysis to try to detect potentially vulnerable SSL
certificate validation code. The other tool actually tries to carry out a
man-in-the-middle attack to actively exploit certificate validation
vulnerabilities.

I developed these tools as part of my [Part II project][project] at Cambridge.
Thanks to [Dr Alastair Beresford][arb] for supervising the project.

Note: I have done some rewriting of the repository with `git filter-branch` to
tidy it up. Some of the commit messages may therefore not make much sense.

Building
--------

[Gradle][gradle] is used as the build system. Java 8 ([Oracle Java][oracle] or
[OpenJDK][openjdk]) on Linux is required.

Run `gradle` to build the tools and run the unit tests.

There's also a separate set of integration tests for the man-in-the-middle tool
which can be run by typing `./mitm-test/run`. Warning: the integration tests
will modify your iptables configuration and might not restore it properly
(especially if they fail).

Static Analysis
---------------

The static analysis tool assumes the Android SDK is installed in
`/opt/android`.

Run `./analysis/static-analyser /path/to/the.apk` to analyse an application. If
you get SPARK-related exceptions from Soot, you can pass the `--paddle` option
to use Paddle (an alternative to SPARK) which might fix it.

Man-in-the-Middle
-----------------

The `./mitm/mitm` script runs the man-in-the-middle tool. `./mitm/mitm-gui`
runs it with a GUI, which is useful if many connections are being intercepted
at the same time as it makes figuring out which data was sent by which
connection easier.

Before running the man-in-the-middle tool for the first time you must generate
a trusted and untrusted certificate authority, and install the trust
certificate on your phone. Run `cd mitm; ./make-ca; ./install-ca` to do so.
Your phone must be rooted to install the trusted certificate in this manner.
The Android SDK's `tools` and `platform-tools` directories must also be in your
`$PATH` environment variable.

Several required options must be specified on the command line (even with the
GUI mode):

### Interception Mode

This is set to indicate how you are passing the intercepted traffic to the
MITM program with iptables.

 * `--nat`: if you are using the iptables REDIRECT target.
 * `--tproxy`: if you are using the iptables [transparent proxying][tproxy]
   support.
 * `--fixed <address>:<port>`: if you aren't actually intercepting traffic at
   all. Allows you to proxy traffic to a fixed address and port for testing
   purposes.

You'll probably want to use the MITM tool in conjunction with some software
such as [hostapd][hostapd], which turns your computer into a WiFi hotspot, or
dsniff's [arpspoof][dsniff] command, which uses ARP spoofing to intercept
traffic on an existing WiFi hotspot or network.

For both the `--nat` and `--tproxy` modes you'll need to enable IP forwarding:

    sysctl -w net.ipv4.ip_forward=1

(This turns your machine into a router, so you might want to be careful with
your configuration if you are connecting to the Internet through a network you
don't control or you might annoy your local sysadmin if you make a mistake!)

For IPv6, the equivalent sysctl is:

    sysctl -w net.ipv6.conf.all.forwarding=1

#### Example iptables commands for `--nat` mode

Assuming hostapd is running on `wlan0`:

    iptables -t nat -A PREROUTING -i wlan0 -p tcp -j REDIRECT --to-port 8443

If you want to intercept local connections from your own machine, then you will
need to run the MITM tool as a different user (`nobody` in this example) to
prevent it intercepting the connections it opens itself:

    iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner nobody -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 8443

I haven't had any luck in getting ARP spoofing working together with the NAT
mode, therefore the tool also supports transparent proxying which I have managed
to get working with ARP spoofing.

Change `iptables` to `ip6tables` if you want to use IPv6 instead. Note that
IPv6 NAT requires Linux 3.7 or above (and a recent enough version of the
user-space iptables tools too).

#### Example iptables commands for `--tproxy` mode

Assuming 192.168.0.1 is the gateway and 192.168.0.100 is the computer whose
traffic you wish to intercept, first start up two `arpspoof` instances:

    arpspoof -t 192.168.0.1 192.168.0.100
    arpspoof -t 192.168.0.100 192.168.0.1

Disable reverse path filtering (again, be careful, lest you annoy a sysadmin):

    sysctl -w net.ipv4.conf.all.rp_filter=0

Add a separate routing table for 'marked' packets which delivers them locally:

    ip rule add fwmark 1 lookup 100
    ip route add local default dev lo table 100

Add iptables rules which transparently proxy any incoming connections passing
through the machine:

    iptables -t mangle -N DIVERT
    iptables -t mangle -A DIVERT -j MARK --set-mark 1
    iptables -t mangle -A DIVERT -j ACCEPT
    iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
    iptables -t mangle -A PREROUTING -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8443

The transparent proxying configuration is tricky to set up, the Squid website
has [some tips][squid] which are applicable. If possible, stick with `--nat`
mode.

As with `--nat` mode, you can replace `iptables` with `ip6tables` if you want
to use IPv6. You'll also need to pass the `-6` flag to the `ip` command.
Changing the `rp_filter` sysctl is not required for IPv6.

### Certificate Hostname Mode

This is set to determine the value of the Common Name and Subject Alternative
Name fields in the generated certificates.

 * `--matching-hostname`: use the same CN and SAN as the real certificate.
 * `--unmatching-hostname`: use a CN which does not match the one in the real
   certificate.

### Certificate Trust Mode

This is set to determine if the generate certificates are signed with the
trusted certificate authority (whose certificate is installed on the phone) or
the untrusted certificate authority (whose certificate is not installed on the
phone).

 * `--trusted`
 * `--untrusted`

Types of Vulnerability
----------------------

For each combination of hostname and trust mode, if the client accepts a
connection which the MITM tool has intercepted then the following vulnerability
is present:

| Hostname Mode | Trust Mode | Vulnerability                              |
| ------------- | ---------- | ------------------------------------------ |
| matching      | trusted    | Client does not use certificate pinning.   |
| matching      | untrusted  | Client uses a permissive X509TrustManager. |
| unmatching    | trusted    | Client uses a permissive HostnameVerifier. |
| unmatching    | untrusted  | Client performs no certificate validation. |

Dependencies
------------

The following Java libraries are used by the tools:

* [Soot][soot]
* [Paddle][paddle] (optional)
* [Jedd][jedd] (optional)
* [JOpt Simple][jopt-simple]
* [Bouncy Castle][bc]
* [Java Native Access][jna]

License
-------

The tools are available under Version 2.0 of the [Apache License][apache]. The
full terms of the Apache License are available in the `LICENSE` file.

[project]: http://www.cl.cam.ac.uk/teaching/projects/
[gradle]: http://www.gradle.org/
[hostapd]: http://hostap.epitest.fi/hostapd/
[oracle]: http://www.oracle.com/technetwork/java/javase/downloads/index.html
[openjdk]: http://openjdk.java.net/
[apache]: https://www.apache.org/licenses/LICENSE-2.0.html
[tproxy]: https://www.kernel.org/doc/Documentation/networking/tproxy.txt
[soot]: http://www.sable.mcgill.ca/soot/
[paddle]: http://www.sable.mcgill.ca/paddle/
[jedd]: http://www.sable.mcgill.ca/jedd/
[jopt-simple]: https://pholser.github.io/jopt-simple/
[bc]: https://www.bouncycastle.org/java.html
[jna]: https://github.com/twall/jna
[squid]: http://wiki.squid-cache.org/Features/Tproxy4
[arb]: http://www.cl.cam.ac.uk/~arb33/
[dsniff]: http://www.monkey.org/~dugsong/dsniff/
