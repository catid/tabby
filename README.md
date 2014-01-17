# Tabby
#### Strong, Fast, and Portable Cryptographic Signatures, Handshakes, and Password Authentication

The Tabby key agreement protocol is designed for the situation where a client
is attempting to connect to a server it has not connected to before.  After the
protocol completes, a 256-bit secret key is shared by both parties.  The server
has also been authenticated by the client.  Perfect forward secrecy is provided,
in that after the server changes its ephemeral key, all previous connections
cannot be decrypted if the server's long-term secret key is leaked somehow.
It is a one-round protocol that executes twice as fast as crypto_box EC-DHE
approaches on the server side.  Tabby has a "128-bit" security level.

Additionally, Tabby implements a new augmented password authentication protocol
that runs roughly 30x faster than SRP6a on the server while following all current
best practices in password protection.

Tabby also provides signatures based on the efficient EdDSA approach.

Tabby uses the [Snowshoe](https://github.com/catid/snowshoe/) elliptic curve
math library, and it also uses the [Cymric](https://github.com/catid/cymric/)
secure random number generator library.  Please refer to those repositories for
more information about the underlying math and software implementation.

Tabby does not do data encryption.  To use the 256-bit key provided by Tabby to
encrypt messages for transmission over TCP/UDP sockets,
see the [Calico project](https://github.com/catid/calico/).


##### Building: Quick Setup

The `tabby-mobile` directory contains an easy-to-import set to C code that also
builds properly for mobile devices.  In a pinch you can use this code for
desktops, though it will tend to run about 1 microsecond slower.


##### Building: Mac/Linux

To build the static library, install command-line Xcode tools and simply run the make script:

~~~
make test
~~~

On Mac, this produces `libtabby.a` with optimizations, and it also runs the unit tester.

The build process needs some more work on Linux.  To build it, the snowshoe and cymric libraries
need to be rebuilt first (`make ecmultest; make release`, and `make test; make release` respectively).
And then the symbols for each static library should be unpacked (`ar -x libsnowshoe.a`, `ar -x libcymric.a`, `ar -x libtabby.a`) and repacked (`ar rcs libtabby.a *.o`).

##### Building: Windows

You can link to the 64-bit `bin/libtabby.lib` static library and include
`include/tabby.h` to use Tabby from an e.g. Visual Studio project.
There is an example test project under `msvc2010/` that demonstrates using
Tabby from a Visual Studio project.

The following instructions allow you to reproduce the `bin/libtabby.lib` binary:

Download LLVM from [http://llvm.org/builds/](http://llvm.org/builds/) for Windows to C:\LLVM\.
Download Mingw64 from [http://mingw-w64.sourceforge.net/](http://mingw-w64.sourceforge.net/) for Windows 64-bit to C:\mingw64\.

~~~
copy Makefile.Mingw64 Makefile
c:\mingw64\bin\mingw32-make.exe release
~~~

This produces `bin/libtabby.lib`, which can be linked to an MSVC2010 build.


#### Usage

The [header file](https://github.com/catid/tabby/blob/master/include/tabby.h)
provides an API reference.


##### Example Usage: EC-DHE (EC-DH with Forward Secrecy)

Link to the Tabby static library `/bin/libtabby.a` (-ltabby)
and include the `./include/tabby.h` header.

Verify binary API compatibility on startup:

~~~
	if (tabby_init()) {
		throw "Buildtime failure: Wrong tabby static library";
	}
~~~

The server side will need to set up a `tabby_server` object, either by generating
a new key pair, or by loading an existing one.  Most commonly the server will be
loading an existing long-term key pair, since the clients that connect will need
to know it ahead of time.

To generate a new server long-term private/public key pair:

~~~
	tabby_server s;
	char public_key[64];
	char private_key[64];

	// Generate a Tabby server object
	if (tabby_server_gen(&s, 0, 0)) {
		return false;
	}

	// Read the public key
	if (tabby_server_get_public_key(&s, public_key)) {
		return false;
	}

	// Read the private key
	if (tabby_server_save_secret(&s, private_key)) {
		return false;
	}

	// Write private key/public key to disk here

	// Always erase sensitive information when done
	tabby_erase(private_key, sizeof(private_key));
	tabby_erase(&s, sizeof(s));
~~~

To reload a server private key:

~~~
	char private_key[64];
	tabby_server s;

	// Read private key from disk here

	if (tabby_server_load_secret(&s, 0, 0, private_key)) {
		return false;
	}
~~~

Now the server is ready to handle connections.  To start a connection,
the client side will need to create a `tabby_client` object.

To create a Tabby client object:

~~~
	tabby_client c;
	char client_request[96];

	if (tabby_client_gen(&c, 0, 0, client_request)) {
		return false;
	}
~~~

This generates the 96 byte `client_request` message that is sent to the server.

To process the client's request on the server:

~~~
	char server_response[128];
	char server_secret_key[32];

	if (tabby_server_handshake(&s, client_request, server_response, server_secret_key)) {
		// Ignore client request message
		return false;
	}
~~~

The server will either reject the request if the function returns non-zero, or the server
will respond with a 128 byte `server_response` message to the client and fill the
`server_secret_key` with the session key shared with the client.

If the client never receives the server's response, it may retry.  So a UDP server should
be able to retransmit the response rather than creating a second connection.

When the client eventually receives the response, it can validate the response and also
calculate the same secret key:

~~~
	char client_secret_key[32];

	if (tabby_client_handshake(&c, public_key, server_response, client_secret_key)) {
		// Ignore server response message
		return false;
	}
~~~

The client will either reject the response if the function returns non-zero, or the client
will have established a 32 byte secret key shared with the server.  This can be used to
set up authenticated encryption with e.g. [Calico](https://github.com/catid/calico).

Periodically the server should rekey.  After each rekeying, all connections made with the
previous key will be protected in the event that the server is compromised and its long-
term secret key is divulged.

To rekey the server, the rekey function should be run from a separate thread periodically:

~~~
	int my_thread_func(tabby_server *s) {
		// Every 30 seconds or until terminated,
		while (my_wait(30000)) {
			// Rekey the server
			tabby_server_rekey(s, 0, 0); // safe to ignore failures
		}
	}
~~~


##### Example Usage: Signatures

The signature API is described in full in the [header file](https://github.com/catid/tabby/blob/master/include/tabby.h).

And there is also an example of signatures in the [unit tester](https://github.com/catid/tabby/blob/master/tests/tabby_test.cpp).


##### Example Usage: Password Authentication

This example builds on the EC-DHE example.  All of the password messages should be
encrypted with the key derived by the EC-DHE handshake.

Using the same client "c" and server "s" objects from the EC-DHE example:

~~~
	const char *username = "catid";
	const char *realm = "AWESOME APP";
	const char *password = "password1";
~~~

##### Generate server database entry for user:

This can be done by a special tool or as part of the client application.
The result should be stored in the server database so that the server can verify logins.

~~~
	char password_verifier[72];

	if (tabby_password(&c,
					   username, strlen(username),
					   realm, strlen(realm),
					   password, strlen(password),
					   password_verifier)) {
		return false;
	}

	// Store "password_verifier" in database.
~~~

##### Generate challenge message and secret:

Now a client wants to log-in.

After the client has sent its "username" to the server, the server will present a password
challenge to the client.  This also generates a temporary secret that is used to validate
the client's response to the challenge.  This is a fast operation (~0.065 ms on a laptop).

~~~
	char challenge_secret[224], challenge[72];

	if (tabby_password_challenge(&s,
								 password_verifier,
								 challenge_secret, challenge)) {
		return false;
	}

	// Transmit "challenge" to client.
	// Store "challenge secret" to validate the client response.
~~~

##### Generate client proof and server verifier:

The client receives the challenge from the server and responds with a password proof.
This operation securely hashes the password and takes roughly 90 milliseconds on a laptop,
so on a mobile device this may take longer.

~~~
	char server_verifier[32], client_proof[96];

	if (tabby_password_client_proof(&c,
									username, strlen(username),
									realm, strlen(realm),
									password, strlen(password),
									challenge, // Server challenge
									public_key, // Server's public key
									server_verifier, client_proof)) {
		return false;
	}

	// Transmit "client proof" to server.
	// Store "server verifier" to validate the server response.
~~~

##### Generate server proof:

The server receives the client proof from the client and responds with a server proof,
after verifying the client proof.  This is a fast operation (~0.065 ms on a laptop).

~~~
	char server_proof[32];

	if (tabby_password_server_proof(&s,
									client_proof, challenge_secret,
									server_proof)) {
		return false;
	}

	// Transmit "server proof" to client.
~~~

##### Verify server proof:

The client receives the server proof from the server and verifies it is expected.
If the server proof is invalid, the client should disconnect immediately.
Before the server proof is received, the client should ignore any other message types.

~~~
	if (tabby_password_check_server(server_proof, server_verifier)) {
		return false;
	}

	// Client and server now have proof both sides know the password!
~~~


#### Benchmarks

The following measurements show normal walltime with Turbo Boost on, and median
cycles with Turbo Boost off.  The measurements were taken over 10,000 samples
for each configuration, unless otherwise noted.

##### libsnowshoe.a on iMac-Tron (2.4 GHz Core i5-4258U Haswell, June 2013):

RDTSC instruction runs at 2.4 GHz so no correction factor is needed.

Key generation:

+ Successfully created a new server key in `375232` cycles, `140` usec (one sample)
+ Generated a client key in `209076` cycles, `67` usec (one sample)
+ Periodic server rekey in `170616` cycles, `60` usec (one sample)

Signatures:

+ Tabby sign: `57136` median cycles, `20.0255` avg usec
+ Tabby verify signature: `134232` median cycles, `46.9197` avg usec

One-round EC-DH with forward secrecy:

+ Tabby server handshake: `117424` median cycles, `40.6725` avg usec (`24586` connections/second)
+ Tabby client handshake: `169804` median cycles, `58.7846` avg usec

These Haswell results are directly comparable to the latest SUPERCOP benchmarks
in some cases, indicating Tabby takes:

+ 72.3% the time of Curve25519 to compute the server's shared secret for EC-DHE.
+ Just 6% slower than kumfp127g, the current speed leader on the charts for EC-DH.

+ 83% the time of Ed25519 to sign a message.
+ 261x faster than ronald3072 (RSA at the same security level) to sign a message.

+ 65% the time of Ed25519 to verify a message signature.
+ Just 8% slower than ronald3072 (RSA at the same security level) to verify signatures.

SUPERCOP submissions for Tabby are in the works.

##### libsnowshoe.a on iMac (2.7 GHz Core i5-2500S Sandy Bridge, June 2011):

RDTSC instruction runs at 2.69393 GHz so no correction factor is needed.

Key generation:

+ Successfully created a new server key in `401064` cycles, `163` usec (one sample)
+ Generated a client key in `183808` cycles, `65` usec (one sample)
+ Periodic server rekey in `187060` cycles, `52` usec (one sample)

Signatures:

+ Tabby sign: `67700` median cycles, `18.5844` avg usec
+ Tabby verify signature: `154192` median cycles, `42.4291` avg usec

One-round EC-DH with forward secrecy:

+ Tabby server handshake: `137436` median cycles, `37.7628` avg usec (`26481` connections/second)
+ Tabby client handshake: `196036` median cycles, `53.7555` avg usec

##### libsnowshoe.a on Macbook Air (1.7 GHz Core i5-2557M Sandy Bridge, July 2011):

These preliminary benchmarks have TurboBoost turned on, so the cycle counts are inaccurate.

Two-round augmented zero-knowledge password authentication:

+ Client generated server verifier for password database in 162367068 cycles, 95511 usec (one sample)
+ Server password challenge generated in 104678 cycles, 61 usec (one sample)
+ Client proof of password generated in 165639241 cycles, 97436 usec (one sample)
+ Server proof of password generated in 110015 cycles, 65 usec (one sample)
+ Client checked server password proof in 340 cycles, 0 usec (one sample)

For comparison, DragonSRP based on the OpenSSL library takes *2 milliseconds* to
run the server verification operation, while offering lower security levels than
the "128 bits" provided by Tabby.


##### Performance Discussion

Each of these operations takes roughly 2.5 usec (<5% overhead) longer than the
Snowshoe math routines they are based on.  Where applicable, these operations
do full input validation, use good random number sources, run in constant time,
and clean up the stack to avoid leaking sensitive information.

In general these results are the best for any public domain library at this time.


#### Security Arguments for the EC-DHE protocol

Please refer to the [companion document for EC-DHE](./ECDHE.md).


#### Security Arguments for the Password Authentication protocol

Please refer to the [companion document for Password Authentication](./PASSWORD.md).


#### Credits

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

