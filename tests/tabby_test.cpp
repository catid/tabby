#include <iostream>
using namespace std;

#include "Clock.hpp"
using namespace cat;

#include "tabby.h"

static Clock m_clock;

int main() {
	cout << "Tabby Tester" << endl;

	m_clock.OnInitialize();

	tabby_server s;
	tabby_client c;

	char sp[64];

	assert(tabby_init() == 0);

	tabby_server_gen(&s, 0, 0);

	tabby_get_public_key(&s, sp);

	// Signature test:

	char *message = "My message";
	int message_bytes = (int)strlen(message);
	char signature[96];

	assert(0 == tabby_sign(&s, message, message_bytes, signature));

	assert(0 == tabby_verify(message, message_bytes, public_key, signature));

	chat *message1 = "Mz message";

	assert(0 != tabby_verify(message1, message_bytes, public_key, signature));

	// Handshake test:

	for (int ii = 0; ii < 10000; ++ii) {
		char client_request[96];

		tabby_client_gen(&c, 0, 0, client_request);

		char server_response[128];
		char server_secret_key[32];

		assert(0 == tabby_server_process(&s, client_request, server_response, server_secret_key));

		char client_secret_key[32];

		assert(0 == tabby_client_process(&c, public_key, server_response, client_secret_key));

		assert(0 == memcmp(server_secret_key, client_secret_key, 32));
	}

	cout << "Tests succeeded!" << endl;

	m_clock.OnFinalize();

	return 0;
}

