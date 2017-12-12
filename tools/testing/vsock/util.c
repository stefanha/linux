// SPDX-License-Identifier: GPL-2.0
/*
 * vsock test utilities
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Author: Stefan Hajnoczi <stefanha@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "timeout.h"
#include "util.h"

/* Install signal handlers */
void init_signals(void)
{
	struct sigaction act = {
		.sa_handler = sigalrm,
	};

	sigaction(SIGALRM, &act, NULL);
	signal(SIGPIPE, SIG_IGN);
}

/* Parse a CID in string representation */
unsigned int parse_cid(const char *str)
{
	char *endptr = NULL;
	unsigned long int n;

	errno = 0;
	n = strtoul(str, &endptr, 10);
	if (errno || *endptr != '\0') {
		fprintf(stderr, "malformed CID \"%s\"\n", str);
		exit(EXIT_FAILURE);
	}
	return n;
}

/* Run test cases.  The program terminates if a failure occurs. */
void run_tests(const struct test_case *test_cases,
	       const struct test_opts *opts)
{
	int i;

	for (i = 0; test_cases[i].name; i++) {
		void (*run)(const struct test_opts *opts);

		printf("%s...", test_cases[i].name);
		fflush(stdout);

		if (opts->mode == TEST_MODE_CLIENT)
			run = test_cases[i].run_client;
		else
			run = test_cases[i].run_server;

		if (run)
			run(opts);

		printf("ok\n");
	}
}
