#include "EnclaveDemo_t.h"

#include "sgx_trts.h"
#include <sgx_exit>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print(buf);
}

void enclave_entry()
{
	// do something

	exit(1);
	exit

	// do something else
}