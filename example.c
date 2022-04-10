#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <stdio.h>

#define DEPRECATE_TEST 0

#if DEPRECATE_TEST

static int __prepare_method(void) {
	return 1;
}

static int __free_method(void) {
	return 1;
}

static int __hook_evp_pkey(EVP_PKEY *evp_pkey) {
	return 1;
}

#else

static RSA_METHOD *__example_rsa_method;
static int __example_rsa_index;

static int __example_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
	const RSA_METHOD *rsa_method = NULL;
	int ret = -1;

	if ((rsa_method = RSA_get_method(rsa)) == NULL) {
                goto cleanup;
        }

	/*
	 * Do it.
	 */
	printf("ENCRYPT\n");
	memset(to, 0, flen);
	ret = 1;

cleanup:

	return ret;
}

static int __example_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
	const RSA_METHOD *rsa_method = NULL;
	int ret = -1;

	if ((rsa_method = RSA_get_method(rsa)) == NULL) {
                goto cleanup;
        }

	/*
	 * Do it.
	 */
	printf("DECRYPT\n");
	memset(to, 0, flen);
	ret = 1;

cleanup:

	return ret;
}


static int __prepare_method(void) {
	int ret = 0;

	if ((__example_rsa_method = RSA_meth_dup(RSA_get_default_method())) == NULL) {
		goto cleanup;
	}

	if (!RSA_meth_set1_name(__example_rsa_method, "example")) {
		goto cleanup;
	}

	if (!RSA_meth_set_priv_dec(__example_rsa_method, __example_rsa_priv_dec)) {
		goto cleanup;
	}

	if (!RSA_meth_set_priv_enc(__example_rsa_method, __example_rsa_priv_enc)) {
		goto cleanup;
	}

	if ((__example_rsa_index = RSA_get_ex_new_index(0, "example", NULL, NULL, NULL)) == -1) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

static int __free_method(void) {
	RSA_meth_free(__example_rsa_method);
}

static int __hook_evp_pkey(EVP_PKEY *evp_pkey) {

	RSA *rsa = NULL;
	int ret = 0;

	/*
	 * Hook private key methods
	 */

	if (EVP_PKEY_id(evp_pkey) != EVP_PKEY_RSA) {
		goto cleanup;
	}

	if ((rsa = EVP_PKEY_get1_RSA(evp_pkey)) == NULL) {
		goto cleanup;
	}

	if (!RSA_set_method(rsa, __example_rsa_method)) {
		goto cleanup;
	}

	if (!RSA_set_ex_data(rsa, __example_rsa_index, "mystate")) {
		goto cleanup;
	}

	if (EVP_PKEY_set1_RSA(evp_pkey, rsa) != 1) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	RSA_free(rsa);

	return ret;
}
#endif

const static char *pem = (
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFMDCCBBigAwIBAgISA6sbShb1HQ3TpSVvhSPOS4JJMA0GCSqGSIb3DQEBCwUA\n"
	"MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\n"
	"EwJSMzAeFw0yMjAzMTAxNzQ4MDdaFw0yMjA2MDgxNzQ4MDZaMBoxGDAWBgNVBAMT\n"
	"D210YS5vcGVuc3NsLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
	"AMZvA0BbvdyVc+06j5e5k6dUr8gqL0KZw0w4xJ0QD6jD/o+czNEMz13YDxuZ5utL\n"
	"YGq8uohlK8l2DWqvDfGfm1T4VYQhD2z0Ky0JDTsxDIb5i6kKA+o2j2VPAivfMkBp\n"
	"f47rLITa4vqZ8/aro3E0ZVWfbpOOGASteM/g9mLEpRLJQA2/o4uu9xLCsyJkLG8F\n"
	"8eTCHUJ8388ZO/3fv8LnN1+/WwciSYcZcZNN44OsrgLNoLh6dzSY+oNZyVGdqxUy\n"
	"ZSO2dURx4/28w26RLzXFnGOZinupE6KoVhCHHM0Wqx7YkfudymzwBCPP3+X4Hkab\n"
	"1gkZZO9wTpRKrhuW3XtaBMkCAwEAAaOCAlYwggJSMA4GA1UdDwEB/wQEAwIFoDAd\n"
	"BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNV\n"
	"HQ4EFgQUW/ht3YVQnVmfAWGArMLkgIyUFNYwHwYDVR0jBBgwFoAUFC6zF7dYVsuu\n"
	"UAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8v\n"
	"cjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9y\n"
	"Zy8wJwYDVR0RBCAwHoIPbXRhLm9wZW5zc2wub3JnggtvcGVuc3NsLm9yZzBMBgNV\n"
	"HSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIBFhpo\n"
	"dHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQMGCisGAQQB1nkCBAIEgfQEgfEA\n"
	"7wB2AEHIyrHfIkZKEMahOglCh15OMYsbA+vrS8do8JBilgb2AAABf3Uo37wAAAQD\n"
	"AEcwRQIhAMDDz1KXMWXblh9maYNLF6vlZOcSXNlp3RgxJhRBYhACAiBB8mU+mqDa\n"
	"8RNog7zLQq3426vcfH4r1wufDnQ0su3GyQB1ACl5vvCeOTkh8FZzn2Old+W+V32c\n"
	"YAr4+U1dJlwlXceEAAABf3Uo4ZoAAAQDAEYwRAIgVD5+n6KMePTQF2GN4ZKIE8Oz\n"
	"lzZPeY90EPY5APu3ZrECIE4HWJ/ZQ/qZ3/7x4Vo+1a1gPoPBM4rsh3d3ormsrkiW\n"
	"MA0GCSqGSIb3DQEBCwUAA4IBAQA+TYBjasfMBLlXbwNdYGaVtfbBKyPPhHFHOqi2\n"
	"iJfdRnx2Z/KS0gmBisD6SS62dKAjHrUy4wSfRTSpAHAOvo3n7BuYSE+3HIYwyFpB\n"
	"P54tJTiEYiAHJvWsPRl8rEqxzYnaR+u0zdKL7Wauk9gJMwGX6fdwhhAgS5WmBe05\n"
	"O4mf8jdWgtLQYxS/kvQYrNDTTBA6J+UoNM/JIxXENMh2/6zcFgy0D2ewr0NjAYWU\n"
	"Ylf5jVgHjxleRSGnbt19v8dwZcHyBhq+vdndQt0sDQl7aoNEKiCXU2/y0KAtDjGF\n"
	"tsFic9a3WMzENWlAUcfACBaGx8Qm9161M9BO396tgHavQLQ8\n"
	"-----END CERTIFICATE-----\n"
);

int main(void) {
	BIO *bio = NULL;
	X509 *x509 = NULL;
	EVP_PKEY *evp_pkey = NULL;
	EVP_PKEY_CTX *evp_pkey_ctx = NULL;
	int ret = 1;

	if (__prepare_method() < 1) {
		goto cleanup;
	}

	if ((bio = BIO_new_mem_buf(pem, strlen(pem))) == NULL) {
		goto cleanup;
	}

	if ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
		goto cleanup;
	}

	if ((evp_pkey = X509_get_pubkey(x509)) == NULL) {
		goto cleanup;
	}

	if (__hook_evp_pkey(evp_pkey) < 1) {
		goto cleanup;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000
	if ((evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL)) == NULL) {
		goto cleanup;
	}
#else
	if ((evp_pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, evp_pkey, NULL)) == NULL) {
		goto cleanup;
	}
#endif

	if (EVP_PKEY_sign_init(evp_pkey_ctx) < 1) {
		goto cleanup;
	}

	{
		char buf[1024];
		size_t len = sizeof(buf);
		if (EVP_PKEY_sign(evp_pkey_ctx, buf, &len, "Test", 4) < 1) {
			goto cleanup;
		}
	}

	ret = 0;

cleanup:

	ERR_print_errors_fp(stdout);

	EVP_PKEY_CTX_free(evp_pkey_ctx);
	EVP_PKEY_free(evp_pkey);
	X509_free(x509);
	BIO_free(bio);

	__free_method();

	return ret;
}
