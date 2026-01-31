# SPDX-License-Identifier: GPL-2.0
#
# Makefile for crypto selftests
#
# Tests for crypto subsystem parsing vulnerabilities:
# - DH parameter parsing (integer overflow, OOB pointers)
# - RSA key component parsing (validation gaps)
# - X.509 certificate loader (manual ASN.1 parsing)
# - OID component parsing (integer overflow)
# - ASN.1 indefinite length recursion (DoS)
#

TEST_GEN_PROGS := dh_helper_test rsa_helper_test x509_loader_test oid_parser_test asn1_depth_test aead_overflow_test skcipher_overflow_test hash_overflow_test hmac_overflow_test ecdsa_test drbg_test krb5_test rxkad_test ima_evm_test evm_test bluetooth_test wifi_test dm_crypto_test sensitive_mem_test

CFLAGS += -Wall -Werror

include ../lib.mk

# DH tests only need basic libc
$(OUTPUT)/dh_helper_test: dh_helper_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# RSA test now uses keyctl for testing
$(OUTPUT)/rsa_helper_test: rsa_helper_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkeyutils

# X.509 and ASN.1 tests need keyutils for add_key()
$(OUTPUT)/x509_loader_test: x509_loader_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkeyutils

$(OUTPUT)/oid_parser_test: oid_parser_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(OUTPUT)/asn1_depth_test: asn1_depth_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkeyutils

# AEAD and skcipher tests use AF_ALG interface
$(OUTPUT)/aead_overflow_test: aead_overflow_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(OUTPUT)/skcipher_overflow_test: skcipher_overflow_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(OUTPUT)/hash_overflow_test: hash_overflow_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(OUTPUT)/hmac_overflow_test: hmac_overflow_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(OUTPUT)/ecdsa_test: ecdsa_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkeyutils

$(OUTPUT)/drbg_test: drbg_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(OUTPUT)/krb5_test: krb5_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(OUTPUT)/rxkad_test: rxkad_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# IMA/EVM and security integrity tests
$(OUTPUT)/ima_evm_test: ima_evm_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# EVM xattr and HMAC tests (requires root, exercises evm_crypto.c)
$(OUTPUT)/evm_test: evm_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# Bluetooth SMP crypto tests
$(OUTPUT)/bluetooth_test: bluetooth_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# WiFi/MAC80211 crypto tests
$(OUTPUT)/wifi_test: wifi_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# dm-crypt/dm-integrity crypto tests
$(OUTPUT)/dm_crypto_test: dm_crypto_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# Sensitive memory handling tests
$(OUTPUT)/sensitive_mem_test: sensitive_mem_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
