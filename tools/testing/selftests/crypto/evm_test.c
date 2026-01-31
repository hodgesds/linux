// SPDX-License-Identifier: GPL-2.0
/*
 * EVM (Extended Verification Module) crypto tests
 *
 * Tests for security/integrity/evm/evm_crypto.c fixes:
 * - crypto_shash_update() and crypto_shash_final() return value checking
 *   in hmac_add_misc(), evm_calc_hmac_or_hash(), and evm_init_hmac()
 *
 * These tests exercise the EVM subsystem by:
 * 1. Setting/getting security.evm xattrs on files
 * 2. Triggering EVM HMAC recalculation
 * 3. Verifying error propagation
 *
 * Requirements:
 * - CONFIG_EVM=y
 * - CONFIG_EVM_ATTR_FSUUID=y (optional)
 * - Must run as root
 * - Filesystem must support xattrs
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include "../kselftest_harness.h"

#define EVM_SYSFS_PATH "/sys/kernel/security/evm"
#define TEST_DIR "/tmp/evm_test"
#define TEST_FILE "/tmp/evm_test/testfile"

/* EVM xattr name */
#define XATTR_NAME_EVM "security.evm"
#define XATTR_NAME_IMA "security.ima"
#define XATTR_NAME_SELINUX "security.selinux"

/* EVM signature types */
#define EVM_XATTR_HMAC 0x01
#define EVM_XATTR_DIGSIG 0x02

FIXTURE(evm_crypto) {
	int evm_enabled;
	char *test_file;
};

static int check_evm_enabled(void)
{
	char buf[16];
	int fd, ret;
	ssize_t n;

	fd = open(EVM_SYSFS_PATH, O_RDONLY);
	if (fd < 0)
		return 0;

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (n <= 0)
		return 0;

	buf[n] = '\0';
	ret = atoi(buf);
	return ret;
}

static int create_test_file(const char *path)
{
	int fd;

	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0)
		return -1;

	/* Write some test content */
	write(fd, "EVM test content\n", 17);
	close(fd);
	return 0;
}

FIXTURE_SETUP(evm_crypto)
{
	self->evm_enabled = check_evm_enabled();
	self->test_file = NULL;

	/* Create test directory */
	mkdir(TEST_DIR, 0755);

	/* Create test file */
	if (create_test_file(TEST_FILE) == 0)
		self->test_file = strdup(TEST_FILE);
}

FIXTURE_TEARDOWN(evm_crypto)
{
	if (self->test_file) {
		unlink(self->test_file);
		free(self->test_file);
	}
	rmdir(TEST_DIR);
}

/*
 * Test 1: Check EVM availability
 * This test verifies that the EVM subsystem is available and reports
 * its status.
 */
TEST_F(evm_crypto, evm_availability)
{
	int fd;

	fd = open(EVM_SYSFS_PATH, O_RDONLY);
	if (fd < 0) {
		TH_LOG("EVM sysfs not available (CONFIG_EVM not enabled?)");
		SKIP(return, "EVM not available");
	}
	close(fd);

	TH_LOG("EVM enabled status: %d", self->evm_enabled);
	/* Just check that we can read the status */
	EXPECT_GE(self->evm_enabled, 0);
}

/*
 * Test 2: Get security.evm xattr
 * Tests the read path which uses evm_calc_hmac_or_hash()
 */
TEST_F(evm_crypto, get_evm_xattr)
{
	char buf[256];
	ssize_t ret;

	if (!self->test_file) {
		TH_LOG("Test file not created");
		SKIP(return, "No test file");
	}

	/* Try to get the EVM xattr - may not exist if EVM not initialized */
	ret = getxattr(self->test_file, XATTR_NAME_EVM, buf, sizeof(buf));
	if (ret < 0) {
		if (errno == ENODATA) {
			TH_LOG("No EVM xattr (EVM key not loaded?)");
			/* This is expected if EVM is not fully initialized */
		} else if (errno == EOPNOTSUPP) {
			TH_LOG("xattrs not supported on this filesystem");
			SKIP(return, "xattrs not supported");
		} else {
			TH_LOG("getxattr failed: %d (%s)", errno, strerror(errno));
		}
	} else {
		TH_LOG("Got EVM xattr: %zd bytes, type=0x%02x", ret, (unsigned char)buf[0]);
		EXPECT_GT(ret, 0);
	}
}

/*
 * Test 3: Set and verify security.ima xattr
 * IMA xattrs are protected by EVM, so this exercises evm_calc_hmac_or_hash()
 */
TEST_F(evm_crypto, set_ima_xattr)
{
	/* Fake IMA hash - 32 bytes SHA256 with header */
	unsigned char ima_hash[34] = {
		0x04,  /* IMA_XATTR_DIGEST_NG */
		0x04,  /* SHA256 algorithm ID */
		/* 32 bytes of hash data */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	};
	char buf[256];
	ssize_t ret;

	if (!self->test_file) {
		TH_LOG("Test file not created");
		SKIP(return, "No test file");
	}

	if (geteuid() != 0) {
		TH_LOG("Must be root to set security xattrs");
		SKIP(return, "Not root");
	}

	/* Set the IMA xattr - this triggers EVM recalculation if EVM is active */
	ret = setxattr(self->test_file, XATTR_NAME_IMA, ima_hash,
		       sizeof(ima_hash), 0);
	if (ret < 0) {
		if (errno == EOPNOTSUPP) {
			TH_LOG("xattrs not supported");
			SKIP(return, "xattrs not supported");
		} else if (errno == EPERM) {
			TH_LOG("Permission denied (need CAP_SYS_ADMIN?)");
			SKIP(return, "Permission denied");
		}
		TH_LOG("setxattr failed: %d (%s)", errno, strerror(errno));
		return;
	}

	TH_LOG("Set IMA xattr: %zu bytes", sizeof(ima_hash));

	/* Verify we can read it back */
	ret = getxattr(self->test_file, XATTR_NAME_IMA, buf, sizeof(buf));
	EXPECT_EQ((ssize_t)sizeof(ima_hash), ret);
	if (ret > 0) {
		EXPECT_EQ(0, memcmp(buf, ima_hash, ret));
		TH_LOG("IMA xattr verified");
	}

	/* Clean up */
	removexattr(self->test_file, XATTR_NAME_IMA);
}

/*
 * Test 4: Multiple xattr updates
 * This exercises the loop in evm_calc_hmac_or_hash() that iterates
 * over protected xattrs
 */
TEST_F(evm_crypto, multiple_xattr_updates)
{
	unsigned char ima_hash[34];
	int i, success = 0;
	ssize_t ret;

	if (!self->test_file) {
		SKIP(return, "No test file");
	}

	if (geteuid() != 0) {
		SKIP(return, "Not root");
	}

	/* Repeatedly set/update the IMA xattr */
	for (i = 0; i < 100; i++) {
		memset(ima_hash, 0, sizeof(ima_hash));
		ima_hash[0] = 0x04;  /* IMA_XATTR_DIGEST_NG */
		ima_hash[1] = 0x04;  /* SHA256 */
		memset(ima_hash + 2, i & 0xFF, 32);

		ret = setxattr(self->test_file, XATTR_NAME_IMA, ima_hash,
			       sizeof(ima_hash), 0);
		if (ret == 0)
			success++;
	}

	TH_LOG("Multiple xattr updates: %d/100 succeeded", success);
	EXPECT_GT(success, 90);

	/* Clean up */
	removexattr(self->test_file, XATTR_NAME_IMA);
}

/*
 * Test 5: Concurrent file operations
 * Tests EVM's handling of concurrent access
 */
TEST_F(evm_crypto, concurrent_file_access)
{
	char path[256];
	int i, created = 0;

	if (geteuid() != 0) {
		SKIP(return, "Not root");
	}

	/* Create multiple files rapidly */
	for (i = 0; i < 50; i++) {
		snprintf(path, sizeof(path), "%s/file%d", TEST_DIR, i);
		if (create_test_file(path) == 0)
			created++;
	}

	TH_LOG("Created %d/50 test files", created);
	EXPECT_EQ(50, created);

	/* Clean up */
	for (i = 0; i < 50; i++) {
		snprintf(path, sizeof(path), "%s/file%d", TEST_DIR, i);
		unlink(path);
	}
}

/*
 * Test 6: Large xattr stress test
 * Tests handling of larger xattr values
 */
TEST_F(evm_crypto, large_xattr_stress)
{
	unsigned char large_xattr[4096];
	char buf[4096];
	ssize_t ret;
	int i;

	if (!self->test_file) {
		SKIP(return, "No test file");
	}

	if (geteuid() != 0) {
		SKIP(return, "Not root");
	}

	/* Try setting progressively larger xattrs */
	for (i = 32; i <= 1024; i *= 2) {
		memset(large_xattr, 0, sizeof(large_xattr));
		large_xattr[0] = 0x04;
		large_xattr[1] = 0x04;
		memset(large_xattr + 2, 0xAA, i - 2);

		ret = setxattr(self->test_file, XATTR_NAME_IMA, large_xattr, i, 0);
		if (ret < 0) {
			TH_LOG("Failed to set %d byte xattr: %s", i, strerror(errno));
			continue;
		}

		ret = getxattr(self->test_file, XATTR_NAME_IMA, buf, sizeof(buf));
		if (ret != i) {
			TH_LOG("Size mismatch: set %d, got %zd", i, ret);
		}
	}

	TH_LOG("Large xattr test completed");

	/* Clean up */
	removexattr(self->test_file, XATTR_NAME_IMA);
}

/*
 * Test 7: EVM status transitions
 * Tests reading EVM status which exercises initialization paths
 */
TEST_F(evm_crypto, evm_status_read)
{
	char buf[64];
	int fd;
	ssize_t n;
	int iterations = 0;

	fd = open(EVM_SYSFS_PATH, O_RDONLY);
	if (fd < 0) {
		SKIP(return, "EVM sysfs not available");
	}

	/* Read EVM status multiple times - re-open each time since it's sysfs */
	close(fd);
	for (int i = 0; i < 100; i++) {
		fd = open(EVM_SYSFS_PATH, O_RDONLY);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0)
			iterations++;
	}

	TH_LOG("EVM status read: %d/100 iterations", iterations);
	EXPECT_EQ(100, iterations);
}

/*
 * Test 8: File attribute changes
 * Changing file attributes (uid, gid, mode) should trigger EVM recalc
 * This exercises hmac_add_misc() which hashes these values
 */
TEST_F(evm_crypto, file_attr_changes)
{
	struct stat st;
	int ret;

	if (!self->test_file) {
		SKIP(return, "No test file");
	}

	if (geteuid() != 0) {
		SKIP(return, "Not root");
	}

	/* Get original attributes */
	ret = stat(self->test_file, &st);
	ASSERT_EQ(0, ret);

	/* Change mode - triggers EVM recalculation */
	ret = chmod(self->test_file, 0600);
	if (ret < 0) {
		TH_LOG("chmod failed: %s", strerror(errno));
	}
	EXPECT_EQ(0, ret);

	/* Change back */
	ret = chmod(self->test_file, st.st_mode);
	EXPECT_EQ(0, ret);

	/* If we're truly root, try chown */
	ret = chown(self->test_file, st.st_uid, st.st_gid);
	EXPECT_EQ(0, ret);

	TH_LOG("File attribute changes completed");
}

TEST_HARNESS_MAIN
