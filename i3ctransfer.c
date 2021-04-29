// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Synopsys, Inc. and/or its affiliates.
 *
 * Author: Vitor Soares <vitor.soares@synopsys.com>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <i3cdev.h>

#define VERSION "0.1"

const char *sopts = "d:p:a:r:w:vh";
static const struct option lopts[] = {
	{"device",		required_argument,	NULL,	'd' },
	{"pec",			required_argument,	NULL,	'p' },
	{"addr_dynamic",	required_argument,	NULL,	'a' },
	{"read",		required_argument,	NULL,	'r' },
	{"write",		required_argument,	NULL,	'w' },
	{"command",		required_argument,	NULL,	'c' },
	{"help",		no_argument,		NULL,	'h' },
	{"version",		no_argument,		NULL,	'v' },
	{0, 0, 0, 0}
};

static void print_usage(const char *name)
{
	fprintf(stderr, "usage: %s options...\n", name);
	fprintf(stderr, "  options:\n");
	fprintf(stderr, "    -d --device       <dev>          device to use.\n");
	fprintf(stderr, "    -p --pec                         append PEC.\n");
	fprintf(stderr, "    -a --addr_dynamic                device dynamic address for PEC calculation\n");
	fprintf(stderr, "    -r --read         <data length>  read data.\n");
	fprintf(stderr, "    -w --write        <data block>   Write data block.\n");
	fprintf(stderr, "    -h --help                        Output usage message and exit.\n");
	fprintf(stderr, "    -v --version                     Output the version number and exit\n");
}

uint32_t dev_dyn_addr = 0x70;
static uint8_t crc8_lookup[256] = {
0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15, 0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65, 0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5, 0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85, 0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2, 0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2, 0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32, 0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42, 0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C, 0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC, 0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C, 0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C, 0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B, 0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B, 0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB, 0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB, 0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3,
};

static uint8_t calc_crc8(uint8_t *ptr, uint8_t len, uint8_t init_v)
{
	uint8_t crc = init_v;

	while (len--) {
		crc = crc8_lookup[crc ^ *ptr++];
	}
	return (crc);
}

static int rx_args_to_xfer(struct i3c_ioc_priv_xfer *xfer, char *arg)
{
	int len = strtol(optarg, NULL, 0);
	uint8_t *tmp;

	tmp = (uint8_t *)calloc(len, sizeof(uint8_t));
	if (!tmp)
		return -1;

	xfer->rnw = 1;
	xfer->len = len;
	xfer->data = (uintptr_t)tmp;

	return 0;
}

static int w_args_to_xfer(struct i3c_ioc_priv_xfer *xfer, char *arg, int pec_en)
{
	char *data_ptrs[256];
	int len, i = 0;
	uint8_t *tmp;
	uint8_t crc, first_byte = dev_dyn_addr << 1;

	data_ptrs[i] = strtok(arg, ",");

	while (data_ptrs[i] && i < 255)
		data_ptrs[++i] = strtok(NULL, ",");

	if (pec_en)
		tmp = (uint8_t *)calloc(i + 1, sizeof(uint8_t));
	else
		tmp = (uint8_t *)calloc(i, sizeof(uint8_t));
	if (!tmp)
		return -1;

	for (len = 0; len < i; len++)
		tmp[len] = (uint8_t)strtol(data_ptrs[len], NULL, 0);

	if (pec_en) {
		if (0xff == tmp[0]) {
			/*
			CCC: exclude 1st byte from PEC calculation
			for example:
			ENEC CCC
			Start
				byte0: (0x7e << 1) | 0x0
				byte1: 0x80 (Direct ENEC)
				byte2: PEC (only include byte1)
			Repeat start:
				byte0: (device address << 1) | 0x0
				byte1: (0x00 << 1) | ENINT
				byte2: PEC (from byte0~byte1)
			*/
			crc = calc_crc8(tmp + 1, len - 1, 0);
		} else {
			/*
			PEC calculation includes device dynamic address and RnW
			encoding:
		    	first_byte[7:1]: dyn_addr
		    	first_byte[0]: RnW
			*/
			crc = calc_crc8(&first_byte, 1, 0);
			crc = calc_crc8(tmp, len, crc);
		}
		tmp[len++] = crc;
		fprintf(stdout, "append crc=0x%02x, len=%d\n", crc, len);
	}
	xfer->len = len;
	xfer->data = (uintptr_t)tmp;

	return 0;
}

static void print_rx_data(struct i3c_ioc_priv_xfer *xfer)
{
	uint8_t *tmp;
	int i;

	tmp = (uint8_t *)calloc(xfer->len, sizeof(uint8_t));
	if (!tmp)
		return;

	memcpy(tmp, (void *)(uintptr_t)xfer->data, xfer->len * sizeof(uint8_t));

	fprintf(stdout, "  received data:\n");
	for (i = 0; i < xfer->len; i++)
		fprintf(stdout, "    0x%02x\n", tmp[i]);

	free(tmp);
}

int main(int argc, char *argv[])
{
	struct i3c_ioc_priv_xfer *xfers;
	int file, ret, opt, i, pec_en = 0;
	int nxfers = 0;
	char *device;

	while ((opt = getopt_long(argc, argv,  sopts, lopts, NULL)) != EOF) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
			/* fall through */
		case 'v':
			fprintf(stderr, "%s - %s\n", argv[0], VERSION);
			exit(EXIT_SUCCESS);
		case 'd':
			/* fall through */
			device = optarg;
			break;
		case 'p':
			pec_en = strtol(optarg, NULL, 0);
			break;
		case 'a':
			dev_dyn_addr = strtol(optarg, NULL, 0);
			break;
		case 'r':
		case 'w':
			nxfers++;
			break;
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!device)
		exit(EXIT_FAILURE);

	file = open(device, O_RDWR);
	if (file < 0)
		exit(EXIT_FAILURE);

	xfers = (struct i3c_ioc_priv_xfer *)calloc(nxfers, sizeof(*xfers));
	if (!xfers)
		exit(EXIT_FAILURE);

	optind = 1;
	nxfers = 0;

	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) != EOF) {
		switch (opt) {
		case 'h':
		case 'v':
		case 'd':
		case 'p':
			break;
		case 'r':
			if (rx_args_to_xfer(&xfers[nxfers], optarg)) {
				ret = EXIT_FAILURE;
				goto err_free;
			}

			nxfers++;
			break;
		case 'w':
			if (w_args_to_xfer(&xfers[nxfers], optarg, pec_en)) {
				ret = EXIT_FAILURE;
				goto err_free;
			}

			nxfers++;
			break;
		}
	}

	if (ioctl(file, I3C_IOC_PRIV_XFER(nxfers), xfers) < 0) {
		fprintf(stderr, "Error: transfer failed: %s\n", strerror(errno));
		ret = EXIT_FAILURE;
		goto err_free;
	}

	for (i = 0; i < nxfers; i++) {
		fprintf(stdout, "Success on message %d\n", i);
		if (xfers[i].rnw)
			print_rx_data(&xfers[i]);
	}

	ret = EXIT_SUCCESS;

err_free:
	for (i = 0; i < nxfers; i++)
		free((void *)(uintptr_t)xfers[i].data);
	free(xfers);

	return ret;
}
