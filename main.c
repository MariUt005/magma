#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MASK32 pow(2, 32)-1

static unsigned char Pi[8][16] = {
	{12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
	{6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
	{11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
	{12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
	{7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
	{5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
	{8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
	{1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},
};

union char_uint64 {
	uint64_t uint;
	char c[8];
};

union char_uint32x8 {
	uint32_t uint[8];
	char c[33];
};

uint32_t t(uint32_t in) {
	uint32_t res = 0;
	int j;
	for (int i = 7; i >= 0; --i) {
		j = (in >> 4 * i) & 0xf;
		res <<= 4;
		res ^= Pi[i][j];
	}
	return res;
}

uint32_t rot11(uint32_t in) {
	return ((in << 11) ^ (in >> (32 - 11))) & (uint64_t)MASK32;
}

uint32_t g(uint32_t in, uint32_t k) {
	return rot11(t((uint64_t)(in + k) % (uint64_t)(MASK32 + 1)));
}

void magma_key_shedule(uint32_t* key, uint32_t* out_keys) {
	int i;
	int j = 0;
	for (i = 0; i < 8; ++i) {
		out_keys[j] = key[i];
		++j;
	}
	for (i = 0; i < 8; ++i) {
		out_keys[j] = out_keys[i];
		++j;
	}
	for (i = 0; i < 8; ++i) {
		out_keys[j] = out_keys[i];
		++j;
	}
	for (i = 7; i >= 0; --i) {
		out_keys[j] = out_keys[i];
		++j;
	}
}

void magma_encrypt(uint64_t* text, uint32_t* key, uint64_t* enc_text) {
	uint32_t keys[32];
	magma_key_shedule(key, keys);
	uint32_t left = *text >> 32;
	uint32_t right = *text & (uint64_t)MASK32;
	uint32_t temp;
	for (int i = 0; i < 31; ++i) {
		temp = right;
		right = left ^ g(right, keys[i]);
		left = temp;
	}
	*enc_text = ((uint64_t)(left ^ g(right, keys[31])) << 32) + right;
}

void magma_decrypt(uint64_t* enc_text, uint32_t* key, uint64_t* text) {
	uint32_t keys[32];
	magma_key_shedule(key, keys);
	uint32_t left = *enc_text >> 32;
	uint32_t right = *enc_text & (uint64_t)MASK32;
	uint32_t temp;
	for (int i = 31; i > 0; --i) {
		temp = right;
		right = left ^ g(right, keys[i]);
		left = temp;
	}
	*text = ((uint64_t)(left ^ g(right, keys[0])) << 32) ^ right;
}

void magma_encrypt_file(uint32_t* key, FILE* file) {
	union char_uint64 in_buf, out_buf;
	int n;
	while (!feof(file)) {
		memset(in_buf.c, '\0', 9);
		memset(out_buf.c, '\0', 9);
		n = fread(in_buf.c, 1, 8, file);
		if (in_buf.uint == 0) { continue; }
		magma_encrypt(&in_buf.uint, key, &out_buf.uint);
		fseek(file, -n, SEEK_CUR);
		fwrite(out_buf.c, 1, 8, file);
	}
}

void magma_decrypt_file(uint32_t* key, FILE* file) {
	union char_uint64 in_buf, out_buf;
	int n;
	while (!feof(file)) {
		memset(out_buf.c, '\0', 9);
		memset(in_buf.c, '\0', 9);
		n = fread(in_buf.c, 1, 8, file);
		if (in_buf.uint == 0) { continue; }
		magma_decrypt(&in_buf.uint, key, &out_buf.uint);
		fseek(file, -n, SEEK_CUR);
		fwrite(out_buf.c, 1, 8, file);
	}
}

int main() {
	union char_uint32x8 key; memset(key.c, '\0', 33);
	char file_name[30]; memset(file_name, '\0', 9);
	int mode;

	printf("Input key >> ");
	scanf("%32s", key.c);
	while (getchar() != '\n');

	printf("Input file name >> ");
	scanf("%30s", file_name);
	while (getchar() != '\n');

	FILE* file;
	file = fopen(file_name, "r+b");
	if (!file) { printf("Error while opening file!\n"); return -1; }

choose_mode:
	printf("Choose mode:\n0 - encrypt\n1 - decrypt\n>> ");
	scanf("%d", &mode);

	switch (mode) {
	case 0:
		magma_encrypt_file(key.uint, file);
		break;
	case 1:
		magma_decrypt_file(key.uint, file);
		break;
	default:
		goto choose_mode;
	}
	fclose(file);
	return 0;
}
