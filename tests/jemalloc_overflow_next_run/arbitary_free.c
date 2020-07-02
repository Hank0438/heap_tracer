#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct __attribute__((__packed__)) {
	void* global_var;
} controlled_data;

typedef struct __attribute__((__packed__)) {
	uint64_t data[0x20];
} symbolic_data;

void winning(void) {
	puts("You win!");
}

size_t write_target[4];
size_t offset;
size_t header_size;
size_t mem2chunk_offset;
size_t malloc_sizes[4] = { 0x8, 0x8, 0x8, 0x8 };
size_t overflow_sizes[1];
size_t fill_sizes[4];
size_t arw_offsets[0];
size_t bf_offsets[0];
controlled_data __attribute__((aligned(16))) ctrl_data_0;
controlled_data __attribute__((aligned(16))) ctrl_data_1;
controlled_data __attribute__((aligned(16))) ctrl_data_2;
controlled_data __attribute__((aligned(16))) ctrl_data_3;
symbolic_data __attribute__((aligned(16))) sym_data;

int main(void) {
	void *dummy_chunk = malloc(0x200);
	free(dummy_chunk);

	ctrl_data_0.global_var = malloc(0x100);
	for (int i=0; i < fill_sizes[0]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_0.global_var)+i, 8);
	}

	// printf("%p\n", ctrl_data_0.global_var+0x55);
	// VULN: Fake_free
	free(ctrl_data_0.global_var+0x55);

	ctrl_data_1.global_var = malloc(0x100);
	for (int i=0; i < fill_sizes[1]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_1.global_var)+i, 8);
	}


	// printf("%p\n", ctrl_data_0.global_var);
	// printf("%p\n", ctrl_data_1.global_var);

	

	winning();
	return 0;
}
