/*
 * the playground is accroading to heaphopper.gen_zoo 
 * In this binary, we try to use real execution, and use pwntool to attach it,
 * to understand it allocator behavior by tracking the heap metadata.
*/
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mcheck.h>

typedef struct __attribute__((__packed__)) {
	uint64_t * global_var;
} controlled_data;

// typedef struct __attribute__((__packed__)) {
// 	uint64_t ctrl_0[0x40];
// 	uint64_t * ptr;
// 	uint64_t ctrl_1[0x40];
// } symbolic_data;

typedef struct __attribute__((__packed__)) {
	uint64_t data[0x20];
} symbolic_data;

// typedef struct __attribute__((__packed__)) {
// 	uint64_t data[0x80];
// } symbolic_data;

// typedef struct __attribute__((__packed__)) {
// 	uint64_t data[0x0];
// } symbolic_data;

void winning(void) {
	puts("You win!");
}

size_t write_target[8];
size_t offset;
size_t header_size;
size_t mem2chunk_offset;
size_t malloc_sizes[8];
size_t overflow_sizes[8];
size_t fill_sizes[8];
size_t arw_offsets[8];
size_t bf_offsets[8];

controlled_data ctrl_data[8] __attribute__((aligned(16)));
symbolic_data sym_data[8] __attribute__((aligned(16)));

#define FD 0
#define DEPTH 8 

unsigned long get_number()
{
    char buf[32] = {0};
    if (!fgets(buf, sizeof(buf), stdin)) {
        perror("fgets");
    }
    unsigned long num = 0;
    sscanf(buf, "%ld", &num);
    return num;
}

int main(void) {
    /* def heap_setup(): */
	void *dummy_chunk = malloc(0x200);
	free(dummy_chunk);

    int opt;
    for (int i=0; i<DEPTH; i++) {
        int num, count, overflow_num;
        printf(">");
        opt = get_number();

        switch (opt) {
            case 1: /* def malloc(num): */
                printf("num: ");
                num = get_number();
                ctrl_data[num].global_var = malloc(malloc_sizes[num]);
                break;
            case 2: /* def fill_chunk(num): */
                printf("num: ");
                num = get_number();
                for (int i=0; i < fill_sizes[num]; i+=8) {
                    read(0, ((uint8_t *)ctrl_data[num].global_var)+i, 8);
                }
                break;
            case 3: /* def free(num): */ /* def double_free(num): */
                printf("num: ");
                num = get_number();
                free(ctrl_data[num].global_var);
                break;
            case 4: /* def uaf(num): */
                printf("num: ");
                num = get_number();
                read(FD, ctrl_data[num].global_var, header_size);
                break;
            case 5: /* def overflow(num, overflow_num): */
                printf("num: ");
                num = get_number();
                printf("overflow_num: ");
                overflow_num = get_number();
                offset = mem2chunk_offset;
                read(FD, ((char *) ctrl_data[num].global_var)-offset, overflow_sizes[overflow_num]);
                break;
            case 6: /* def fake_free(num): */
                printf("num: ");
                num = get_number();
                free(((uint8_t *) &sym_data[num].data) + mem2chunk_offset);
                break;
            // case 7: /* def arb_relative_write(num, count): */
            //     num = get_number();
            //     arw_offsets[count] = 0;
            //     read(0, &arw_offsets[count], sizeof(arw_offsets[count]));
            //     arw_offsets[count] = arw_offsets[count] % malloc_sizes[num];
            //     read(FD, ctrl_data[num].global_var+arw_offsets[count], sizeof(arw_offsets[count]));
            //     break;
            // case 8: /* def single_bitflip(num, count): */
            //     num = get_number();
            //     bf_offsets[count] = 0;
            //     read(0, &bf_offsets[count], sizeof(bf_offsets[count]));
            //     uint8_t bit[count];
            //     read(0, &bit[count], sizeof(bit[count]));
            //     bit[count] = bit[count] % 64;
            //     *(ctrl_data[num].global_var+bf_offsets[count]) = *(ctrl_data[num].global_var+bf_offsets[count]) ^ (1 << bit[count]);
            //     break;
            case 9: /*  */
                num = get_number();

                break;
            case 10: /*  */
                num = get_number();

                break;
            case 11: /*  */
                num = get_number();       
                
                break;
            default:
                printf("invalid option\n");
        }
    }
    winning();
    return 0;
}