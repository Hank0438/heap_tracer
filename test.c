#include <stdio.h>
#include <stdlib.h>

int main(){
	char *a = malloc(0x200);
	free(a);
	char *b = malloc(0x8);

}

