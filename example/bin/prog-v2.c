#include <stdio.h>

void main(void) {
	FILE *file;
	file = fopen("prog.txt", "w");
	fprintf(file, "Hello Lilium Project developer!\n");
	fclose(file);
}