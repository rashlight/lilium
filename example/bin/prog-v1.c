#include <stdio.h>
#include <unistd.h>

void main(int argc, char *argv[])
{
	FILE *file;
	file = fopen("prog.txt", "w");

	if (argc > 1)
	{
		fprintf(file, "Hello Lilium Project tester, %s!\nMy pid is %i\nI am holding %i arguments\n", argv[1], getpid(), argc);
	}
	else
	{
		fprintf(file, "Hello Lilium Project tester!\nMy pid is %i\nI am holding %i arguments\n", getpid(), argc);
	}

	fclose(file);
}