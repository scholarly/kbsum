#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
In python, this is a two-liner:

   with open(fname,"r") as wordfile:
	return wordfile.read().splitlines()

Writing in C definitely increases my appreciation for higher-level languages.
*/

char **readlist(char *fname, int *count) {
	FILE *wordfile = fopen(fname, "rb");
	if (!wordfile) {
		char *err = strerror(errno);
		fprintf(stderr, "cannot open word list %s:%s\n", fname, err);
		exit(3);
	}
	fseek(wordfile, 0, SEEK_END);

	size_t cbwords = ftell(wordfile);
	int maxwords = cbwords / 5;	// rough estimate: 5 characters per word; 
	size_t listmem = maxwords * sizeof(char *);
	//fprintf(stderr,"%d %d %d\n",cbwords,maxwords,listmem);

	if (count) {
		*count = 0;
	}
	char *wordmem = (char *)malloc(cbwords + 1);
	char **wordlist = (char **)malloc(listmem);

	if (wordmem == 0 || wordlist == 0) {
		char *err = strerror(errno);
		fprintf(stderr, "%s\n", fname);
		exit(1);
	}
	fseek(wordfile, 0, SEEK_SET);
	size_t bytesread = 0;
	while (bytesread < cbwords) {
		size_t block = fread(wordmem + bytesread, 1, cbwords, wordfile);
		//fprintf(stderr,"read %d bytes\n",block);
		if (block == 0) {
			int errn = ferror(wordfile);
			if (errn) {
				char *err = strerror(errn);
				fprintf(stderr, "error reading word list %s:%s\n", fname, err);
				exit(1);
			} else {
				break;
			}
		} else {
			bytesread += block;
		}
	}
	wordmem[bytesread] = '\0';
	//fprintf(stderr,"wordmem[%d]=%d\n",bytesread,(int)wordmem[bytesread]);

	int iword = 0;
	char *current = wordmem;

	for (int iword = 0; iword < maxwords; ++iword) {
		wordlist[iword] = current;
		char *next = strchr(current, '\n');
		if (next) {
			*next = '\0';
			//fprintf(stderr,"%d:%s ",iword,current);
			current = next + 1;
		} else {
			//fprintf(stderr,"read %d words in %d bytes\n",iword,current-wordmem);
			wordlist[iword] = 0;
			if (count) {
				*count = iword;
			}
			break;
		}
	}
	return wordlist;
}
