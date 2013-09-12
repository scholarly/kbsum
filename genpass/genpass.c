#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>


#include "readlist.h"
#include "dicewords.h"
#include "bigdivide.h"

const int bigbytes = 16;

char* SEEDFILE = "/dev/random";


char hex(char c){
    c &= 0xf;
    return c<10 ? c+'0' : c+'a'-10;
}


size_t hexlify(char* out, size_t outlen, char* subject, size_t bytes){

    assert(outlen>=bytes*2);// buffer too small

    size_t j=0;
    for(size_t i = 0; i<bytes;){
        char c = subject[i++];
        out[j++]=hex(c>>4);
        out[j++]=hex(c);
    }
    out[j]='\0';
    return j;
}

int main(int argc, char**argv){
    char big[16];
    char buff[33];

    char* seedfile = SEEDFILE;
    char* wordfile = 0;
    char** wordlist = WORDS;
    int wordcount = WORDCOUNT;
    if( argc>1 ){
        seedfile = argv[1];
        if(argc>2){
            wordfile = argv[2];
        }
    }
    FILE* rand = fopen(seedfile,"rb");
    if(rand){
        fread(big,1,16,rand);
        fclose(rand);
    }else{
        char* err = strerror(errno); 
        fprintf(stderr,"cannot open seed file %s:%s\n",seedfile,err);
        exit(1);
    }

    hexlify(buff,33,big,16);
    puts(buff);

    if(wordfile){
        wordlist = readlist(wordfile,&wordcount);
    }
        
    {
        unsigned int rem;
    
        char more=1;
        printf("wordcount: %d\n",wordcount);
        while(more){
            more = bigdivide(big,bigbytes,wordcount,&rem);
            
            char* word = wordlist[rem];
            printf("%s ",word);
        }
        puts("");
    }

    if(wordfile){
        free(wordlist[0]);
        free(wordlist);
    }
    return 0;

}
