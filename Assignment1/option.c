#include "option.h"

bool searchOpts(int argc, char* argv[], int optCnt, char* optStr[], bool optVal[]){
	for(int i=1;i<argc;i++){
		if(argv[i][0]=='-'){
			int flag=1;
			for(int j=0;j<optCnt;j++){
				if(strcmp(argv[i], optStr[j])==0){
					optVal[j]=true;
					flag=0;
					break;
				}
			}
			if(flag){
				printf("%s: invalid option -- '%s'\n",argv[0],&argv[i][1]);
				return false;
			}
		}		
	}
	return true;
}

void separateOpts(int argc, char* argv[], int* notOptc, char* notOptv[]){
	*notOptc=0;
	for(int i=0;i<argc;i++){
		if(argv[i][0]!='-'){
			notOptv[(*notOptc)++] = argv[i];
			//printf("%s\n", argv[i]);
		}
	}
	return;
}

void splitOpts(int argc, char* argv[], int* sOptc, char* sOptv[], int splitStart){
	*sOptc=0;
	for(int i=0;i<argc;i++){
		if (i < splitStart) {
			sOptv[(*sOptc)++] = strdup(argv[i]);
			continue;
		}
		char *t = strtok(argv[i], " ");
		while (t != NULL) {
			if (t[0] == '\'' || t[0] == '"') {
			}
			sOptv[(*sOptc)++] = strdup(t);
			t = strtok(NULL, " ");
			//printf("%s\n", t);
		}
	}
	return;
}
