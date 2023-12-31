#ifndef	_OPTION_H
#define	_OPTION_H	1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define ARGCOUNT 10*1024

bool searchOpts(int argc, char* argv[], int optCnt, char* optStr[], bool optVal[]);
void separateOpts(int argc, char* argv[], int* notOptc, char* notOptv[]);
void splitOpts(int argc, char* argv[], int* notOptc, char* notOptv[], int splitStart);

#endif /* option.h  */
