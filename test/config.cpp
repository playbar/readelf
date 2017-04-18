//
// Created by houguoli on 2017/2/20.
//

#include <iostream>
#include "configFile.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#define EXE_SIZE 128
#define LINE_W 32
#define PROT_ALL PROT_READ|PROT_WRITE|PROT_EXEC

void dump_mem(void* start)
{
	if(start == NULL)
		return ;

	char* words = (char*)start;
	int i, j, l;
	l = 0;
	fprintf(stderr, "0x%04x", l);
	for(i=0, j=0; i < EXE_SIZE; i++, ++j)
	{
		if(j >= LINE_W)
		{
			fprintf(stderr, "\n");
			j = 0;
			fprintf(stderr, "0x%04x", ++l);
		}
		fprintf(stderr, " %02x", (unsigned char)*(words+i));
	}
	fprintf(stderr, "\n");
}
void fill_mem(void* start)
{
	char* code = NULL;
	if(start == NULL)
		return ;
	int i = 0;
	code = (char*)start;
	code[i++] = 0x55;
	code[i++] = 0x89;
	code[i++] = 0xe5;
	code[i++] = 0xb8;
	code[i++] = 0x10;
	code[i++] = 0x00;
	code[i++] = 0x00;
	code[i++] = 0x00;
	code[i++] = 0xc9;
	code[i++] = 0xc3;
	/* 这段代码是x86的汇编代码,它是一个完整的函数
     * 调用过程的结构,就是给eax赋值为0x10,
     * 因为exec_mem所调用的start()并没有要求返回值
     * 但却由这段汇编代码给eax(eax是x86的返回值寄存器)
     * 一个值为0x10的值,那么当start()返回后,exec_mem
     * 并没有对eax的操作,所以exec_mem()的返回值就是
     * start()的返回值也就是我那段在mmap空间时的汇编
     * 代码所赋的值.所以程序输出的结果为16(0x10).
     * 这一功能可以发散它,继续使用,可以想像Linux上的
     * 动态库是怎么实现的.或者说一个解释程序的JIT可能
     * 也是基于这一简单的理论实现的.
    */
}
int exec_mem(void* start)
{
	typedef void (*f)(void);
	((f)start)();
}
int main(int argc, char* argv[])
{
	void* start = NULL;
	start = mmap(NULL, EXE_SIZE, PROT_ALL, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	dump_mem(start);
	fill_mem(start);
	dump_mem(start);
	int ret = exec_mem(start);
	fprintf(stderr, "ret:%d\n", ret);
	munmap(start, EXE_SIZE);
	return 0;
}


int main_1(int argc, char **argv)
{
	char *pInFileName = NULL;
	char *pOutFileName = NULL;
	if (argc == 3)
	{
		pInFileName = argv[1];
		pOutFileName = argv[2];
	}
	else
	{
		pInFileName = "globalgamemanagers";
		pOutFileName = "globalgamemanagers_out";
	}
    UnityConfigFile cfgFile;
    cfgFile.addCardboardInDaydream(pInFileName, pOutFileName);
    std::cout << "Hello, World!" << std::endl;
    return 0;
}