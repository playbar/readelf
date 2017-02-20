//
// Created by houguoli on 2017/2/20.
//

#include <cstdio>
#include <sys/types.h>
#include <cstdlib>
#include "UnityConfigFile.h"
#include "stdint.h"


int32_t swapInt32(int32_t value)
{
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0xFF000000) >> 24) ;
}

UnityConfigFile::UnityConfigFile()
{
    mfilelong = 0;
}

UnityConfigFile::~UnityConfigFile()
{

}

void UnityConfigFile::readFile()
{
    int tmp = 0;
    FILE* pf = fopen("globalgamemanagers", "r" );
    if( pf == NULL)
        return;

    fseek( pf, 4, SEEK_CUR);
    unsigned char data[1024];
    fread((char*)&mfilelong, 4, 1, pf );   //  file length
    mfilelong = swapInt32( mfilelong);

    fseek( pf, 4, SEEK_CUR);
    fread( &mbaseaddr, 4, 1, pf);
    mbaseaddr = swapInt32(mbaseaddr); // base address

    fseek( pf, 20, SEEK_CUR);

    int stcount = 0;
    int everycount = 0;
    fread( &stcount, 4, 1, pf);
    fread( &everycount, 4, 1, pf);
    stcount = swapInt32( stcount);
    everycount = swapInt32(everycount);
    everycount *= 4;
    tmp = everycount * stcount;

    fseek(pf, stcount * everycount, SEEK_CUR);
//    lseek(pf, 4, SEEK_CUR);
    fread( &tmp, 4, 1, pf);
    fseek(pf, 10 * 24, SEEK_CUR);
    fseek(pf, 12, SEEK_CUR);
    int modifycount =0;
    fread( &modifycount, 4, 1, pf);



//    mfilelong = atoi((char*)data);

    fclose(pf);
    return;
}