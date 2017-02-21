//
// Created by houguoli on 2017/2/20.
//

#include <cstdio>
#include <sys/types.h>
#include <cstdlib>
#include "UnityConfigFile.h"
#include "stdint.h"
#include "memory.h"


int32_t swapInt32(int32_t value)
{
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0xFF000000) >> 24) ;
}

unsigned int calc_align(unsigned int n, unsigned align)
{
	return ((n + align - 1) & (~(align - 1)));
}

UnityConfigFile::UnityConfigFile()
{
    mfilelen = 0;
	mbadd4 = false;
	mbadd8 = false;
	mAddOffest = 0;
	mCurInfPos = 0;
}

UnityConfigFile::~UnityConfigFile()
{

}

int UnityConfigFile::getModifyFileLen(FILE *pInf)
{
	int err = 0;
	int tmp = 0;
	if (pInf == NULL)
		return 0;
	fseek(pInf, 0, SEEK_SET);

	err = fseek(pInf, 4, SEEK_SET);
	//err = fseek(pf, 4, SEEK_SET);
	fread((char*)&mfilelen, 1, 4, pInf);   //  file length
	mfilelen = swapInt32(mfilelen);	
	//fread((char*)&mbaseaddr, 1, 4, pf);
	err = fseek(pInf, 4, SEEK_CUR);
	fread((char*)&mbaseaddr, 1, 4, pInf);
	mbaseaddr = swapInt32(mbaseaddr); // base address

	fseek(pInf, 20, SEEK_CUR);

	int stcount = 0;
	int everycount = 0;
	fread(&stcount, 4, 1, pInf);
	fread(&everycount, 4, 1, pInf);
	stcount = swapInt32(stcount);
	everycount = swapInt32(everycount);
	everycount *= 4;
	tmp = everycount * stcount;

	fseek(pInf, stcount * everycount, SEEK_CUR);
	fseek(pInf, 4, SEEK_CUR);
	//fread( &tmp, 1, 4, pf);
	fseek(pInf, 10 * 28, SEEK_CUR);
	fseek(pInf, 8, SEEK_CUR);
	fread(&m0boffset, 1, 4, pInf);
	fread(&m0blen, 1, 4, pInf);

	fseek(pInf, 20, SEEK_CUR);
	fread(&m0coffset, 1, 4, pInf);
	long coffset = m0blen + m0boffset + 4;
	if (coffset > m0coffset &&  coffset < m0coffset + 4) {
		mbadd4 = true;
		mAddOffest = 4;
	}
	else if (coffset >= m0coffset + 4)
	{
		mbadd8 = true;
		mAddOffest = 8;
	}
}

void UnityConfigFile::changeDaydreamToCardboard(char *pInFile, char *pOutFile)
{
	int err = 0;
	int iTmp = 0;
    char szTmp[1024];
    FILE* pInf = fopen(pInFile, "rb+" );
	FILE *pOutf = fopen(pOutFile, "wb+");
	getModifyFileLen(pInf);
	fseek(pInf, 0, SEEK_SET);
    if( pInf == NULL)
        return;
	if (pOutf == NULL)
		return;
	memset(szTmp, 0, 1024);
	fread(szTmp, 1, 4, pInf);
	mCurInfPos += 4;
	fwrite(szTmp, 1, 4, pOutf);
 
    fread((char*)&mfilelen, 1, 4, pInf );   //  file length
	mCurInfPos += 4;
    mfilelen = swapInt32( mfilelen);
	mfilelen += mAddOffest;
	mfilelen = swapInt32(mfilelen);
	fwrite((char*)&mfilelen, 1, 4, pOutf);

	fread(szTmp, 1, 4, pInf);
	mCurInfPos += 4;
	fwrite(szTmp, 1, 4, pOutf);
    fread( (char*)&mbaseaddr, 1, 4, pInf);
	mCurInfPos += 4;
	fwrite((char*)&mbaseaddr, 1, 4, pOutf);
    mbaseaddr = swapInt32(mbaseaddr); // base address

	fread(szTmp, 1, 20, pInf);
	mCurInfPos += 20;
	fwrite(szTmp, 1, 20, pOutf);

    int stcount = 0;
    int everycount = 0;
    fread( &stcount, 4, 1, pInf);
	mCurInfPos += 4;
	fwrite(&stcount, 4, 1, pOutf);
    fread( &everycount, 4, 1, pInf);
	mCurInfPos += 4;
	fwrite(&everycount, 4, 1, pOutf);
    stcount = swapInt32( stcount);
    everycount = swapInt32(everycount);
    everycount *= 4;
    //int tmp = everycount * stcount;
	for (int i = 0; i < stcount; ++i)
	{
		fread(szTmp, everycount, 1, pInf);
		mCurInfPos += everycount;
		fwrite(szTmp, everycount, 1, pOutf);
	}
	fread(szTmp, 4, 1, pInf);
	mCurInfPos += 4;
	fwrite(szTmp, 4, 1, pOutf);

	fread(szTmp, 10 * 28, 1, pInf);
	fwrite(szTmp, 10 * 28, 1, pOutf);
	mCurInfPos += (10 * 28);

	fread(szTmp, 8, 1, pInf);
	fwrite(szTmp, 8, 1, pOutf);
	mCurInfPos += 8;
	fread(&m0boffset, 4, 1, pInf);
	fwrite(&m0boffset, 4, 1, pOutf);
	mCurInfPos += 4;

    fread( &m0blen, 4, 1, pInf);
	iTmp = m0blen + 4;
	fwrite(&iTmp, 4, 1, pOutf);
	mCurInfPos += 4;
	
	//fseek(pInf, 20, SEEK_CUR);
	fread(szTmp, 20, 1, pInf);
	fwrite(szTmp, 20, 1, pOutf);
	mCurInfPos += 20;
	fread(&m0coffset, 1, 4, pInf);
	long coffset = m0blen + m0boffset + 4;
	if (coffset > m0coffset &&  coffset < m0coffset + 4) {
		mbadd4 = true;
		mAddOffest = 4;
	}
	else if (coffset >= m0coffset + 4)
	{
		mbadd8 = true;
		mAddOffest = 8;
	}

	m0coffset += mAddOffest;
	fwrite(&m0coffset, 4, 1, pOutf);
	mCurInfPos += 4;

	for (int i = 0x0d; i <= stcount; ++i)
	{
		fread(szTmp, 24, 1, pInf);
		fwrite(szTmp, 24, 1, pOutf);
		mCurInfPos += 24;
		fread(&m0doffset, 4, 1, pInf);
		m0doffset += mAddOffest;
		fwrite(&m0doffset, 4, 1, pOutf);
		mCurInfPos += 4;
	}

	iTmp = mbaseaddr + m0boffset - mCurInfPos;
	char *pdata = new char[iTmp + 1];
	fread(pdata, iTmp, 1, pInf);
	fwrite(pdata, iTmp, 1, pOutf);
	delete[]pdata;
	mCurInfPos += iTmp;

	int strlistlen = 0; 
	int strlen = 0;
	fread(&strlistlen, 4, 1, pInf);
	fwrite(&strlistlen, 4, 1, pOutf);
	mCurInfPos += 4;
	for (int i = 0; i < strlistlen; ++i)  //读取包名
	{
		fread(&strlen, 4, 1, pInf);
		fwrite(&strlen, 4, 1, pOutf);
		mCurInfPos += 4;
		strlen = calc_align(strlen, 4);
		fread(szTmp, strlen, 1, pInf);
		fwrite(szTmp, strlen, 1, pOutf);
		mCurInfPos += strlen;
	}

	//fseek(pInf, 4, SEEK_CUR);
	fread(&iTmp, 4, 1, pInf);
	fwrite(&iTmp, 4, 1, pOutf);
	mCurInfPos += 4;
	for (int i = 0; i < iTmp; ++i )
	{
		fread(&strlen, 4, 1, pInf);
		fwrite(&strlen, 4, 1, pOutf);
		mCurInfPos += 4;
		strlen = calc_align(strlen, 4);
		fread(szTmp, strlen, 1, pInf);
		fwrite(szTmp, strlen, 1, pOutf);
		mCurInfPos += strlen;
	}
	fread(&mrendercount, 4, 1, pInf);
	fwrite(&mrendercount, 4, 1, pOutf);
	mCurInfPos += 4;
	fread(&mrenderlen, 4, 1, pInf);	
	mCurInfPos += 4;
	memset(mrendername, 0, 13);
	fread(mrendername, 1, mrenderlen, pInf);
	mrenderlen += 1;
	fwrite(&mrenderlen, 4, 1, pOutf);
	mCurInfPos += mrenderlen;
	memset(mrendername, 0, 13);
	memcpy(mrendername, "cardboard", 9);
	fwrite(mrendername, 12, 1, pOutf);
	
	iTmp = mbaseaddr + m0coffset - mCurInfPos - 4;
	pdata = new char[iTmp + 1];
	fread(pdata, iTmp, 1, pInf);
	mCurInfPos += iTmp;
	fwrite(pdata, iTmp, 1, pOutf);
	if (mAddOffest == 0)
	{
		fseek(pInf, 4, SEEK_CUR);
		mCurInfPos += 4;
	}
	if (iTmp == 8) {
		memset(pdata, 0, iTmp);
		fwrite(pdata, iTmp, 1, pOutf);
	}
	delete[]pdata;

	while ((iTmp = fread(szTmp, 1, 1024, pInf)) != 0)
	{
		fwrite(szTmp, 1, iTmp, pOutf);
	}

    fclose(pInf);
	fclose(pOutf);
    return;
}

void UnityConfigFile::addCardboardInDaydream(char *pInFile, char *pOutFile)
{
	int err = 0;
	int iTmp = 0;
	char szTmp[1024];
	FILE* pInf = fopen(pInFile, "rb+");
	FILE *pOutf = fopen(pOutFile, "wb+");
	fseek(pInf, 0, SEEK_SET);
	if (pInf == NULL)
		return;
	if (pOutf == NULL)
		return;
	memset(szTmp, 0, 1024);
	fread(&iTmp, 4, 1, pInf);
	fwrite(&iTmp, 4, 1, pOutf);
	mCurInfPos += 4;
	
	fread((char*)&mfilelen, 1, 4, pInf);   //  file length
	mCurInfPos += 4;
	mfilelen = swapInt32(mfilelen);
	mfilelen += 16;  //cardboard length
	mfilelen = swapInt32(mfilelen);
	fwrite((char*)&mfilelen, 1, 4, pOutf);

	fread(&mVersoin, 1, 4, pInf);  // version
	mCurInfPos += 4;
	fwrite(&mVersoin, 1, 4, pOutf);
	mVersoin = swapInt32(mVersoin);
	fread((char*)&mbaseaddr, 1, 4, pInf);
	mCurInfPos += 4;
	fwrite((char*)&mbaseaddr, 1, 4, pOutf);
	mbaseaddr = swapInt32(mbaseaddr); // base address

	int verLen = 0;
	if (mVersoin == 15)
	{
		verLen = 20;
	}
	else if (mVersoin == 0x11)
	{
		verLen = 14;
	}

	fread(szTmp, verLen, 1, pInf);
	mCurInfPos += verLen;
	fwrite(szTmp, verLen, 1, pOutf);

	int stcount = 0;
	int everycount = 0;
	fread(&stcount, 4, 1, pInf);
	mCurInfPos += 4;
	fwrite(&stcount, 4, 1, pOutf);
	fread(&everycount, 4, 1, pInf);
	mCurInfPos += 4;
	fwrite(&everycount, 4, 1, pOutf);
	stcount = swapInt32(stcount);
	everycount = swapInt32(everycount);
	everycount *= 4;
	//int tmp = everycount * stcount;
	for (int i = 0; i < stcount; ++i)
	{
		fread(szTmp, everycount, 1, pInf);
		mCurInfPos += everycount;
		fwrite(szTmp, everycount, 1, pOutf);
	}
	fread(szTmp, 4, 1, pInf);
	mCurInfPos += 4;
	fwrite(szTmp, 4, 1, pOutf);

	fread(szTmp, 10 * 28, 1, pInf);
	fwrite(szTmp, 10 * 28, 1, pOutf);
	mCurInfPos += (10 * 28);

	fread(szTmp, 8, 1, pInf);
	fwrite(szTmp, 8, 1, pOutf);
	mCurInfPos += 8;
	fread(&m0boffset, 4, 1, pInf);
	fwrite(&m0boffset, 4, 1, pOutf);
	mCurInfPos += 4;

	fread(&m0blen, 4, 1, pInf);
	iTmp = m0blen + 16;
	fwrite(&iTmp, 4, 1, pOutf);    //length + 16
	mCurInfPos += 4;

	//fseek(pInf, 20, SEEK_CUR);
	fread(szTmp, 20, 1, pInf);
	fwrite(szTmp, 20, 1, pOutf);
	mCurInfPos += 20;

	fread(&m0coffset, 1, 4, pInf);
	mAddOffest = 16;
	iTmp = m0coffset + mAddOffest;
	fwrite(&iTmp, 4, 1, pOutf);
	mCurInfPos += 4;

	for (int i = 0x0d; i <= stcount; ++i)
	{
		fread(szTmp, 24, 1, pInf);
		fwrite(szTmp, 24, 1, pOutf);
		mCurInfPos += 24;

		fread(&m0doffset, 4, 1, pInf);
		iTmp = m0doffset + mAddOffest;
		fwrite(&iTmp, 4, 1, pOutf);
		mCurInfPos += 4;
	}

	iTmp = mbaseaddr + m0boffset - mCurInfPos;
	char *pdata = new char[iTmp + 1];
	fread(pdata, iTmp, 1, pInf);
	fwrite(pdata, iTmp, 1, pOutf);
	delete[]pdata;
	mCurInfPos += iTmp;

	int strlistlen = 0;
	int strlen = 0;
	fread(&strlistlen, 4, 1, pInf);
	fwrite(&strlistlen, 4, 1, pOutf);
	mCurInfPos += 4;
	for (int i = 0; i < strlistlen; ++i)  //读取包名
	{
		fread(&strlen, 4, 1, pInf);
		fwrite(&strlen, 4, 1, pOutf);
		mCurInfPos += 4;
		strlen = calc_align(strlen, 4);
		fread(szTmp, strlen, 1, pInf);
		fwrite(szTmp, strlen, 1, pOutf);
		mCurInfPos += strlen;
	}

	//fseek(pInf, 4, SEEK_CUR);
	fread(&iTmp, 4, 1, pInf);
	fwrite(&iTmp, 4, 1, pOutf);
	mCurInfPos += 4;
	for (int i = 0; i < iTmp; ++i)
	{
		fread(&strlen, 4, 1, pInf);
		fwrite(&strlen, 4, 1, pOutf);
		mCurInfPos += 4;
		strlen = calc_align(strlen, 4);
		fread(szTmp, strlen, 1, pInf);
		fwrite(szTmp, strlen, 1, pOutf);
		mCurInfPos += strlen;
	}
	fread(&mrendercount, 4, 1, pInf);
	mCurInfPos += 4;
	mrendercount += 1;
	fwrite(&mrendercount, 4, 1, pOutf);
	iTmp = 9;
	fwrite(&iTmp, 4, 1, pOutf);
	memset(mrendername, 0, 13);
	memcpy(mrendername, "cardboard", 9);
	fwrite(mrendername, 12, 1, pOutf);

	while ((iTmp = fread(szTmp, 1, 1024, pInf)) != 0)
	{
		fwrite(szTmp, 1, iTmp, pOutf);
	}

	fclose(pInf);
	fclose(pOutf);
	return;
}

void UnityConfigFile::createCfg()
{
	//FILE* pInf = fopen("globalgamemanagers", "rb+");

}