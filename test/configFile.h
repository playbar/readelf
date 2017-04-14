//
// Created by houguoli on 2017/2/20.
//

#ifndef CLIONPRO_UNITYCONFIGFILE_H
#define CLIONPRO_UNITYCONFIGFILE_H


class UnityConfigFile {
public:
    UnityConfigFile();
    ~UnityConfigFile();

    void changeDaydreamToCardboard(char *pInFile, char *pOutFile);
	void addCardboardInDaydream(char *pInFile, char *pOutFile);
	void addCardInDay5_4(FILE *pInf, FILE *pOutf);
	void addCardInDay5_6(FILE *pInf, FILE *pOutf);
	int getModifyFileLen(FILE *pInf);
	void createCfg();
private:
	long mCurInfPos;
	long mVersoin;
	//long mCurOutfPos;
    long mfilelen;
    long mbaseaddr;
	long m0Boffset;
	long m0Blen;
	bool mbadd4;
	bool mbadd8;
	long mAddOffest;
	long m0Coffset;
	long m0Doffset;
	int mrendercount;
	int mrenderlen;
	char mrendername[13];

};


#endif //CLIONPRO_UNITYCONFIGFILE_H
