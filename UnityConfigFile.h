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
	int getModifyFileLen(FILE *pInf);
	void createCfg();
private:
	long mCurInfPos;
	long mVersoin;
	//long mCurOutfPos;
    long mfilelen;
    long mbaseaddr;
	long m0boffset;
	long m0blen;
	bool mbadd4;
	bool mbadd8;
	long mAddOffest;
	long m0coffset;
	long m0doffset;
	//long m0eoffset;
	//long m0foffset;
	//long m10offset;
	//long m11offset;
	int mrendercount;
	int mrenderlen;
	char mrendername[13];

};


#endif //CLIONPRO_UNITYCONFIGFILE_H
