//
// Created by houguoli on 2017/2/20.
//

#include <iostream>
#include "configFile.h"

int main(int argc, char **argv)
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