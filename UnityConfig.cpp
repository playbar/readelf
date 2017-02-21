//
// Created by houguoli on 2017/2/20.
//

#include <iostream>
#include "UnityConfigFile.h"

int main(int argc, char **argv) {
    UnityConfigFile cfgFile;
    cfgFile.createCfgFile();
    std::cout << "Hello, World!" << std::endl;
    return 0;
}