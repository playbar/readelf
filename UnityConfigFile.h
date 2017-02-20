//
// Created by houguoli on 2017/2/20.
//

#ifndef CLIONPRO_UNITYCONFIGFILE_H
#define CLIONPRO_UNITYCONFIGFILE_H


class UnityConfigFile {
public:
    UnityConfigFile();
    ~UnityConfigFile();

    void readFile();
private:
    long mfilelong;
    long mbaseaddr;

};


#endif //CLIONPRO_UNITYCONFIGFILE_H
