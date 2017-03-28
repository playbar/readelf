//
// Created by houguoli on 2017/2/10.
//

#ifndef CLIONTEST_AA_H
#define CLIONTEST_AA_H

#include <string>
#include "stdio.h"
using namespace std;

#ifdef __cplusplus
extern "C" {
#endif

void depth_2_1();
void depth_2_2();
void depth_1();

#ifdef __cplusplus
}
#endif

class CTest {
public:
    int a;
    int b;
};

struct person
{
    string name;
    int age;

    person(string name, int age)
    {
        this->name =  name;
        this->age = age;
    }

    bool operator < (const person& p) const
    {
        return this->age < p.age;
    }

    bool operator== (const person& p) const
    {
        return name==p.name && age==p.age;
    }
};

#endif //CLIONTEST_AA_H
