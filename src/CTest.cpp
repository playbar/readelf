//
// Created by houguoli on 2017/2/10.
//

#include "CTest.h"

void depth_2_1()
{
    printf("inside depth_2_1\n");
}

void depth_2_2()
{
    fprintf(stderr, "inside depth_2_2\n");
}

void depth_1()
{
    depth_2_1();
    depth_2_2();
    printf("inside depth_1\n");
}

