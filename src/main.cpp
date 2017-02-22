#include <iostream>
#include "CTest.h"
#include "windows.h"
#include <sys/types.h>
#include <unistd.h>

int main() {
    CTest a;
    MessageBox(NULL, "hello", "caption", MB_OK);
    std::cout << "Hello, World!" << std::endl;
    pid_t pid = getpid();
    depth_1();
    return 0;
}