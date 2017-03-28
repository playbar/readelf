#include <iostream>
#include "CTest.h"
#include "windows.h"
#include <sys/types.h>
#include <unistd.h>
#include <map>

void testmap()
{
    map<person,int> m;
    person p1("Tom1",20);
    person p2("Tom2",22);
    person p3("Tom3",22);
    person p4("Tom4",23);
    person p5("Tom5",24);
    m.insert(make_pair(p3, 100));
    m.insert(make_pair(p4, 100));
    m.insert(make_pair(p5, 100));
    m.insert(make_pair(p1, 100));
    m.insert(make_pair(p2, 100));

    for(map<person, int>::iterator iter = m.begin(); iter != m.end(); iter++)
    {
        cout<<iter->first.name<<"\t"<<iter->first.age<<endl;
    }
    return;
}


int main() {
    testmap();
    CTest a;
    MessageBox(NULL, "hello", "caption", MB_OK);
    std::cout << "Hello, World!" << std::endl;
    pid_t pid = getpid();
    depth_1();
    return 0;
}