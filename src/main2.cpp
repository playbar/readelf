#include <iostream>
#include "CTest.h"
#include "windows.h"
#include <sys/types.h>
#include <unistd.h>


static pthread_key_t thread_log_key;

void write_to_thread_log (const char* message)
{
    FILE* thread_log = (FILE*)pthread_getspecific(thread_log_key);
    fprintf (thread_log, "%s\n", message);
}

void close_thread_log (void* thread_log)
{
    fclose ((FILE*) thread_log);
}

//const char *filename = "/data/data/com.mj.test/lib/libgvrimpl.so";

void* thread_function (void* args)
{
    char thread_log_filename[256];
    FILE* thread_log;
    pid_t pid = getpid();
    sprintf (thread_log_filename, "d:/thread-%d.log", (int)getpid());
    thread_log = fopen (thread_log_filename, "w");
    pthread_setspecific (thread_log_key, thread_log);
    write_to_thread_log ("Thread starting.");
    return nullptr;
}



#define THREAD_NUM 1
void createThread()
{
    int i;
    pthread_t threads[THREAD_NUM];
    pthread_key_create (&thread_log_key, close_thread_log);

    for (i = 0; i < THREAD_NUM; ++i)
        pthread_create (&(threads[i]), NULL, thread_function, NULL);

    for (i = 0; i < THREAD_NUM; ++i)
        pthread_join (threads[i], NULL);
    return;
}

int main() {
    createThread();
    depth_1();
    return 0;
}