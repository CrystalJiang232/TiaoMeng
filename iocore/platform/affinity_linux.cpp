#include "iocore/platform/thread_affinity.hpp"

#include <pthread.h>
#include <sched.h>
#include <cstring>

namespace iocore::platform
{

void pin_to_core(size_t core_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

void set_thread_name(const char* name)
{
    pthread_setname_np(pthread_self(), name);
}

} // namespace iocore::platform
