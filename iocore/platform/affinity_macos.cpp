#include "iocore/platform/thread_affinity.hpp"

#include <pthread.h>
#include <pthread/qos.h>

namespace iocore::platform
{

void pin_to_core(size_t)
{
    // macOS does not support thread affinity pinning
    // Quality of Service is used instead
}

void set_thread_name(const char* name)
{
    pthread_setname_np(name);
}

} // namespace iocore::platform
