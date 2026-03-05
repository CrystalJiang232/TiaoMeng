#include "iocore/platform/thread_affinity.hpp"

#include <windows.h>

namespace iocore::platform
{

void pin_to_core(size_t core_id)
{
    SetThreadAffinityMask(GetCurrentThread(), 1ULL << core_id);
}

void set_thread_name(const char* name)
{
    // Windows thread naming uses exceptions
    // This is a simplified version
    (void)name;
}

} // namespace iocore::platform
