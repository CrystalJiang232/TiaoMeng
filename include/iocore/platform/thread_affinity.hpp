#pragma once

#include <cstddef>

namespace iocore::platform
{

void pin_to_core(size_t core_id);
void set_thread_name(const char* name);

} // namespace iocore::platform
