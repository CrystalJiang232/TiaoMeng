#include "metrics.hpp"

void ServerMetrics::print() const
{
    std::println("{}",*this);
}