#pragma once
#include <stdexcept>

class OperationCancelledException : public std::runtime_error {
public:
    OperationCancelledException() : std::runtime_error("Operation cancelled by user intercept.") {}
};