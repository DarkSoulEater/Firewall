#pragma once

#include <cstddef>
#include <cassert>
#include <stdlib.h>

class Buffer {
  public:
    Buffer(size_t capacity) : data_(new char[capacity]), capacity_(data_ == nullptr ? 0 : capacity), size_(0) { assert(data_ != nullptr && "Buffer not allocate"); }
    Buffer(Buffer&& data) {
        data_ = data.data_;
        size_ = data.size_;
        capacity_ = data.capacity_;
        data.data_ = nullptr;
    }
    ~Buffer() { if (data_ != nullptr) { delete[] data_; }}

    char* Data() { return data_; }
    size_t Capacity() { return capacity_; }
    void SetSize(size_t size) { size_ = size; }
    size_t Size() { return size_; }

  private:
    char* data_;
    size_t size_;
    size_t capacity_;
};