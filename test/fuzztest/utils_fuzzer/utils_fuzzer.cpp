/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include "concurrent_task_utils.h"
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {

namespace {
constexpr size_t MIN_FUZZ_INPUT_SIZE = 4;
constexpr size_t MIN_REQUIRED_BYTES = 4;
constexpr size_t MIN_COMPLEX_CASE_BYTES = 8;
constexpr size_t MIN_RANDOM_MEMORY_BYTES = 8;
constexpr size_t STACK_BUFFER_SIZE = 256;
constexpr size_t STACK_BUFFER_MAX_OFFSET = STACK_BUFFER_SIZE - 1;
constexpr size_t HEAP_MAX_ALLOC_SIZE = 1024;
constexpr size_t ALIGNED_ALLOC_MAX_SIZE = 512;
constexpr size_t LARGE_BUFFER_SIZE = 1024;
constexpr size_t LARGE_BUFFER_OFFSET_MAX = 1000;
constexpr size_t LARGE_ALLOCATION_MIN_SIZE = 1024;
constexpr size_t LARGE_ALLOCATION_MAX_SIZE = 1024 * 1024;
constexpr size_t STRUCT_CHAR_ARRAY_SIZE = 100;
constexpr size_t STRUCT_CHAR_MID_INDEX = STRUCT_CHAR_ARRAY_SIZE / 2;
constexpr size_t VECTOR_MAX_ELEMENTS = 100;
constexpr size_t INT_BUFFER_SIZE = 10;
constexpr size_t RANDOM_MEMORY_MAX_SIZE = 4096;
constexpr int RANDOM_OFFSET_COUNT_MAX = 10;
constexpr int REPEAT_CALLS_MIN = 1;
constexpr int REPEAT_CALLS_MAX = 100;
constexpr int STRESS_ITERATION_MIN = 100;
constexpr int STRESS_ITERATION_MAX = 1000;
constexpr int HEAP_ALLOCATION_INTERVAL = 10;
constexpr int SAFE_STACK_VALUE = 42;
constexpr size_t ALIGNMENT_OPTIONS[] = {1, 2, 4, 8, 16, 32, 64, 128, STACK_BUFFER_SIZE};
enum class UtilsPointerCase : int {
    STACK_INT = 0,
    STACK_ARRAY,
    HEAP_ALLOC,
    ALIGNED_ALLOC,
    STRUCT_POINTER,
    ARRAY_OFFSET,
    FUNCTION_POINTER,
    RANDOM_UNALIGNED,
    LARGE_ALLOCATION,
    VECTOR_DATA
};

enum class UtilsFuzzChoice : int {
    NULL_INPUT = 0,
    VALID_POINTERS,
    REPEATED_CALLS,
    DIFFERENT_POINTERS,
    RANDOM_MEMORY,
    EXTREME_VALUES,
    STRESS_TEST
};

constexpr int MAX_FUZZ_TARGET_INDEX = static_cast<int>(UtilsFuzzChoice::STRESS_TEST);

inline bool SecureClear(void* buffer, size_t size)
{
    return memset_s(buffer, size, 0, size) == EOK;
}

bool HandleStackIntCase(FuzzedDataProvider &fdp)
{
    int stackVar = fdp.ConsumeIntegral<int>();
    uint64_t tag = GetAddrTag(&stackVar);
    (void)tag;
    return true;
}

bool HandleStackArrayCase()
{
    char buffer[STACK_BUFFER_SIZE];
    if (!SecureClear(buffer, sizeof(buffer))) {
        return false;
    }
    uint64_t tag = GetAddrTag(buffer);
    (void)tag;
    return true;
}

bool HandleHeapAllocationCase(FuzzedDataProvider &fdp)
{
    void* heapPtr = malloc(fdp.ConsumeIntegralInRange<size_t>(1, HEAP_MAX_ALLOC_SIZE));
    if (!heapPtr) {
        return true;
    }
    uint64_t tag = GetAddrTag(heapPtr);
    (void)tag;
    free(heapPtr);
    return true;
}

bool HandleAlignedAllocationCase(FuzzedDataProvider &fdp)
{
    void* alignedPtr = nullptr;
    size_t alignment = fdp.PickValueInArray(ALIGNMENT_OPTIONS);
    size_t size = fdp.ConsumeIntegralInRange<size_t>(1, ALIGNED_ALLOC_MAX_SIZE);
    if (posix_memalign(&alignedPtr, alignment, size) != 0 || alignedPtr == nullptr) {
        return true;
    }
    uint64_t tag = GetAddrTag(alignedPtr);
    (void)tag;
    free(alignedPtr);
    return true;
}

bool HandleStructPointerCase(FuzzedDataProvider &fdp)
{
    struct TestStruct {
        int a;
        long b;
        char c[STRUCT_CHAR_ARRAY_SIZE];
    };
    TestStruct ts;
    ts.a = fdp.ConsumeIntegral<int>();
    uint64_t tag = GetAddrTag(&ts);
    (void)tag;
    return true;
}

bool HandleArrayOffsetCase(FuzzedDataProvider &fdp)
{
    char largeBuffer[LARGE_BUFFER_SIZE];
    size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, LARGE_BUFFER_OFFSET_MAX);
    uint64_t tag = GetAddrTag(&largeBuffer[offset]);
    (void)tag;
    return true;
}

bool HandleFunctionPointerCase()
{
    void (*funcPtr)(void) = reinterpret_cast<void(*)(void)>(GetAddrTag);
    uint64_t tag = GetAddrTag(reinterpret_cast<void*>(funcPtr));
    (void)tag;
    return true;
}

bool HandleRandomUnalignedCase(FuzzedDataProvider &fdp)
{
    char buffer[STACK_BUFFER_SIZE];
    size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, STACK_BUFFER_MAX_OFFSET);
    uint64_t tag = GetAddrTag(&buffer[offset]);
    (void)tag;
    return true;
}

bool HandleLargeAllocationCase(FuzzedDataProvider &fdp)
{
    size_t largeSize = fdp.ConsumeIntegralInRange<size_t>(LARGE_ALLOCATION_MIN_SIZE, LARGE_ALLOCATION_MAX_SIZE);
    void* largePtr = malloc(largeSize);
    if (!largePtr) {
        return true;
    }
    uint64_t tag = GetAddrTag(largePtr);
    (void)tag;
    free(largePtr);
    return true;
}

bool HandleVectorDataCase(FuzzedDataProvider &fdp)
{
    std::vector<int> vec(fdp.ConsumeIntegralInRange<size_t>(1, VECTOR_MAX_ELEMENTS));
    uint64_t tag = GetAddrTag(vec.data());
    (void)tag;
    return true;
}

bool HandlePointerCase(UtilsPointerCase testCase, FuzzedDataProvider &fdp)
{
    switch (testCase) {
        case UtilsPointerCase::STACK_INT:
            return HandleStackIntCase(fdp);
        case UtilsPointerCase::STACK_ARRAY:
            return HandleStackArrayCase();
        case UtilsPointerCase::HEAP_ALLOC:
            return HandleHeapAllocationCase(fdp);
        case UtilsPointerCase::ALIGNED_ALLOC:
            return HandleAlignedAllocationCase(fdp);
        case UtilsPointerCase::STRUCT_POINTER:
            return HandleStructPointerCase(fdp);
        case UtilsPointerCase::ARRAY_OFFSET:
            return HandleArrayOffsetCase(fdp);
        case UtilsPointerCase::FUNCTION_POINTER:
            return HandleFunctionPointerCase();
        case UtilsPointerCase::RANDOM_UNALIGNED:
            return HandleRandomUnalignedCase(fdp);
        case UtilsPointerCase::LARGE_ALLOCATION:
            return HandleLargeAllocationCase(fdp);
        case UtilsPointerCase::VECTOR_DATA:
            return HandleVectorDataCase(fdp);
        default:
            return true;
    }
}
}

// Fuzz GetAddrTag with nullptr
bool FuzzGetAddrTagNull(FuzzedDataProvider &fdp)
{
    uint64_t tag = GetAddrTag(nullptr);
    // According to implementation, should return 0 for nullptr
    (void)tag; // Use the value to prevent optimization
    return true;
}

// Fuzz GetAddrTag with valid pointers
bool FuzzGetAddrTagValid(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_COMPLEX_CASE_BYTES) {
        return false;
    }

    auto testCase = static_cast<UtilsPointerCase>(fdp.ConsumeIntegralInRange<int>(
        0, static_cast<int>(UtilsPointerCase::VECTOR_DATA)));
    return HandlePointerCase(testCase, fdp);
}

// Fuzz GetAddrTag with same pointer multiple times
bool FuzzGetAddrTagRepeated(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_REQUIRED_BYTES) {
        return false;
    }

    int buffer[INT_BUFFER_SIZE];
    if (!SecureClear(buffer, sizeof(buffer))) {
        return false;
    }

    // Call GetAddrTag multiple times with same pointer
    int numCalls = fdp.ConsumeIntegralInRange<int>(REPEAT_CALLS_MIN, REPEAT_CALLS_MAX);
    for (int i = 0; i < numCalls; i++) {
        uint64_t tag = GetAddrTag(buffer);
        (void)tag;
    }

    return true;
}

// Fuzz GetAddrTag with different pointers to same object
bool FuzzGetAddrTagDifferentPtrs(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_REQUIRED_BYTES) {
        return false;
    }

    struct TestData {
        int a;
        int b;
        int c;
        char d[STRUCT_CHAR_ARRAY_SIZE];
    };

    TestData data;
    if (!SecureClear(&data, sizeof(data))) {
        return false;
    }

    // Get tags for different offsets into the same object
    uint64_t tag1 = GetAddrTag(&data);
    uint64_t tag2 = GetAddrTag(&data.a);
    uint64_t tag3 = GetAddrTag(&data.b);
    uint64_t tag4 = GetAddrTag(&data.c);
    uint64_t tag5 = GetAddrTag(&data.d[0]);
    uint64_t tag6 = GetAddrTag(&data.d[STRUCT_CHAR_MID_INDEX]);

    (void)tag1;
    (void)tag2;
    (void)tag3;
    (void)tag4;
    (void)tag5;
    (void)tag6;

    return true;
}

// Fuzz with random memory patterns
bool FuzzGetAddrTagRandomMemory(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_RANDOM_MEMORY_BYTES) {
        return false;
    }

    size_t size = fdp.ConsumeIntegralInRange<size_t>(1, RANDOM_MEMORY_MAX_SIZE);
    std::vector<uint8_t> buffer(size);

    // Fill with random data
    for (size_t i = 0; i < size && fdp.remaining_bytes() > 0; i++) {
        buffer[i] = fdp.ConsumeIntegral<uint8_t>();
    }

    // Get tag for the buffer
    uint64_t tag = GetAddrTag(buffer.data());
    (void)tag;

    // Get tags for random offsets
    int numOffsets = fdp.ConsumeIntegralInRange<int>(1, RANDOM_OFFSET_COUNT_MAX);
    for (int i = 0; i < numOffsets && fdp.remaining_bytes() > 0; i++) {
        size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, size - 1);
        uint64_t offsetTag = GetAddrTag(&buffer[offset]);
        (void)offsetTag;
    }

    return true;
}

// Fuzz with extreme pointer values (careful - may segfault if not handled)
bool FuzzGetAddrTagExtremeValues(FuzzedDataProvider &fdp)
{
    // This test is intentionally conservative to avoid segfaults
    // We only test nullptr which is safe
    uint64_t tag = GetAddrTag(nullptr);
    (void)tag;

    // Test with stack variable (safe)
    int safeVar = SAFE_STACK_VALUE;
    uint64_t tag2 = GetAddrTag(&safeVar);
    (void)tag2;

    return true;
}

// Stress test - call GetAddrTag many times rapidly
bool FuzzGetAddrTagStress(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_REQUIRED_BYTES) {
        return false;
    }

    int numIterations = fdp.ConsumeIntegralInRange<int>(STRESS_ITERATION_MIN, STRESS_ITERATION_MAX);

    for (int i = 0; i < numIterations; i++) {
        int stackVar = i;
        uint64_t tag = GetAddrTag(&stackVar);
        (void)tag;

        if ((i % HEAP_ALLOCATION_INTERVAL) == 0 && fdp.remaining_bytes() > 0) {
            void* heapVar = malloc(sizeof(int));
            if (heapVar) {
                uint64_t heapTag = GetAddrTag(heapVar);
                (void)heapTag;
                free(heapVar);
            }
        }
    }

    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::MIN_FUZZ_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Randomly choose which fuzzing function to execute
    auto choice = static_cast<OHOS::UtilsFuzzChoice>(fdp.ConsumeIntegralInRange<int>(
        0, OHOS::MAX_FUZZ_TARGET_INDEX));

    switch (choice) {
        case OHOS::UtilsFuzzChoice::NULL_INPUT:
            OHOS::FuzzGetAddrTagNull(fdp);
            break;
        case OHOS::UtilsFuzzChoice::VALID_POINTERS:
            OHOS::FuzzGetAddrTagValid(fdp);
            break;
        case OHOS::UtilsFuzzChoice::REPEATED_CALLS:
            OHOS::FuzzGetAddrTagRepeated(fdp);
            break;
        case OHOS::UtilsFuzzChoice::DIFFERENT_POINTERS:
            OHOS::FuzzGetAddrTagDifferentPtrs(fdp);
            break;
        case OHOS::UtilsFuzzChoice::RANDOM_MEMORY:
            OHOS::FuzzGetAddrTagRandomMemory(fdp);
            break;
        case OHOS::UtilsFuzzChoice::EXTREME_VALUES:
            OHOS::FuzzGetAddrTagExtremeValues(fdp);
            break;
        case OHOS::UtilsFuzzChoice::STRESS_TEST:
            OHOS::FuzzGetAddrTagStress(fdp);
            break;
        default:
            break;
    }

    return 0;
}
