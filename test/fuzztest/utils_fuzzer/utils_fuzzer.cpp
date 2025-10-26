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
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {

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
    if (fdp.remaining_bytes() < 8) {
        return false;
    }

    // Test with various pointer types and alignments
    int testCase = fdp.ConsumeIntegralInRange<int>(0, 9);

    switch (testCase) {
        case 0: {
            // Stack allocated integer
            int stackVar = fdp.ConsumeIntegral<int>();
            uint64_t tag = GetAddrTag(&stackVar);
            (void)tag;
            break;
        }
        case 1: {
            // Stack allocated array
            char buffer[256];
            memset(buffer, 0, sizeof(buffer));
            uint64_t tag = GetAddrTag(buffer);
            (void)tag;
            break;
        }
        case 2: {
            // Heap allocated memory
            void* heapPtr = malloc(fdp.ConsumeIntegralInRange<size_t>(1, 1024));
            if (heapPtr) {
                uint64_t tag = GetAddrTag(heapPtr);
                (void)tag;
                free(heapPtr);
            }
            break;
        }
        case 3: {
            // Aligned memory
            void* alignedPtr = nullptr;
            size_t alignment = fdp.PickValueInArray({1, 2, 4, 8, 16, 32, 64, 128, 256});
            size_t size = fdp.ConsumeIntegralInRange<size_t>(1, 512);
            if (posix_memalign(&alignedPtr, alignment, size) == 0 && alignedPtr) {
                uint64_t tag = GetAddrTag(alignedPtr);
                (void)tag;
                free(alignedPtr);
            }
            break;
        }
        case 4: {
            // Pointer to struct
            struct TestStruct {
                int a;
                long b;
                char c[100];
            };
            TestStruct ts;
            ts.a = fdp.ConsumeIntegral<int>();
            uint64_t tag = GetAddrTag(&ts);
            (void)tag;
            break;
        }
        case 5: {
            // Pointer offset within array
            char largeBuffer[1024];
            size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, 1000);
            uint64_t tag = GetAddrTag(&largeBuffer[offset]);
            (void)tag;
            break;
        }
        case 6: {
            // Function pointer (should still work)
            void (*funcPtr)(void) = reinterpret_cast<void(*)(void)>(GetAddrTag);
            uint64_t tag = GetAddrTag(reinterpret_cast<void*>(funcPtr));
            (void)tag;
            break;
        }
        case 7: {
            // Random unaligned pointer
            char buffer[256];
            size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, 255);
            uint64_t tag = GetAddrTag(&buffer[offset]);
            (void)tag;
            break;
        }
        case 8: {
            // Very large allocation
            size_t largeSize = fdp.ConsumeIntegralInRange<size_t>(1024, 1024 * 1024);
            void* largePtr = malloc(largeSize);
            if (largePtr) {
                uint64_t tag = GetAddrTag(largePtr);
                (void)tag;
                free(largePtr);
            }
            break;
        }
        case 9: {
            // Pointer to dynamically allocated array
            std::vector<int> vec(fdp.ConsumeIntegralInRange<size_t>(1, 100));
            uint64_t tag = GetAddrTag(vec.data());
            (void)tag;
            break;
        }
    }

    return true;
}

// Fuzz GetAddrTag with same pointer multiple times
bool FuzzGetAddrTagRepeated(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 4) {
        return false;
    }

    int buffer[10];
    memset(buffer, 0, sizeof(buffer));

    // Call GetAddrTag multiple times with same pointer
    int numCalls = fdp.ConsumeIntegralInRange<int>(1, 100);
    for (int i = 0; i < numCalls; i++) {
        uint64_t tag = GetAddrTag(buffer);
        (void)tag;
    }

    return true;
}

// Fuzz GetAddrTag with different pointers to same object
bool FuzzGetAddrTagDifferentPtrs(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 4) {
        return false;
    }

    struct TestData {
        int a;
        int b;
        int c;
        char d[100];
    };

    TestData data;
    memset(&data, 0, sizeof(data));

    // Get tags for different offsets into the same object
    uint64_t tag1 = GetAddrTag(&data);
    uint64_t tag2 = GetAddrTag(&data.a);
    uint64_t tag3 = GetAddrTag(&data.b);
    uint64_t tag4 = GetAddrTag(&data.c);
    uint64_t tag5 = GetAddrTag(&data.d[0]);
    uint64_t tag6 = GetAddrTag(&data.d[50]);

    (void)tag1; (void)tag2; (void)tag3; (void)tag4; (void)tag5; (void)tag6;

    return true;
}

// Fuzz with random memory patterns
bool FuzzGetAddrTagRandomMemory(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 8) {
        return false;
    }

    size_t size = fdp.ConsumeIntegralInRange<size_t>(1, 4096);
    std::vector<uint8_t> buffer(size);

    // Fill with random data
    for (size_t i = 0; i < size && fdp.remaining_bytes() > 0; i++) {
        buffer[i] = fdp.ConsumeIntegral<uint8_t>();
    }

    // Get tag for the buffer
    uint64_t tag = GetAddrTag(buffer.data());
    (void)tag;

    // Get tags for random offsets
    int numOffsets = fdp.ConsumeIntegralInRange<int>(1, 10);
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
    int safeVar = 42;
    uint64_t tag2 = GetAddrTag(&safeVar);
    (void)tag2;

    return true;
}

// Stress test - call GetAddrTag many times rapidly
bool FuzzGetAddrTagStress(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 4) {
        return false;
    }

    int numIterations = fdp.ConsumeIntegralInRange<int>(100, 1000);

    for (int i = 0; i < numIterations; i++) {
        int stackVar = i;
        uint64_t tag = GetAddrTag(&stackVar);
        (void)tag;

        if (i % 10 == 0 && fdp.remaining_bytes() > 0) {
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
    if (size < 4) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Randomly choose which fuzzing function to execute
    int choice = fdp.ConsumeIntegralInRange<int>(0, 6);

    switch (choice) {
        case 0:
            OHOS::FuzzGetAddrTagNull(fdp);
            break;
        case 1:
            OHOS::FuzzGetAddrTagValid(fdp);
            break;
        case 2:
            OHOS::FuzzGetAddrTagRepeated(fdp);
            break;
        case 3:
            OHOS::FuzzGetAddrTagDifferentPtrs(fdp);
            break;
        case 4:
            OHOS::FuzzGetAddrTagRandomMemory(fdp);
            break;
        case 5:
            OHOS::FuzzGetAddrTagExtremeValues(fdp);
            break;
        case 6:
            OHOS::FuzzGetAddrTagStress(fdp);
            break;
    }

    return 0;
}
