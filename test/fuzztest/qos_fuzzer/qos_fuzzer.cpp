/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <functional>
#include <unordered_map>
#include <unistd.h>
#include <sys/types.h>
#include "concurrent_task_service.h"
#include "securec.h"
#include "qos.h"
#include "qos_interface.h"
#include "qos_policy.h"
#include "system_ability_definition.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::ConcurrentTask;
using namespace OHOS::QOS;

namespace OHOS {
static std::mutex onStopMutex_;
#define  QUADRUPLE  4
#define  LEN 4

namespace {
constexpr size_t FUZZER_MIN_INPUT_SIZE = 8;
constexpr uint8_t FUZZER_SELECTOR_RANGE = 10;
constexpr size_t QOS_LEVEL_APIS_SIZE = 8;
constexpr size_t C_API_QOS_SIZE = 2;
constexpr uint8_t QOS_LEVEL_MAX = 8;

enum QosManagerTestCase : uint8_t {
    TEST_CASE_QOS_LEVEL_MANAGEMENT = 0,
    TEST_CASE_C_API_QOS = 1,
    TEST_CASE_EDGE_CASES = 6,
    TEST_CASE_COMPREHENSIVE = 7
};

template <typename T>
T SafeExtractInt(const uint8_t *data, size_t size, size_t *offset)
{
    if (*offset + sizeof(T) > size) {
        *offset = size;
        return T{};
    }
    T value{};
    if (memcpy_s(&value, sizeof(T), data + *offset, sizeof(T)) != 0) {
        *offset = size;
        return T{};
    }
    *offset += sizeof(T);
    return value;
}

QosLevel SafeExtractQosLevel(const uint8_t* data, size_t size, size_t* offset)
{
    if (*offset >= size) {
        return static_cast<QosLevel>(0);
    }
    uint8_t levelByte = data[(*offset)++];
    return static_cast<QosLevel>(levelByte % QOS_LEVEL_MAX);
}

QosLevel SafeExtractQosLevelC(const uint8_t* data, size_t size, size_t* offset)
{
    if (*offset >= size) {
        return static_cast<QosLevel>(0);
    }
    uint8_t levelByte = data[(*offset)++];
    return static_cast<QosLevel>(levelByte % QOS_LEVEL_MAX);
}

void TestQosLevelApis(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset >= size) {
        return;
    }

    QosLevel level1 = SafeExtractQosLevel(data, size, &offset);
    QosLevel level2 = SafeExtractQosLevel(data, size, &offset);
    int tid = SafeExtractInt<int>(data, size, &offset);

    SetThreadQos(level1);

    QosLevel retrievedLevel = static_cast<QosLevel>(0);
    GetThreadQos(retrievedLevel);

    if (tid != 0) {
        SetQosForOtherThread(level2, tid);
        QosLevel retrievedOther = static_cast<QosLevel>(0);
        GetQosForOtherThread(retrievedOther, tid);
    }

    int currentTid = gettid();
    if (currentTid > 0) {
        SetQosForOtherThread(level2, currentTid);
        QosLevel tempLevel = static_cast<QosLevel>(0);
        GetQosForOtherThread(tempLevel, currentTid);
    }

    ResetQosForOtherThread(tid);
    ResetThreadQos();
}

void TestCApiQosManagement(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset >= size) {
        return;
    }

    QosLevel level = SafeExtractQosLevelC(data, size, &offset);
    SetThreadQos(level);

    QosLevel currentLevel = static_cast<QosLevel>(0);
    GetThreadQos(currentLevel);

    ResetThreadQos();
}

void TestQosTransitions(const uint8_t* data, size_t size, size_t& offset)
{
    QosLevel levels[] = {
        static_cast<QosLevel>(0),
        static_cast<QosLevel>(3),
        static_cast<QosLevel>(7)
    };

    for (auto level : levels) {
        SetThreadQos(level);
        QosLevel current = static_cast<QosLevel>(0);
        GetThreadQos(current);
    }

    if (offset < size) {
        int tid = SafeExtractInt<int>(data, size, &offset);
        if (tid > 0) {
            QosLevel level = SafeExtractQosLevel(data, size, &offset);
            SetQosForOtherThread(level, tid);
            QosLevel retrieved = static_cast<QosLevel>(0);
            GetQosForOtherThread(retrieved, tid);
            ResetQosForOtherThread(tid);
        }
    }
}

using QosTestHandler = std::function<void(const uint8_t*, size_t, size_t&)>;

const std::unordered_map<uint8_t, QosTestHandler> G_QOS_CASE_HANDLERS = {
    { TEST_CASE_QOS_LEVEL_MANAGEMENT, [](const uint8_t* data, size_t size, size_t& offset) {
        if (offset + QOS_LEVEL_APIS_SIZE <= size) {
            TestQosLevelApis(data, size, offset);
        }
    } },
    { TEST_CASE_C_API_QOS, [](const uint8_t* data, size_t size, size_t& offset) {
        if (offset + C_API_QOS_SIZE <= size) {
            TestCApiQosManagement(data, size, offset);
        }
    } },
    { TEST_CASE_EDGE_CASES, [](const uint8_t* data, size_t size, size_t& offset) {
        TestQosTransitions(data, size, offset);
    } },
    { TEST_CASE_COMPREHENSIVE, [](const uint8_t* data, size_t size, size_t& offset) {
        if (offset + QOS_LEVEL_APIS_SIZE <= size) {
            TestQosLevelApis(data, size, offset);
        }
        TestQosTransitions(data, size, offset);
    } }
};

void DispatchQosTestCase(const uint8_t* data, size_t size, size_t& offset, uint8_t selector)
{
    auto handler = G_QOS_CASE_HANDLERS.find(selector);
    if (handler != G_QOS_CASE_HANDLERS.end()) {
        handler->second(data, size, offset);
        return;
    }
    G_QOS_CASE_HANDLERS.at(TEST_CASE_COMPREHENSIVE)(data, size, offset);
}

    constexpr int TEST_DATA_FIRST = 1;
    constexpr int TEST_DATA_SECOND = 2;
    constexpr int TEST_DATA_THIRD = 3;
    constexpr int TEST_DATA_FOURTH = 4;
    constexpr int TEST_DATA_FIFTH = 5;
    constexpr int TEST_DATA_SIXTH = 6;
    constexpr int TEST_DATA_SEVENTH = 7;
    constexpr int TEST_DATA_EIGHTH = 8;
    constexpr int TEST_DATA_TENTH = 10;
}


bool FuzzQosControllerGetThreadQosForOtherThread(FuzzedDataProvider &fdp)
{
    enum QosLevel level;
    int tid = fdp.ConsumeIntegral<int>();
    QosController::GetInstance().GetThreadQosForOtherThread(level, tid);
    return true;
}

bool FuzzQosInterfaceQosLeave(FuzzedDataProvider &fdp)
{
    int level = fdp.ConsumeIntegral<int>();
    level = level % TEST_DATA_TENTH;
    if (level == TEST_DATA_FIFTH || level == TEST_DATA_SECOND) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_BACKGROUND);
    } else if (level == TEST_DATA_THIRD || level == TEST_DATA_FOURTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_UTILITY);
    } else if (level == TEST_DATA_FIFTH || level == TEST_DATA_SIXTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_DEFAULT);
    } else if (level == TEST_DATA_SEVENTH || level == TEST_DATA_EIGHTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_USER_INITIATED);
    }
    QosLeave();
    return true;
}

bool FuzzQosResetThreadQos(FuzzedDataProvider &fdp)
{
    int level = fdp.ConsumeIntegral<int>();
    level = level % TEST_DATA_TENTH;
    if (level == TEST_DATA_FIFTH || level == TEST_DATA_SECOND) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_BACKGROUND);
    } else if (level == TEST_DATA_THIRD || level == TEST_DATA_FOURTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_UTILITY);
    } else if (level == TEST_DATA_FIFTH || level == TEST_DATA_SIXTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_DEFAULT);
    } else if (level == TEST_DATA_SEVENTH || level == TEST_DATA_EIGHTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_USER_INITIATED);
    }
    QOS::ResetThreadQos();
    
    return true;
}

bool FuzzQosSetQosForOtherThread(FuzzedDataProvider &fdp)
{
    int level = fdp.ConsumeIntegral<int>();
    int tid = fdp.ConsumeIntegral<int>();
    level = level % TEST_DATA_TENTH;
    if (level == TEST_DATA_FIRST || level == TEST_DATA_SECOND) {
        QOS::SetQosForOtherThread(QOS::QosLevel::QOS_BACKGROUND, tid);
    } else if (level == TEST_DATA_THIRD || level == TEST_DATA_FOURTH) {
        QOS::SetQosForOtherThread(QOS::QosLevel::QOS_UTILITY, tid);
    } else if (level == TEST_DATA_FIFTH || level == TEST_DATA_SIXTH) {
        QOS::SetQosForOtherThread(QOS::QosLevel::QOS_DEFAULT, tid);
    } else if (level == TEST_DATA_SEVENTH || level == TEST_DATA_EIGHTH) {
        QOS::SetQosForOtherThread(QOS::QosLevel::QOS_USER_INITIATED, tid);
    }
    return true;
}

bool FuzzQosSetThreadQos(FuzzedDataProvider &fdp)
{
    int level = fdp.ConsumeIntegral<int>();
    level = level % TEST_DATA_TENTH;
    if (level == TEST_DATA_FIFTH || level == TEST_DATA_SECOND) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_BACKGROUND);
    } else if (level == TEST_DATA_THIRD || level == TEST_DATA_FOURTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_UTILITY);
    } else if (level == TEST_DATA_FIFTH || level == TEST_DATA_SIXTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_DEFAULT);
    } else if (level == TEST_DATA_SEVENTH || level == TEST_DATA_EIGHTH) {
        QOS::SetThreadQos(QOS::QosLevel::QOS_USER_INITIATED);
    }
    return true;
}

void RunQosManagerFuzzCases(const uint8_t* data, size_t size)
{
    if (size < FUZZER_MIN_INPUT_SIZE) {
        return;
    }
    size_t offset = 0;
    uint8_t selector = data[offset++] % FUZZER_SELECTOR_RANGE;
    DispatchQosTestCase(data, size, offset, selector);
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::FuzzQosControllerGetThreadQosForOtherThread(fdp);
    OHOS::FuzzQosInterfaceQosLeave(fdp);
    OHOS::FuzzQosResetThreadQos(fdp);
    OHOS::FuzzQosSetQosForOtherThread(fdp);
    OHOS::FuzzQosSetThreadQos(fdp);
    OHOS::RunQosManagerFuzzCases(data, size);
    return 0;
}
