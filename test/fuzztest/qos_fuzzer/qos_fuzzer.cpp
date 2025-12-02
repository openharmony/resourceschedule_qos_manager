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
    constexpr int TEST_DATA_FIRST = 1;
    constexpr int TEST_DATA_SECOND = 2;
    constexpr int TEST_DATA_THIRD = 3;
    constexpr int TEST_DATA_FOURTH = 4;
    constexpr int TEST_DATA_FIFTH = 5;
    constexpr int TEST_DATA_SIXTH = 6;
    constexpr int TEST_DATA_SEVENTH = 7;
    constexpr int TEST_DATA_EIGHTH = 8;
    constexpr int TEST_DATA_TENTH = 10;

    constexpr QosLevel VALID_QOS_LEVELS[] = {
        QosLevel::QOS_BACKGROUND,
        QosLevel::QOS_UTILITY,
        QosLevel::QOS_DEFAULT,
        QosLevel::QOS_USER_INITIATED,
        QosLevel::QOS_DEADLINE_REQUEST,
        QosLevel::QOS_USER_INTERACTIVE
    };
    constexpr size_t VALID_QOS_COUNT = sizeof(VALID_QOS_LEVELS) / sizeof(VALID_QOS_LEVELS[0]);
    
    constexpr int INVALID_QOS_LEVELS[] = {
        -1, -100, 6, 7, 100, 255, INT_MIN, INT_MAX
    };
    constexpr size_t INVALID_QOS_COUNT = sizeof(INVALID_QOS_LEVELS) / sizeof(INVALID_QOS_LEVELS[0]);
}


static QosLevel GetValidQosLevel(FuzzedDataProvider &fdp)
{
    size_t index = fdp.ConsumeIntegralInRange<size_t>(0, VALID_QOS_COUNT - 1);
    return VALID_QOS_LEVELS[index];
}

static int GetPossiblyInvalidQosLevel(FuzzedDataProvider &fdp)
{
    if (fdp.ConsumeBool()) {
        return static_cast<int>(GetValidQosLevel(fdp));
    } else {
        size_t index = fdp.ConsumeIntegralInRange<size_t>(0, INVALID_QOS_COUNT - 1);
        return INVALID_QOS_LEVELS[index];
    }
}

static int GetThreadId(FuzzedDataProvider &fdp)
{
    constexpr int invalidTid1 = -1;
    constexpr int invalidTid2 = 0;
    constexpr int initProcessTid = 1;
    constexpr int threadTidMax = INT_MAX;
    constexpr int threadTidMin = INT_MIN;
    constexpr int threadTidMaxValid = 65535;

    enum ThreadIdChoice : uint8_t {
        CURRENT_THREAD = 0,
        INIT_PROCESS,
        INVALID_TID_NEG1,
        INVALID_TID_ZERO,
        MAX_TID,
        MIN_TID,
        RANDOM_VALID
    };

    uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);

    switch (choice) {
        case CURRENT_THREAD:
            return gettid();
        case INIT_PROCESS:
            return initProcessTid;
        case INVALID_TID_NEG1:
            return invalidTid1;
        case INVALID_TID_ZERO:
            return invalidTid2;
        case MAX_TID:
            return threadTidMax;
        case MIN_TID:
            return threadTidMin;
        default:
            return fdp.ConsumeIntegralInRange<int>(1, threadTidMaxValid);
    }
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

bool FuzzInvalidQosLevels(FuzzedDataProvider &fdp)
{
    int invalidLevel = GetPossiblyInvalidQosLevel(fdp);
    int tid = GetThreadId(fdp);
    
    QOS::SetQosForOtherThread(static_cast<QosLevel>(invalidLevel), tid);
    
    return true;
}

bool FuzzInvalidThreadIds(FuzzedDataProvider &fdp)
{
    QosLevel level = GetValidQosLevel(fdp);
    
    int invalidTids[] = {-1, 0, -100, INT_MIN, INT_MAX, 999999};
    for (int tid : invalidTids) {
        QOS::SetQosForOtherThread(level, tid);
        
        enum QosLevel outLevel;
        QosController::GetInstance().GetThreadQosForOtherThread(outLevel, tid);
    }
    
    return true;
}

bool FuzzQosStateTransitions(FuzzedDataProvider &fdp)
{
    QosLevel initialLevel = GetValidQosLevel(fdp);
    QOS::SetThreadQos(initialLevel);
    
    for (size_t i = 0; i < VALID_QOS_COUNT && fdp.remaining_bytes() > 0; i++) {
        QosLevel newLevel = GetValidQosLevel(fdp);
        QOS::SetThreadQos(newLevel);
        
        enum QosLevel currentLevel;
        QOS::GetThreadQos(currentLevel);
    }
    
    QOS::ResetThreadQos();
    
    return true;
}

bool FuzzDoubleOperations(FuzzedDataProvider &fdp)
{
    QosLevel level = GetValidQosLevel(fdp);
    
    QOS::SetThreadQos(level);
    QOS::SetThreadQos(level);
    
    QOS::ResetThreadQos();
    QOS::ResetThreadQos();
    
    QOS::SetThreadQos(level);
    QosLeave();
    QosLeave();
    
    return true;
}

bool FuzzUninitializedState(FuzzedDataProvider &fdp)
{
    enum QosLevel level;

    QOS::GetThreadQos(level);
    QOS::ResetThreadQos();
    QosLeave();
    
    return true;
}

bool FuzzResourceLeak(FuzzedDataProvider &fdp)
{
    size_t iterations = fdp.ConsumeIntegralInRange<size_t>(100, 500);
    
    for (size_t i = 0; i < iterations && fdp.remaining_bytes() > 0; i++) {
        QosLevel level = GetValidQosLevel(fdp);
        int tid = GetThreadId(fdp);
        
        QOS::SetQosForOtherThread(level, tid);
        
        enum QosLevel outLevel;
        QosController::GetInstance().GetThreadQosForOtherThread(outLevel, tid);
    }
    
    return true;
}

bool FuzzRaceCondition(FuzzedDataProvider &fdp)
{
    int targetTid = gettid();
    size_t threadCount = fdp.ConsumeIntegralInRange<size_t>(2, 5);
    std::vector<std::thread> threads;
    
    constexpr size_t minBytesForThread = 4;
    constexpr int qosSetRepeat = 10;

    for (size_t i = 0; i < threadCount && fdp.remaining_bytes() > minBytesForThread; i++) {
        QosLevel level = GetValidQosLevel(fdp);
        threads.emplace_back([level, targetTid]() {
            for (int j = 0; j < qosSetRepeat; j++) {
                QOS::SetQosForOtherThread(level, targetTid);
                
                enum QosLevel outLevel;
                QosController::GetInstance().GetThreadQosForOtherThread(outLevel, targetTid);
            }
        });
    }
    
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    return true;
}

bool FuzzOperationSequence(FuzzedDataProvider &fdp)
{
    QosLevel level = GetValidQosLevel(fdp);
    int tid = GetThreadId(fdp);
    
    (void)QOS::SetQosForOtherThread(level, tid);
    
    enum QosLevel getLevel;
    (void)QosController::GetInstance().GetThreadQosForOtherThread(getLevel, tid);
    
    if (fdp.ConsumeBool()) {
        QosLevel newLevel = GetValidQosLevel(fdp);
        QOS::SetQosForOtherThread(newLevel, tid);
    }
    
    (void)QosController::GetInstance().ResetThreadQosForOtherThread(tid);
    
    (void)QosController::GetInstance().GetThreadQosForOtherThread(getLevel, tid);
    
    return true;
}


bool FuzzLeaveVsReset(FuzzedDataProvider &fdp)
{
    QosLevel level = GetValidQosLevel(fdp);
    
    QOS::SetThreadQos(level);
    QosLeave();
    
    QOS::SetThreadQos(level);
    QOS::ResetThreadQos();
    
    QOS::SetThreadQos(level);
    if (fdp.ConsumeBool()) {
        QosLeave();
    } else {
        QOS::ResetThreadQos();
    }
    
    return true;
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
    OHOS::FuzzInvalidQosLevels(fdp);
    OHOS::FuzzInvalidThreadIds(fdp);
    OHOS::FuzzQosStateTransitions(fdp);
    OHOS::FuzzDoubleOperations(fdp);
    OHOS::FuzzUninitializedState(fdp);
    OHOS::FuzzResourceLeak(fdp);
    OHOS::FuzzRaceCondition(fdp);
    OHOS::FuzzOperationSequence(fdp);
    OHOS::FuzzLeaveVsReset(fdp);
    return 0;
}

