/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <climits>
#include <fuzzer/FuzzedDataProvider.h>

#include "concurrent_task_service.h"
#include "securec.h"
#include "qos.h"
#include "qos_interface.h"
#include "qos_policy.h"
#include "system_ability_definition.h"

using namespace OHOS::ConcurrentTask;
using namespace OHOS::QOS;

namespace OHOS {

// Constants to avoid magic numbers
constexpr unsigned int QOS_LEVEL_MIN = 0;
constexpr unsigned int QOS_LEVEL_MAX = 6;
constexpr unsigned int QOS_LEVEL_EXTENDED_MAX = 7;
constexpr unsigned int QOS_LEVEL_TEST_MAX = 8;
constexpr unsigned int QOS_LEVEL_TEST_MID = 2;
constexpr unsigned int QOS_LEVEL_TEST_HIGH = 3;
constexpr unsigned int TEST_LEVEL_100 = 100;
constexpr int TEST_TID_SMALL = 100;
constexpr int TEST_TID_MEDIUM = 1000;
constexpr int TEST_TID_LARGE = 65535;
constexpr int TEST_ITERATIONS_SMALL = 3;
constexpr int TEST_ITERATIONS_MEDIUM = 5;
constexpr int TEST_ITERATIONS_LARGE = 10;
constexpr size_t MIN_FUZZ_DATA_SIZE = 4;
constexpr size_t MIN_FUZZ_DATA_SIZE_EXTENDED = 8;
constexpr int MAX_TID_RANGE = 10000;
constexpr uint8_t MAX_OPERATION_TYPE = 5;
constexpr uint8_t OPERATION_QOS_GET = 1;
constexpr uint8_t OPERATION_QOS_LEAVE_FOR_OTHER = 4;
constexpr uint8_t OPERATION_QOS_LEAVE_FOR_OTHER_ALT = 5;
constexpr unsigned int LEVEL_1 = 1;
constexpr unsigned int LEVEL_4 = 4;
constexpr int INVALID_LEVEL = -1;
constexpr unsigned int LEVEL_INCREMENT = 1;
constexpr int LOOP_START_INDEX = 0;
constexpr int SUCCESS_RETURN = 0;

bool FuzzQosApply(FuzzedDataProvider &fdp)
{
    unsigned int levels[] = {
        QOS_LEVEL_MIN, LEVEL_1, QOS_LEVEL_TEST_MID, QOS_LEVEL_TEST_HIGH, LEVEL_4,
        TEST_ITERATIONS_MEDIUM, QOS_LEVEL_MAX, QOS_LEVEL_EXTENDED_MAX, TEST_LEVEL_100, UINT_MAX
    };
    
    for (auto level : levels) {
        QosApply(level);
        
        int retrievedLevel = INVALID_LEVEL;
        QosGet(retrievedLevel);
        
        QosLeave();
    }
    
    while (fdp.remaining_bytes() > MIN_FUZZ_DATA_SIZE) {
        unsigned int randomLevel = fdp.ConsumeIntegral<unsigned int>();
        QosApply(randomLevel);
    }
    
    return true;
}

bool FuzzQosApplyForOther(FuzzedDataProvider &fdp)
{
    int testTids[] = {
        INVALID_LEVEL, QOS_LEVEL_MIN, LEVEL_1, TEST_TID_SMALL,
        TEST_TID_MEDIUM, TEST_TID_LARGE, INT_MAX, INT_MIN
    };
    
    for (auto tid : testTids) {
        for (unsigned int level = QOS_LEVEL_MIN; level < QOS_LEVEL_TEST_MAX; ++level) {
            QosApplyForOther(level, tid);
            
            int retrievedLevel = INVALID_LEVEL;
            QosGetForOther(tid, retrievedLevel);
            
            QosLeaveForOther(tid);
        }
    }
    
    while (fdp.remaining_bytes() > MIN_FUZZ_DATA_SIZE_EXTENDED) {
        unsigned int level = fdp.ConsumeIntegral<unsigned int>();
        int tid = fdp.ConsumeIntegral<int>();
        
        QosApplyForOther(level, tid);
        QosLeaveForOther(tid);
    }
    
    return true;
}

bool FuzzQosGet(FuzzedDataProvider &fdp)
{
    int level = INVALID_LEVEL;
    
    QosGet(level);
    
    QosApply(QOS_LEVEL_TEST_HIGH);
    QosGet(level);
    
    for (int i = LOOP_START_INDEX; i < TEST_ITERATIONS_LARGE; ++i) {
        QosGet(level);
    }
    
    QosLeave();
    QosGet(level);
    
    return true;
}

bool FuzzQosGetForOther(FuzzedDataProvider &fdp)
{
    int level = INVALID_LEVEL;
    int testTids[] = {INVALID_LEVEL, QOS_LEVEL_MIN, LEVEL_1, TEST_TID_SMALL, INT_MAX, INT_MIN};
    
    for (auto tid : testTids) {
        QosGetForOther(tid, level);
        
        QosApplyForOther(QOS_LEVEL_TEST_MID, tid);
        QosGetForOther(tid, level);
        
        QosLeaveForOther(tid);
        QosGetForOther(tid, level);
    }
    
    while (fdp.remaining_bytes() > MIN_FUZZ_DATA_SIZE) {
        int randomTid = fdp.ConsumeIntegral<int>();
        QosGetForOther(randomTid, level);
    }
    
    return true;
}

bool FuzzQosLeave(FuzzedDataProvider &fdp)
{
    QosLeave();
    
    QosApply(QOS_LEVEL_TEST_MID);
    QosLeave();
    
    for (int i = LOOP_START_INDEX; i < TEST_ITERATIONS_MEDIUM; ++i) {
        QosLeave();
    }
    
    for (unsigned int level = QOS_LEVEL_MIN; level < QOS_LEVEL_EXTENDED_MAX; ++level) {
        QosApply(level);
        QosLeave();
        
        int retrievedLevel = INVALID_LEVEL;
        QosGet(retrievedLevel);
    }
    
    return true;
}

bool FuzzQosLeaveForOther(FuzzedDataProvider &fdp)
{
    int testTids[] = {INVALID_LEVEL, QOS_LEVEL_MIN, LEVEL_1, TEST_TID_SMALL, INT_MAX};
    
    for (auto tid : testTids) {
        QosLeaveForOther(tid);
        
        QosApplyForOther(QOS_LEVEL_TEST_HIGH, tid);
        QosLeaveForOther(tid);
        
        for (int i = LOOP_START_INDEX; i < TEST_ITERATIONS_SMALL; ++i) {
            QosLeaveForOther(tid);
        }
    }
    
    while (fdp.remaining_bytes() > MIN_FUZZ_DATA_SIZE) {
        int randomTid = fdp.ConsumeIntegral<int>();
        QosLeaveForOther(randomTid);
    }
    
    return true;
}

bool FuzzQosApplyLeaveSequence(FuzzedDataProvider &fdp)
{
    for (unsigned int level = QOS_LEVEL_MIN; level < QOS_LEVEL_EXTENDED_MAX; ++level) {
        QosApply(level);
        
        int retrievedLevel = INVALID_LEVEL;
        QosGet(retrievedLevel);
        
        QosApply(level + LEVEL_INCREMENT);
        QosGet(retrievedLevel);
        
        QosLeave();
    }
    
    return true;
}

bool FuzzQosCrossThreadOperations(FuzzedDataProvider &fdp)
{
    int tids[] = {LEVEL_1, QOS_LEVEL_TEST_MID, QOS_LEVEL_TEST_HIGH};
    
    for (auto tid : tids) {
        QosApplyForOther(QOS_LEVEL_TEST_MID, tid);
    }
    
    int level = INVALID_LEVEL;
    for (auto tid : tids) {
        QosGetForOther(tid, level);
    }
    
    for (auto tid : tids) {
        QosLeaveForOther(tid);
    }
    
    for (auto tid : tids) {
        QosGetForOther(tid, level);
    }
    
    return true;
}

bool FuzzQosRapidOperations(FuzzedDataProvider &fdp)
{
    while (fdp.remaining_bytes() > MIN_FUZZ_DATA_SIZE_EXTENDED) {
        uint8_t operation = fdp.ConsumeIntegralInRange<uint8_t>(QOS_LEVEL_MIN, MAX_OPERATION_TYPE);
        
        switch (operation) {
            case QOS_LEVEL_MIN: {
                unsigned int level = fdp.ConsumeIntegralInRange<unsigned int>(QOS_LEVEL_MIN, QOS_LEVEL_MAX);
                QosApply(level);
                break;
            }
            case OPERATION_QOS_GET: {
                int level = INVALID_LEVEL;
                QosGet(level);
                break;
            }
            case QOS_LEVEL_TEST_MID: {
                QosLeave();
                break;
            }
            case QOS_LEVEL_TEST_HIGH: {
                unsigned int level = fdp.ConsumeIntegralInRange<unsigned int>(QOS_LEVEL_MIN, QOS_LEVEL_MAX);
                int tid = fdp.ConsumeIntegralInRange<int>(QOS_LEVEL_MIN, MAX_TID_RANGE);
                QosApplyForOther(level, tid);
                break;
            }
            case OPERATION_QOS_LEAVE_FOR_OTHER: {
                int tid = fdp.ConsumeIntegralInRange<int>(QOS_LEVEL_MIN, MAX_TID_RANGE);
                int level = INVALID_LEVEL;
                QosGetForOther(tid, level);
                break;
            }
            case OPERATION_QOS_LEAVE_FOR_OTHER_ALT: {
                int tid = fdp.ConsumeIntegralInRange<int>(QOS_LEVEL_MIN, MAX_TID_RANGE);
                QosLeaveForOther(tid);
                break;
            }
            default:
                break;
        }
    }
    
    return true;
}

bool FuzzQosBoundaryTransitions(FuzzedDataProvider &fdp)
{
    unsigned int boundaryLevels[] = {QOS_LEVEL_MIN, QOS_LEVEL_MAX, QOS_LEVEL_EXTENDED_MAX, UINT_MAX};
    
    for (auto level : boundaryLevels) {
        QosApply(level);
        
        int retrieved = INVALID_LEVEL;
        QosGet(retrieved);
        
        QosLeave();
    }
    
    int boundaryTids[] = {INT_MIN, INVALID_LEVEL, QOS_LEVEL_MIN, LEVEL_1, INT_MAX};
    
    for (auto tid : boundaryTids) {
        for (auto level : boundaryLevels) {
            QosApplyForOther(level, tid);
            
            int retrieved = INVALID_LEVEL;
            QosGetForOther(tid, retrieved);
            
            QosLeaveForOther(tid);
        }
    }
    
    return true;
}

bool FuzzQosConsistencyCheck(FuzzedDataProvider &fdp)
{
    for (unsigned int level = QOS_LEVEL_MIN; level < QOS_LEVEL_EXTENDED_MAX; ++level) {
        QosApply(level);
        
        int retrievedLevel = INVALID_LEVEL;
        for (int i = LOOP_START_INDEX; i < TEST_ITERATIONS_MEDIUM; ++i) {
            QosGet(retrievedLevel);
        }
        
        QosLeave();
    }
    
    int tid = fdp.ConsumeIntegralInRange<int>(LEVEL_1, MAX_TID_RANGE);
    for (unsigned int level = QOS_LEVEL_MIN; level < QOS_LEVEL_EXTENDED_MAX; ++level) {
        QosApplyForOther(level, tid);
        
        int retrievedLevel = INVALID_LEVEL;
        for (int i = LOOP_START_INDEX; i < TEST_ITERATIONS_MEDIUM; ++i) {
            QosGetForOther(tid, retrievedLevel);
        }
        
        QosLeaveForOther(tid);
    }
    
    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::MIN_FUZZ_DATA_SIZE) {
        return OHOS::SUCCESS_RETURN;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    OHOS::FuzzQosApply(fdp);
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE_EXTENDED) {
        OHOS::FuzzQosApplyForOther(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE) {
        OHOS::FuzzQosGet(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE) {
        OHOS::FuzzQosGetForOther(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE) {
        OHOS::FuzzQosLeave(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE) {
        OHOS::FuzzQosLeaveForOther(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE) {
        OHOS::FuzzQosApplyLeaveSequence(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE) {
        OHOS::FuzzQosCrossThreadOperations(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE_EXTENDED) {
        OHOS::FuzzQosRapidOperations(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE) {
        OHOS::FuzzQosBoundaryTransitions(fdp);
    }
    
    if (fdp.remaining_bytes() > OHOS::MIN_FUZZ_DATA_SIZE) {
        OHOS::FuzzQosConsistencyCheck(fdp);
    }
    
    return OHOS::SUCCESS_RETURN;
}
