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
    return 0;
}

