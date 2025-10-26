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
#include "qos_policy.h"
#include "qos_interface.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::ConcurrentTask;

namespace OHOS {

namespace {
    constexpr int MIN_QOS_LEVEL = 0;
    constexpr int MAX_QOS_LEVEL = 6;
    constexpr int MIN_NICE = -20;
    constexpr int MAX_NICE = 19;
    constexpr int MIN_LATENCY_NICE = -20;
    constexpr int MAX_LATENCY_NICE = 19;
    constexpr int MIN_UCLAMP = 0;
    constexpr int MAX_UCLAMP = 1024;
    constexpr int MIN_RT_PRIORITY = 1;
    constexpr int MAX_RT_PRIORITY = 99;
}

// Fuzz QosPolicy::Init - test XML parsing and initialization
bool FuzzQosPolicyInit(FuzzedDataProvider &fdp)
{
    try {
        QosPolicy qosPolicy;
        qosPolicy.Init();
    } catch (...) {
        // Catch any exceptions to prevent fuzzer crashes
    }
    return true;
}

// Fuzz QosPolicyData structure with random values
bool FuzzQosPolicyDataStructure(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < sizeof(QosPolicyData)) {
        return false;
    }

    QosPolicyData policyData;
    policyData.nice = fdp.ConsumeIntegralInRange<int>(MIN_NICE * 2, MAX_NICE * 2);
    policyData.latencyNice = fdp.ConsumeIntegralInRange<int>(MIN_LATENCY_NICE * 2, MAX_LATENCY_NICE * 2);
    policyData.uclampMin = fdp.ConsumeIntegralInRange<int>(-100, MAX_UCLAMP * 2);
    policyData.uclampMax = fdp.ConsumeIntegralInRange<int>(-100, MAX_UCLAMP * 2);
    policyData.rtSchedPriority = fdp.ConsumeIntegralInRange<int>(0, MAX_RT_PRIORITY * 2);
    policyData.policy = fdp.ConsumeIntegralInRange<int>(-1, 10);

    // Fuzz with potentially invalid policy combinations
    return true;
}

// Fuzz QosPolicyDatas structure with all QoS levels
bool FuzzQosPolicyDatasStructure(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < sizeof(QosPolicyDatas)) {
        return false;
    }

    QosPolicyDatas policyDatas;

    // Fuzz policyType with values outside valid range
    policyDatas.policyType = fdp.ConsumeIntegralInRange<int>(
        static_cast<int>(QosPolicyType::QOS_POLICY_DEFAULT) - 5,
        static_cast<int>(QosPolicyType::QOS_POLICY_MAX_NR) + 5
    );

    // Fuzz policyFlag with random bit patterns
    policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>();

    // Fuzz all 7 QoS levels
    for (int i = 0; i < NR_QOS; i++) {
        policyDatas.policys[i].nice = fdp.ConsumeIntegralInRange<int>(MIN_NICE * 2, MAX_NICE * 2);
        policyDatas.policys[i].latencyNice = fdp.ConsumeIntegralInRange<int>(MIN_LATENCY_NICE * 2, MAX_LATENCY_NICE * 2);
        policyDatas.policys[i].uclampMin = fdp.ConsumeIntegralInRange<int>(-100, MAX_UCLAMP * 2);
        policyDatas.policys[i].uclampMax = fdp.ConsumeIntegralInRange<int>(-100, MAX_UCLAMP * 2);
        policyDatas.policys[i].rtSchedPriority = fdp.ConsumeIntegralInRange<int>(-10, MAX_RT_PRIORITY * 2);
        policyDatas.policys[i].policy = fdp.ConsumeIntegralInRange<int>(-5, 10);
    }

    return true;
}

// Fuzz QosPolicy::SetQosPolicy with random policy data
bool FuzzSetQosPolicy(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < sizeof(QosPolicyDatas)) {
        return false;
    }

    try {
        QosPolicy qosPolicy;
        qosPolicy.Init();

        QosPolicyDatas policyDatas;
        policyDatas.policyType = fdp.ConsumeIntegralInRange<int>(
            static_cast<int>(QosPolicyType::QOS_POLICY_DEFAULT) - 2,
            static_cast<int>(QosPolicyType::QOS_POLICY_MAX_NR) + 2
        );
        policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>();

        for (int i = 0; i < NR_QOS; i++) {
            policyDatas.policys[i].nice = fdp.ConsumeIntegralInRange<int>(MIN_NICE - 10, MAX_NICE + 10);
            policyDatas.policys[i].latencyNice = fdp.ConsumeIntegralInRange<int>(MIN_LATENCY_NICE - 10, MAX_LATENCY_NICE + 10);
            policyDatas.policys[i].uclampMin = fdp.ConsumeIntegralInRange<int>(-50, MAX_UCLAMP + 50);
            policyDatas.policys[i].uclampMax = fdp.ConsumeIntegralInRange<int>(-50, MAX_UCLAMP + 50);
            policyDatas.policys[i].rtSchedPriority = fdp.ConsumeIntegralInRange<int>(0, MAX_RT_PRIORITY + 10);
            policyDatas.policys[i].policy = fdp.ConsumeIntegralInRange<int>(
                static_cast<int>(SchedPolicy::SCHED_POLICY_OTHER),
                static_cast<int>(SchedPolicy::SCHED_POLICY_RT_EX) + 10
            );
        }

        qosPolicy.SetQosPolicy(&policyDatas);
    } catch (...) {
        // Catch exceptions
    }

    return true;
}

// Fuzz QosPolicySet directly through qos_interface
bool FuzzQosPolicySetInterface(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < sizeof(QosPolicyDatas)) {
        return false;
    }

    QosPolicyDatas policyDatas;
    policyDatas.policyType = fdp.ConsumeIntegralInRange<int>(0, 10);
    policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>();

    // Fuzz with extreme values
    for (int i = 0; i < NR_QOS; i++) {
        policyDatas.policys[i].nice = fdp.ConsumeIntegral<int>();
        policyDatas.policys[i].latencyNice = fdp.ConsumeIntegral<int>();
        policyDatas.policys[i].uclampMin = fdp.ConsumeIntegral<int>();
        policyDatas.policys[i].uclampMax = fdp.ConsumeIntegral<int>();
        policyDatas.policys[i].rtSchedPriority = fdp.ConsumeIntegral<int>();
        policyDatas.policys[i].policy = fdp.ConsumeIntegral<int>();
    }

    QosPolicySet(&policyDatas);
    return true;
}

// Fuzz with edge case combinations
bool FuzzPolicyEdgeCases(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 32) {
        return false;
    }

    QosPolicyDatas policyDatas;

    // Test edge cases
    int edgeCase = fdp.ConsumeIntegralInRange<int>(0, 9);

    switch (edgeCase) {
        case 0:
            // All policies set to minimum values
            policyDatas.policyType = QosPolicyType::QOS_POLICY_DEFAULT;
            policyDatas.policyFlag = 0;
            for (int i = 0; i < NR_QOS; i++) {
                policyDatas.policys[i].nice = MIN_NICE;
                policyDatas.policys[i].latencyNice = MIN_LATENCY_NICE;
                policyDatas.policys[i].uclampMin = MIN_UCLAMP;
                policyDatas.policys[i].uclampMax = MIN_UCLAMP;
                policyDatas.policys[i].rtSchedPriority = 0;
                policyDatas.policys[i].policy = SCHED_POLICY_OTHER;
            }
            break;
        case 1:
            // All policies set to maximum values
            policyDatas.policyType = QosPolicyType::QOS_POLICY_FOCUS;
            policyDatas.policyFlag = QOS_FLAG_ALL;
            for (int i = 0; i < NR_QOS; i++) {
                policyDatas.policys[i].nice = MAX_NICE;
                policyDatas.policys[i].latencyNice = MAX_LATENCY_NICE;
                policyDatas.policys[i].uclampMin = MAX_UCLAMP;
                policyDatas.policys[i].uclampMax = MAX_UCLAMP;
                policyDatas.policys[i].rtSchedPriority = MAX_RT_PRIORITY;
                policyDatas.policys[i].policy = SCHED_POLICY_RT_EX;
            }
            break;
        case 2:
            // Inverted uclamp values (min > max)
            policyDatas.policyType = QosPolicyType::QOS_POLICY_FRONT;
            policyDatas.policyFlag = QOS_FLAG_UCLAMP;
            for (int i = 0; i < NR_QOS; i++) {
                policyDatas.policys[i].uclampMin = fdp.ConsumeIntegralInRange<int>(512, 1024);
                policyDatas.policys[i].uclampMax = fdp.ConsumeIntegralInRange<int>(0, 511);
            }
            break;
        case 3:
            // Null policy type
            policyDatas.policyType = 0;
            policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>();
            break;
        case 4:
            // Invalid policy type
            policyDatas.policyType = QosPolicyType::QOS_POLICY_MAX_NR + 100;
            policyDatas.policyFlag = QOS_FLAG_ALL;
            break;
        case 5:
            // Mixed SCHED_RESET_ON_FORK flag
            policyDatas.policyType = QosPolicyType::QOS_POLICY_SYSTEM_SERVER;
            policyDatas.policyFlag = QOS_FLAG_RT;
            for (int i = 0; i < NR_QOS; i++) {
                policyDatas.policys[i].policy = SCHED_POLICY_FIFO | SCHED_RESET_ON_FORK;
                policyDatas.policys[i].rtSchedPriority = fdp.ConsumeIntegralInRange<int>(1, 99);
            }
            break;
        case 6:
            // Negative values for unsigned fields (type punning)
            policyDatas.policyType = -1;
            policyDatas.policyFlag = 0xFFFFFFFF;
            break;
        case 7:
            // Only specific flags enabled
            policyDatas.policyType = QosPolicyType::QOS_POLICY_BACK;
            policyDatas.policyFlag = fdp.PickValueInArray({
                QOS_FLAG_NICE,
                QOS_FLAG_LATENCY_NICE,
                QOS_FLAG_UCLAMP,
                QOS_FLAG_RT
            });
            break;
        case 8:
            // Random flag combinations
            policyDatas.policyType = fdp.ConsumeIntegralInRange<int>(1, 5);
            policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>() & QOS_FLAG_ALL;
            break;
        case 9:
            // All zeros
            memset(&policyDatas, 0, sizeof(policyDatas));
            break;
    }

    QosPolicySet(&policyDatas);
    return true;
}

// Fuzz policy flag combinations
bool FuzzPolicyFlags(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 8) {
        return false;
    }

    QosPolicyDatas policyDatas;
    policyDatas.policyType = fdp.ConsumeIntegralInRange<int>(1, 5);

    // Test all flag combinations
    unsigned int baseFlags[] = {
        0,
        QOS_FLAG_NICE,
        QOS_FLAG_LATENCY_NICE,
        QOS_FLAG_UCLAMP,
        QOS_FLAG_RT,
        QOS_FLAG_NICE | QOS_FLAG_LATENCY_NICE,
        QOS_FLAG_NICE | QOS_FLAG_UCLAMP,
        QOS_FLAG_NICE | QOS_FLAG_RT,
        QOS_FLAG_LATENCY_NICE | QOS_FLAG_UCLAMP,
        QOS_FLAG_LATENCY_NICE | QOS_FLAG_RT,
        QOS_FLAG_UCLAMP | QOS_FLAG_RT,
        QOS_FLAG_ALL,
        0xFFFFFFFF  // All bits set
    };

    policyDatas.policyFlag = fdp.PickValueInArray(baseFlags);

    // Set random policy data
    for (int i = 0; i < NR_QOS; i++) {
        policyDatas.policys[i].nice = fdp.ConsumeIntegralInRange<int>(-20, 19);
        policyDatas.policys[i].latencyNice = fdp.ConsumeIntegralInRange<int>(-20, 19);
        policyDatas.policys[i].uclampMin = fdp.ConsumeIntegralInRange<int>(0, 1024);
        policyDatas.policys[i].uclampMax = fdp.ConsumeIntegralInRange<int>(0, 1024);
        policyDatas.policys[i].rtSchedPriority = fdp.ConsumeIntegralInRange<int>(0, 99);
        policyDatas.policys[i].policy = fdp.ConsumeIntegralInRange<int>(0, 3);
    }

    QosPolicySet(&policyDatas);
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
            OHOS::FuzzQosPolicyInit(fdp);
            break;
        case 1:
            OHOS::FuzzQosPolicyDataStructure(fdp);
            break;
        case 2:
            OHOS::FuzzQosPolicyDatasStructure(fdp);
            break;
        case 3:
            OHOS::FuzzSetQosPolicy(fdp);
            break;
        case 4:
            OHOS::FuzzQosPolicySetInterface(fdp);
            break;
        case 5:
            OHOS::FuzzPolicyEdgeCases(fdp);
            break;
        case 6:
            OHOS::FuzzPolicyFlags(fdp);
            break;
    }

    return 0;
}
