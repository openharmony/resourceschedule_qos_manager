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
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::ConcurrentTask;

namespace OHOS {

namespace {
    constexpr size_t MIN_FUZZ_INPUT_SIZE = 4;
    constexpr size_t MIN_POLICY_EDGE_BYTES = 32;
    constexpr size_t MIN_POLICY_FLAG_BYTES = 8;
    constexpr int MIN_NICE = -20;
    constexpr int MAX_NICE = 19;
    constexpr int MIN_LATENCY_NICE = -20;
    constexpr int MAX_LATENCY_NICE = 19;
    constexpr int MIN_UCLAMP = 0;
    constexpr int MAX_UCLAMP = 1024;
    constexpr int MIN_RT_PRIORITY = 1;
    constexpr int MAX_RT_PRIORITY = 99;
    constexpr int DEFAULT_RT_PRIORITY_MIN = 0;
    constexpr int UCLAMP_NEGATIVE_MARGIN = 100;
    constexpr int UCLAMP_EXTRA_MARGIN = 50;
    constexpr int UCLAMP_MAX_SCALE = 2;
    constexpr int NICE_MARGIN = 10;
    constexpr int RT_PRIORITY_NEGATIVE_MARGIN = 10;
    constexpr int RT_PRIORITY_EXTRA_MARGIN = 10;
    constexpr int RT_PRIORITY_MAX_SCALE = 2;
    constexpr int SCHED_POLICY_EXTRA_OFFSET = 10;
    constexpr int POLICY_RANDOM_MIN = -1;
    constexpr int POLICY_RANDOM_MAX = 10;
    constexpr int POLICY_FUZZ_MIN = -5;
    constexpr int RANGE_EXPANSION_FACTOR = 2;
    constexpr int POLICY_TYPE_RANGE_EXTENSION = 5;
    constexpr int POLICY_TYPE_MARGIN = 2;
    constexpr int MAX_SCHED_POLICY_INDEX = 3;
    constexpr int POLICY_TYPE_RANDOM_MIN = 0;
    constexpr int POLICY_TYPE_RANDOM_MAX = 10;
    constexpr int POLICY_TYPE_LIMITED_MIN = 1;
    constexpr int POLICY_TYPE_LIMITED_MAX = 5;
    enum class PolicyEdgeCase : int {
        ALL_MIN = 0,
        ALL_MAX,
        INVERTED_UCLAMP,
        NULL_POLICY_TYPE,
        INVALID_POLICY_TYPE,
        MIXED_RESET_ON_FORK,
        NEGATIVE_UNSIGNED,
        SPECIFIC_FLAGS,
        RANDOM_FLAGS,
        ALL_ZERO
    };

    enum class QosFuzzChoice : int {
        INIT = 0,
        POLICY_DATA_STRUCTURE,
        POLICY_DATAS_STRUCTURE,
        SET_POLICY,
        SET_INTERFACE,
        POLICY_EDGE_CASES,
        POLICY_FLAGS
    };

    constexpr int INVALID_POLICY_TYPE_OFFSET = 100;
    constexpr int INVALID_POLICY_TYPE_SENTINEL = -1;
    constexpr unsigned int INVALID_POLICY_FLAG_MASK = 0xFFFFFFFF;
    constexpr int UCLAMP_SPLIT_THRESHOLD = MAX_UCLAMP / 2;
    constexpr int UCLAMP_SPLIT_MAX = UCLAMP_SPLIT_THRESHOLD - 1;
    constexpr int MAX_FUZZ_DISPATCH_INDEX = static_cast<int>(QosFuzzChoice::POLICY_FLAGS);
    constexpr int MAX_EDGE_CASE_INDEX = static_cast<int>(PolicyEdgeCase::ALL_ZERO);

    inline bool SecureZero(void* ptr, size_t size)
    {
        return memset_s(ptr, size, 0, size) == EOK;
    }

    void ApplyAllMinCase(QosPolicyDatas &policyDatas)
    {
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
    }

    void ApplyAllMaxCase(QosPolicyDatas &policyDatas)
    {
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
    }

    void ApplyInvertedUclampCase(QosPolicyDatas &policyDatas, FuzzedDataProvider &fdp)
    {
        policyDatas.policyType = QosPolicyType::QOS_POLICY_FRONT;
        policyDatas.policyFlag = QOS_FLAG_UCLAMP;
        for (int i = 0; i < NR_QOS; i++) {
            policyDatas.policys[i].uclampMin = fdp.ConsumeIntegralInRange<int>(UCLAMP_SPLIT_THRESHOLD, MAX_UCLAMP);
            policyDatas.policys[i].uclampMax = fdp.ConsumeIntegralInRange<int>(MIN_UCLAMP, UCLAMP_SPLIT_MAX);
        }
    }

    void ApplyNullPolicyTypeCase(QosPolicyDatas &policyDatas, FuzzedDataProvider &fdp)
    {
        policyDatas.policyType = static_cast<int>(QosPolicyType::QOS_POLICY_DEFAULT);
        policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>();
    }

    void ApplyInvalidPolicyTypeCase(QosPolicyDatas &policyDatas)
    {
        policyDatas.policyType = QosPolicyType::QOS_POLICY_MAX_NR + INVALID_POLICY_TYPE_OFFSET;
        policyDatas.policyFlag = QOS_FLAG_ALL;
    }

    void ApplyMixedResetCase(QosPolicyDatas &policyDatas, FuzzedDataProvider &fdp)
    {
        policyDatas.policyType = QosPolicyType::QOS_POLICY_SYSTEM_SERVER;
        policyDatas.policyFlag = QOS_FLAG_RT;
        for (int i = 0; i < NR_QOS; i++) {
            policyDatas.policys[i].policy = SCHED_POLICY_FIFO | SCHED_RESET_ON_FORK;
            policyDatas.policys[i].rtSchedPriority = fdp.ConsumeIntegralInRange<int>(MIN_RT_PRIORITY, MAX_RT_PRIORITY);
        }
    }

    void ApplyNegativeUnsignedCase(QosPolicyDatas &policyDatas)
    {
        policyDatas.policyType = INVALID_POLICY_TYPE_SENTINEL;
        policyDatas.policyFlag = INVALID_POLICY_FLAG_MASK;
    }

    void ApplySpecificFlagsCase(QosPolicyDatas &policyDatas, FuzzedDataProvider &fdp)
    {
        policyDatas.policyType = QosPolicyType::QOS_POLICY_BACK;
        policyDatas.policyFlag = fdp.PickValueInArray({
            QOS_FLAG_NICE,
            QOS_FLAG_LATENCY_NICE,
            QOS_FLAG_UCLAMP,
            QOS_FLAG_RT
        });
    }

    void ApplyRandomFlagsCase(QosPolicyDatas &policyDatas, FuzzedDataProvider &fdp)
    {
        policyDatas.policyType = fdp.ConsumeIntegralInRange<int>(POLICY_TYPE_LIMITED_MIN, POLICY_TYPE_LIMITED_MAX);
        policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>() & QOS_FLAG_ALL;
    }

    bool ApplyAllZeroCase(QosPolicyDatas &policyDatas)
    {
        return SecureZero(&policyDatas, sizeof(policyDatas));
    }

    bool ApplyEdgeCase(PolicyEdgeCase edgeCase, QosPolicyDatas &policyDatas, FuzzedDataProvider &fdp)
    {
        switch (edgeCase) {
            case PolicyEdgeCase::ALL_MIN:
                ApplyAllMinCase(policyDatas);
                return true;
            case PolicyEdgeCase::ALL_MAX:
                ApplyAllMaxCase(policyDatas);
                return true;
            case PolicyEdgeCase::INVERTED_UCLAMP:
                ApplyInvertedUclampCase(policyDatas, fdp);
                return true;
            case PolicyEdgeCase::NULL_POLICY_TYPE:
                ApplyNullPolicyTypeCase(policyDatas, fdp);
                return true;
            case PolicyEdgeCase::INVALID_POLICY_TYPE:
                ApplyInvalidPolicyTypeCase(policyDatas);
                return true;
            case PolicyEdgeCase::MIXED_RESET_ON_FORK:
                ApplyMixedResetCase(policyDatas, fdp);
                return true;
            case PolicyEdgeCase::NEGATIVE_UNSIGNED:
                ApplyNegativeUnsignedCase(policyDatas);
                return true;
            case PolicyEdgeCase::SPECIFIC_FLAGS:
                ApplySpecificFlagsCase(policyDatas, fdp);
                return true;
            case PolicyEdgeCase::RANDOM_FLAGS:
                ApplyRandomFlagsCase(policyDatas, fdp);
                return true;
            case PolicyEdgeCase::ALL_ZERO:
                return ApplyAllZeroCase(policyDatas);
            default:
                return true;
        }
    }
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
    policyData.nice = fdp.ConsumeIntegralInRange<int>(MIN_NICE * RANGE_EXPANSION_FACTOR,
        MAX_NICE * RANGE_EXPANSION_FACTOR);
    policyData.latencyNice = fdp.ConsumeIntegralInRange<int>(
        MIN_LATENCY_NICE * RANGE_EXPANSION_FACTOR, MAX_LATENCY_NICE * RANGE_EXPANSION_FACTOR);
    policyData.uclampMin = fdp.ConsumeIntegralInRange<int>(
        -UCLAMP_NEGATIVE_MARGIN, MAX_UCLAMP * UCLAMP_MAX_SCALE);
    policyData.uclampMax = fdp.ConsumeIntegralInRange<int>(
        -UCLAMP_NEGATIVE_MARGIN, MAX_UCLAMP * UCLAMP_MAX_SCALE);
    policyData.rtSchedPriority = fdp.ConsumeIntegralInRange<int>(
        0, MAX_RT_PRIORITY * RT_PRIORITY_MAX_SCALE);
    policyData.policy = fdp.ConsumeIntegralInRange<int>(POLICY_RANDOM_MIN, POLICY_RANDOM_MAX);

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
        static_cast<int>(QosPolicyType::QOS_POLICY_DEFAULT) - POLICY_TYPE_RANGE_EXTENSION,
        static_cast<int>(QosPolicyType::QOS_POLICY_MAX_NR) + POLICY_TYPE_RANGE_EXTENSION
    );

    // Fuzz policyFlag with random bit patterns
    policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>();

    // Fuzz all 7 QoS levels
    for (int i = 0; i < NR_QOS; i++) {
        policyDatas.policys[i].nice =
            fdp.ConsumeIntegralInRange<int>(MIN_NICE * RANGE_EXPANSION_FACTOR,
            MAX_NICE * RANGE_EXPANSION_FACTOR);
        policyDatas.policys[i].latencyNice =
            fdp.ConsumeIntegralInRange<int>(MIN_LATENCY_NICE * RANGE_EXPANSION_FACTOR,
            MAX_LATENCY_NICE * RANGE_EXPANSION_FACTOR);
        policyDatas.policys[i].uclampMin = fdp.ConsumeIntegralInRange<int>(
            -UCLAMP_NEGATIVE_MARGIN, MAX_UCLAMP * UCLAMP_MAX_SCALE);
        policyDatas.policys[i].uclampMax = fdp.ConsumeIntegralInRange<int>(
            -UCLAMP_NEGATIVE_MARGIN, MAX_UCLAMP * UCLAMP_MAX_SCALE);
        policyDatas.policys[i].rtSchedPriority = fdp.ConsumeIntegralInRange<int>(
            -RT_PRIORITY_NEGATIVE_MARGIN, MAX_RT_PRIORITY * RT_PRIORITY_MAX_SCALE);
        policyDatas.policys[i].policy =
            fdp.ConsumeIntegralInRange<int>(POLICY_FUZZ_MIN, POLICY_RANDOM_MAX);
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
            static_cast<int>(QosPolicyType::QOS_POLICY_DEFAULT) - POLICY_TYPE_MARGIN,
            static_cast<int>(QosPolicyType::QOS_POLICY_MAX_NR) + POLICY_TYPE_MARGIN);
        policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>();

        for (int i = 0; i < NR_QOS; i++) {
            policyDatas.policys[i].nice =
                fdp.ConsumeIntegralInRange<int>(MIN_NICE - NICE_MARGIN, MAX_NICE + NICE_MARGIN);
            policyDatas.policys[i].latencyNice = fdp.ConsumeIntegralInRange<int>(
                MIN_LATENCY_NICE - NICE_MARGIN, MAX_LATENCY_NICE + NICE_MARGIN);
            policyDatas.policys[i].uclampMin = fdp.ConsumeIntegralInRange<int>(
                -UCLAMP_EXTRA_MARGIN, MAX_UCLAMP + UCLAMP_EXTRA_MARGIN);
            policyDatas.policys[i].uclampMax = fdp.ConsumeIntegralInRange<int>(
                -UCLAMP_EXTRA_MARGIN, MAX_UCLAMP + UCLAMP_EXTRA_MARGIN);
            policyDatas.policys[i].rtSchedPriority = fdp.ConsumeIntegralInRange<int>(
                0, MAX_RT_PRIORITY + RT_PRIORITY_EXTRA_MARGIN);
            policyDatas.policys[i].policy = fdp.ConsumeIntegralInRange<int>(
                static_cast<int>(SchedPolicy::SCHED_POLICY_OTHER),
                static_cast<int>(SchedPolicy::SCHED_POLICY_RT_EX) + SCHED_POLICY_EXTRA_OFFSET);
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
    policyDatas.policyType = fdp.ConsumeIntegralInRange<int>(POLICY_TYPE_RANDOM_MIN, POLICY_TYPE_RANDOM_MAX);
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
    if (fdp.remaining_bytes() < MIN_POLICY_EDGE_BYTES) {
        return false;
    }

    QosPolicyDatas policyDatas;
    auto edgeCase = static_cast<PolicyEdgeCase>(fdp.ConsumeIntegralInRange<int>(0, MAX_EDGE_CASE_INDEX));
    if (!ApplyEdgeCase(edgeCase, policyDatas, fdp)) {
        return false;
    }

    QosPolicySet(&policyDatas);
    return true;
}

// Fuzz policy flag combinations
bool FuzzPolicyFlags(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_POLICY_FLAG_BYTES) {
        return false;
    }

    QosPolicyDatas policyDatas;
    policyDatas.policyType = fdp.ConsumeIntegralInRange<int>(POLICY_TYPE_LIMITED_MIN, POLICY_TYPE_LIMITED_MAX);

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
        INVALID_POLICY_FLAG_MASK  // All bits set
    };

    policyDatas.policyFlag = fdp.PickValueInArray(baseFlags);

    // Set random policy data
    for (int i = 0; i < NR_QOS; i++) {
        policyDatas.policys[i].nice =
            fdp.ConsumeIntegralInRange<int>(MIN_NICE, MAX_NICE);
        policyDatas.policys[i].latencyNice =
            fdp.ConsumeIntegralInRange<int>(MIN_LATENCY_NICE, MAX_LATENCY_NICE);
        policyDatas.policys[i].uclampMin =
            fdp.ConsumeIntegralInRange<int>(MIN_UCLAMP, MAX_UCLAMP);
        policyDatas.policys[i].uclampMax =
            fdp.ConsumeIntegralInRange<int>(MIN_UCLAMP, MAX_UCLAMP);
        policyDatas.policys[i].rtSchedPriority =
            fdp.ConsumeIntegralInRange<int>(DEFAULT_RT_PRIORITY_MIN, MAX_RT_PRIORITY);
        policyDatas.policys[i].policy =
            fdp.ConsumeIntegralInRange<int>(0, MAX_SCHED_POLICY_INDEX);
    }

    QosPolicySet(&policyDatas);
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
    auto choice = static_cast<OHOS::QosFuzzChoice>(fdp.ConsumeIntegralInRange<int>(
        0, OHOS::MAX_FUZZ_DISPATCH_INDEX));

    switch (choice) {
        case OHOS::QosFuzzChoice::INIT:
            OHOS::FuzzQosPolicyInit(fdp);
            break;
        case OHOS::QosFuzzChoice::POLICY_DATA_STRUCTURE:
            OHOS::FuzzQosPolicyDataStructure(fdp);
            break;
        case OHOS::QosFuzzChoice::POLICY_DATAS_STRUCTURE:
            OHOS::FuzzQosPolicyDatasStructure(fdp);
            break;
        case OHOS::QosFuzzChoice::SET_POLICY:
            OHOS::FuzzSetQosPolicy(fdp);
            break;
        case OHOS::QosFuzzChoice::SET_INTERFACE:
            OHOS::FuzzQosPolicySetInterface(fdp);
            break;
        case OHOS::QosFuzzChoice::POLICY_EDGE_CASES:
            OHOS::FuzzPolicyEdgeCases(fdp);
            break;
        case OHOS::QosFuzzChoice::POLICY_FLAGS:
            OHOS::FuzzPolicyFlags(fdp);
            break;
        default:
            break;
    }

    return 0;
}
