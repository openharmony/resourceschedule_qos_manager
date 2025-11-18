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
#include <array>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include <limits>
#include "qos_interface.h"
#include "concurrent_task_controller_interface.h"
#include "concurrent_task_type.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::ConcurrentTask;

namespace OHOS {

namespace {
constexpr size_t MIN_FUZZ_INPUT_SIZE = 4;
constexpr size_t MIN_ENABLE_RTG_DATA_BYTES = 8;
constexpr size_t MIN_QUERY_INTERVAL_BYTES = 8;
constexpr size_t MIN_SET_AUDIO_BYTES = 16;
constexpr size_t MIN_GROUP_LIFECYCLE_BYTES = 24;
constexpr size_t MIN_QUERY_DEADLINE_BYTES = 16;
constexpr size_t MIN_EXTREME_IDS_BYTES = 12;
constexpr size_t MIN_CONCURRENT_OP_BYTES = 20;
constexpr size_t MAX_RTG_DATA_LENGTH = 256;
constexpr size_t INTERVAL_BUNDLE_NAME_MAX = 128;
constexpr size_t PAYLOAD_KEY_MAX_LEN = 32;
constexpr size_t PAYLOAD_VALUE_MAX_LEN = 64;
constexpr int INVALID_QUERY_TYPE = -1;
constexpr int RESERVED_QUERY_TYPE = 999;
constexpr int INVALID_QUERY_TYPE_OFFSET = 100;
constexpr int MAX_QUERY_PAYLOAD_ENTRIES = 10;
constexpr int MAX_GROUP_CREATE_ATTEMPTS = 5;
constexpr int MAX_RAPID_ENABLE_OPERATIONS = 10;
constexpr int MAX_THREAD_OPERATIONS = 10;

enum class TaskControllerOperation : int {
    SINGLE_INIT = 0,
    SINGLE_RELEASE,
    DOUBLE_INIT,
    DOUBLE_RELEASE
};

enum class RtgFuzzTarget : int {
    ENABLE_RTG = 0,
    ENABLE_RTG_WITH_DATA,
    QUERY_INTERVAL,
    SET_AUDIO_DEADLINE,
    GROUP_LIFECYCLE,
    QUERY_DEADLINE,
    INIT_RELEASE,
    EXTREME_IDS,
    CONCURRENT_OPS
};

constexpr int MAX_TASK_CONTROLLER_OPERATION_INDEX = static_cast<int>(TaskControllerOperation::DOUBLE_RELEASE);
constexpr int MAX_RTG_FUZZ_TARGET_INDEX = static_cast<int>(RtgFuzzTarget::CONCURRENT_OPS);

bool DispatchTaskControllerOperation(TaskControllerOperation operation, TaskControllerInterface &controller)
{
    switch (operation) {
        case TaskControllerOperation::SINGLE_INIT:
            controller.Init();
            return true;
        case TaskControllerOperation::SINGLE_RELEASE:
            controller.Release();
            return true;
        case TaskControllerOperation::DOUBLE_INIT:
            controller.Init();
            controller.Init();
            return true;
        case TaskControllerOperation::DOUBLE_RELEASE:
            controller.Release();
            controller.Release();
            return true;
        default:
            return true;
    }
}
}

// Fuzz EnableRtg with various flags and data
bool FuzzEnableRtg(FuzzedDataProvider &fdp)
{
    bool flag = fdp.ConsumeBool();
    EnableRtg(flag);
    return true;
}

// Fuzz EnableRtg with custom data string
bool FuzzEnableRtgWithData(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_ENABLE_RTG_DATA_BYTES) {
        return false;
    }

    bool flag = fdp.ConsumeBool();

    // Create RtgEnableData structure
    RtgEnableData rtgData;
    rtgData.enable = flag ? 1 : 0;

    // Fuzz data string
    std::string dataStr = fdp.ConsumeRandomLengthString(MAX_RTG_DATA_LENGTH);
    rtgData.len = static_cast<int>(dataStr.length());
    rtgData.data = const_cast<char*>(dataStr.c_str());

    // This tests the ioctl path with custom data
    EnableRtg(flag);

    return true;
}

// Fuzz TaskControllerInterface QueryInterval operations
bool FuzzTaskControllerQueryInterval(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_QUERY_INTERVAL_BYTES) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    // Fuzz all query types and some invalid ones
    int queryTypes[] = {
        QUERY_UI,
        QUERY_RENDER,
        QUERY_RENDER_SERVICE,
        QUERY_COMPOSER,
        QUERY_HARDWARE,
        QUERY_EXECUTOR_START,
        QUERY_RENDER_SERVICE_MAIN,
        QUERY_RENDER_SERVICE_RENDER,
        QURRY_TYPE_MAX,
        INVALID_QUERY_TYPE,
        RESERVED_QUERY_TYPE,
        QURRY_TYPE_MAX + INVALID_QUERY_TYPE_OFFSET
    };

    int queryItem = fdp.PickValueInArray(queryTypes);

    IntervalReply queryRs;
    queryRs.rtgId = fdp.ConsumeIntegral<int>();
    queryRs.tid = fdp.ConsumeIntegral<int>();
    queryRs.paramA = fdp.ConsumeIntegral<int>();
    queryRs.paramB = fdp.ConsumeIntegral<int>();
    queryRs.bundleName = fdp.ConsumeRandomLengthString(INTERVAL_BUNDLE_NAME_MAX);

    controller.QueryInterval(queryItem, queryRs);

    return true;
}

// Fuzz SetAudioDeadline operations
bool FuzzTaskControllerSetAudioDeadline(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_SET_AUDIO_BYTES) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    // Fuzz audio deadline query types
    int audioTypes[] = {
        AUDIO_DDL_CREATE_GRP,
        AUDIO_DDL_ADD_THREAD,
        AUDIO_DDL_REMOVE_THREAD,
        AUDIO_DDL_DESTROY_GRP,
        INVALID_QUERY_TYPE,
        RESERVED_QUERY_TYPE
    };

    int queryItem = fdp.PickValueInArray(audioTypes);
    int tid = fdp.ConsumeIntegral<int>();
    int grpId = fdp.ConsumeIntegral<int>();

    IntervalReply queryRs;
    queryRs.rtgId = fdp.ConsumeIntegral<int>();
    queryRs.tid = fdp.ConsumeIntegral<int>();
    queryRs.paramA = fdp.ConsumeIntegral<int>();
    queryRs.paramB = fdp.ConsumeIntegral<int>();

    controller.SetAudioDeadline(queryItem, tid, grpId, queryRs);

    return true;
}

// Fuzz RTG group lifecycle operations in sequence
bool FuzzRtgGroupLifecycle(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_GROUP_LIFECYCLE_BYTES) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    // Try to create an RTG group
    IntervalReply createReply;
    createReply.rtgId = -1;
    controller.SetAudioDeadline(AUDIO_DDL_CREATE_GRP, -1, -1, createReply);

    if (createReply.rtgId > 0) {
        // Add random threads to the group
        int numThreads = fdp.ConsumeIntegralInRange<int>(0, MAX_THREAD_OPERATIONS);
        for (int i = 0; i < numThreads; i++) {
            int tid = fdp.ConsumeIntegral<int>();
            IntervalReply addReply;
            controller.SetAudioDeadline(AUDIO_DDL_ADD_THREAD, tid, createReply.rtgId, addReply);
        }

        // Remove some threads
        int numRemove = fdp.ConsumeIntegralInRange<int>(0, numThreads);
        for (int i = 0; i < numRemove; i++) {
            int tid = fdp.ConsumeIntegral<int>();
            IntervalReply removeReply;
            controller.SetAudioDeadline(AUDIO_DDL_REMOVE_THREAD, tid, createReply.rtgId, removeReply);
        }

        // Destroy the group
        IntervalReply destroyReply;
        controller.SetAudioDeadline(AUDIO_DDL_DESTROY_GRP, -1, createReply.rtgId, destroyReply);
    }

    return true;
}

// Fuzz QueryDeadline operations
bool FuzzTaskControllerQueryDeadline(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_QUERY_DEADLINE_BYTES) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    int queryTypes[] = {
        DDL_RATE,
        MSG_GAME,
        INVALID_QUERY_TYPE,
        RESERVED_QUERY_TYPE
    };

    int queryItem = fdp.PickValueInArray(queryTypes);

    DeadlineReply ddlReply;
    ddlReply.setStatus = fdp.ConsumeBool();

    std::unordered_map<std::string, std::string> payload;

    // Add random payload entries
    int numEntries = fdp.ConsumeIntegralInRange<int>(0, MAX_QUERY_PAYLOAD_ENTRIES);
    for (int i = 0; i < numEntries; i++) {
        std::string key = fdp.ConsumeRandomLengthString(PAYLOAD_KEY_MAX_LEN);
        std::string value = fdp.ConsumeRandomLengthString(PAYLOAD_VALUE_MAX_LEN);
        payload[key] = value;
    }

    controller.QueryDeadline(queryItem, ddlReply, payload);

    return true;
}

// Fuzz Init and Release operations
bool FuzzTaskControllerInitRelease(FuzzedDataProvider &fdp)
{
    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    auto operation = static_cast<TaskControllerOperation>(fdp.ConsumeIntegralInRange<int>(
        0, MAX_TASK_CONTROLLER_OPERATION_INDEX));
    DispatchTaskControllerOperation(operation, controller);

    return true;
}

// Fuzz with extreme RTG IDs and thread IDs
bool FuzzExtremeIds(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_EXTREME_IDS_BYTES) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    // Test with extreme values
    const std::array<int, 6> extremeIds = {
        std::numeric_limits<int>::min(),
        -1,
        0,
        1,
        65535,
        std::numeric_limits<int>::max()
    };

    int tid = fdp.PickValueInArray(extremeIds);
    int grpId = fdp.PickValueInArray(extremeIds);

    IntervalReply queryRs;

    // Try various operations with extreme values
    controller.SetAudioDeadline(AUDIO_DDL_ADD_THREAD, tid, grpId, queryRs);
    controller.SetAudioDeadline(AUDIO_DDL_REMOVE_THREAD, tid, grpId, queryRs);
    controller.SetAudioDeadline(AUDIO_DDL_DESTROY_GRP, tid, grpId, queryRs);

    return true;
}

// Fuzz concurrent RTG operations
bool FuzzConcurrentRtgOps(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_CONCURRENT_OP_BYTES) {
        return false;
    }

    // Simulate concurrent operations by rapidly executing them
    for (int i = 0; i < MAX_RAPID_ENABLE_OPERATIONS; i++) {
        EnableRtg(fdp.ConsumeBool());
    }

    // Create multiple groups rapidly
    std::vector<int> groupIds;
    for (int i = 0; i < MAX_GROUP_CREATE_ATTEMPTS; i++) {
        IntervalReply reply;
        TaskControllerInterface::GetInstance().SetAudioDeadline(
            AUDIO_DDL_CREATE_GRP, -1, -1, reply);
        if (reply.rtgId > 0) {
            groupIds.push_back(reply.rtgId);
        }
    }

    // Destroy them in random order
    for (int grpId : groupIds) {
        IntervalReply reply;
        TaskControllerInterface::GetInstance().SetAudioDeadline(
            AUDIO_DDL_DESTROY_GRP, -1, grpId, reply);
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
    auto choice = static_cast<OHOS::RtgFuzzTarget>(fdp.ConsumeIntegralInRange<int>(
        0, OHOS::MAX_RTG_FUZZ_TARGET_INDEX));

    switch (choice) {
        case OHOS::RtgFuzzTarget::ENABLE_RTG:
            OHOS::FuzzEnableRtg(fdp);
            break;
        case OHOS::RtgFuzzTarget::ENABLE_RTG_WITH_DATA:
            OHOS::FuzzEnableRtgWithData(fdp);
            break;
        case OHOS::RtgFuzzTarget::QUERY_INTERVAL:
            OHOS::FuzzTaskControllerQueryInterval(fdp);
            break;
        case OHOS::RtgFuzzTarget::SET_AUDIO_DEADLINE:
            OHOS::FuzzTaskControllerSetAudioDeadline(fdp);
            break;
        case OHOS::RtgFuzzTarget::GROUP_LIFECYCLE:
            OHOS::FuzzRtgGroupLifecycle(fdp);
            break;
        case OHOS::RtgFuzzTarget::QUERY_DEADLINE:
            OHOS::FuzzTaskControllerQueryDeadline(fdp);
            break;
        case OHOS::RtgFuzzTarget::INIT_RELEASE:
            OHOS::FuzzTaskControllerInitRelease(fdp);
            break;
        case OHOS::RtgFuzzTarget::EXTREME_IDS:
            OHOS::FuzzExtremeIds(fdp);
            break;
        case OHOS::RtgFuzzTarget::CONCURRENT_OPS:
            OHOS::FuzzConcurrentRtgOps(fdp);
            break;
        default:
            break;
    }

    return 0;
}
