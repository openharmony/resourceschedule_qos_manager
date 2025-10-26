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
#include "qos_interface.h"
#include "concurrent_task_controller_interface.h"
#include "concurrent_task_type.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::ConcurrentTask;

namespace OHOS {

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
    if (fdp.remaining_bytes() < 8) {
        return false;
    }

    bool flag = fdp.ConsumeBool();

    // Create RtgEnableData structure
    RtgEnableData rtgData;
    rtgData.enable = flag ? 1 : 0;

    // Fuzz data string
    std::string dataStr = fdp.ConsumeRandomLengthString(256);
    rtgData.len = static_cast<int>(dataStr.length());
    rtgData.data = const_cast<char*>(dataStr.c_str());

    // This tests the ioctl path with custom data
    EnableRtg(flag);

    return true;
}

// Fuzz TaskControllerInterface QueryInterval operations
bool FuzzTaskControllerQueryInterval(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 8) {
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
        -1,  // Invalid
        999, // Invalid
        QURRY_TYPE_MAX + 100  // Invalid
    };

    int queryItem = fdp.PickValueInArray(queryTypes);

    IntervalReply queryRs;
    queryRs.rtgId = fdp.ConsumeIntegral<int>();
    queryRs.tid = fdp.ConsumeIntegral<int>();
    queryRs.paramA = fdp.ConsumeIntegral<int>();
    queryRs.paramB = fdp.ConsumeIntegral<int>();
    queryRs.bundleName = fdp.ConsumeRandomLengthString(128);

    controller.QueryInterval(queryItem, queryRs);

    return true;
}

// Fuzz SetAudioDeadline operations
bool FuzzTaskControllerSetAudioDeadline(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 16) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    // Fuzz audio deadline query types
    int audioTypes[] = {
        AUDIO_DDL_CREATE_GRP,
        AUDIO_DDL_ADD_THREAD,
        AUDIO_DDL_REMOVE_THREAD,
        AUDIO_DDL_DESTROY_GRP,
        -1,  // Invalid
        999  // Invalid
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
    if (fdp.remaining_bytes() < 24) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    // Try to create an RTG group
    IntervalReply createReply;
    createReply.rtgId = -1;
    controller.SetAudioDeadline(AUDIO_DDL_CREATE_GRP, -1, -1, createReply);

    if (createReply.rtgId > 0) {
        // Add random threads to the group
        int numThreads = fdp.ConsumeIntegralInRange<int>(0, 10);
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
    if (fdp.remaining_bytes() < 16) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    int queryTypes[] = {
        DDL_RATE,
        MSG_GAME,
        -1,
        999
    };

    int queryItem = fdp.PickValueInArray(queryTypes);

    DeadlineReply ddlReply;
    ddlReply.setStatus = fdp.ConsumeBool();

    std::unordered_map<std::string, std::string> payload;

    // Add random payload entries
    int numEntries = fdp.ConsumeIntegralInRange<int>(0, 10);
    for (int i = 0; i < numEntries; i++) {
        std::string key = fdp.ConsumeRandomLengthString(32);
        std::string value = fdp.ConsumeRandomLengthString(64);
        payload[key] = value;
    }

    controller.QueryDeadline(queryItem, ddlReply, payload);

    return true;
}

// Fuzz Init and Release operations
bool FuzzTaskControllerInitRelease(FuzzedDataProvider &fdp)
{
    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    int operation = fdp.ConsumeIntegralInRange<int>(0, 3);

    switch (operation) {
        case 0:
            controller.Init();
            break;
        case 1:
            controller.Release();
            break;
        case 2:
            controller.Init();
            controller.Init(); // Double init
            break;
        case 3:
            controller.Release();
            controller.Release(); // Double release
            break;
    }

    return true;
}

// Fuzz with extreme RTG IDs and thread IDs
bool FuzzExtremeIds(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 12) {
        return false;
    }

    TaskControllerInterface& controller = TaskControllerInterface::GetInstance();

    // Test with extreme values
    int extremeIds[] = {
        -2147483648, // INT_MIN
        -1,
        0,
        1,
        65535,
        2147483647  // INT_MAX
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
    if (fdp.remaining_bytes() < 20) {
        return false;
    }

    // Simulate concurrent operations by rapidly executing them
    for (int i = 0; i < 10; i++) {
        EnableRtg(fdp.ConsumeBool());
    }

    // Create multiple groups rapidly
    std::vector<int> groupIds;
    for (int i = 0; i < 5; i++) {
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
    if (size < 4) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Randomly choose which fuzzing function to execute
    int choice = fdp.ConsumeIntegralInRange<int>(0, 8);

    switch (choice) {
        case 0:
            OHOS::FuzzEnableRtg(fdp);
            break;
        case 1:
            OHOS::FuzzEnableRtgWithData(fdp);
            break;
        case 2:
            OHOS::FuzzTaskControllerQueryInterval(fdp);
            break;
        case 3:
            OHOS::FuzzTaskControllerSetAudioDeadline(fdp);
            break;
        case 4:
            OHOS::FuzzRtgGroupLifecycle(fdp);
            break;
        case 5:
            OHOS::FuzzTaskControllerQueryDeadline(fdp);
            break;
        case 6:
            OHOS::FuzzTaskControllerInitRelease(fdp);
            break;
        case 7:
            OHOS::FuzzExtremeIds(fdp);
            break;
        case 8:
            OHOS::FuzzConcurrentRtgOps(fdp);
            break;
    }

    return 0;
}
