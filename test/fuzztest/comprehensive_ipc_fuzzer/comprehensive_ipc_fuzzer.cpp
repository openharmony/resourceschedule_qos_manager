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
#include "concurrent_task_service.h"
#include "concurrent_task_client.h"
#include "message_parcel.h"
#include "message_option.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::ConcurrentTask;

namespace OHOS {

// Fuzz IPC with malformed MessageParcel data
bool FuzzMalformedParcel(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 16) {
        return false;
    }

    try {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;

        // Choose random IPC code
        uint32_t codes[] = {
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REPORT_DATA),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REPORT_SCENE_INFO),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_QUERY_INTERVAL),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_QUERY_DEADLINE),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_SET_AUDIO_DEADLINE),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REQUEST_AUTH),
            999,  // Invalid code
            0xFFFFFFFF  // Invalid code
        };

        uint32_t code = fdp.PickValueInArray(codes);

        // Write random data to parcel
        size_t dataSize = fdp.ConsumeIntegralInRange<size_t>(0, 512);
        std::vector<uint8_t> randomData = fdp.ConsumeBytes<uint8_t>(dataSize);

        if (!randomData.empty()) {
            data.WriteBuffer(randomData.data(), randomData.size());
        }

        // Send to service
        ConcurrentTaskService service;
        service.OnRemoteRequest(code, data, reply, option);
    } catch (...) {
        // Catch exceptions
    }

    return true;
}

// Fuzz with truncated parcels
bool FuzzTruncatedParcel(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 8) {
        return false;
    }

    try {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;

        uint32_t code = static_cast<uint32_t>(
            IConcurrentTaskServiceIpcCode::COMMAND_REPORT_DATA);

        // Write incomplete data (should cause parsing errors)
        data.WriteUint32(fdp.ConsumeIntegral<uint32_t>());
        // Don't write the rest of expected data

        ConcurrentTaskService service;
        service.OnRemoteRequest(code, data, reply, option);
    } catch (...) {
        // Expected to fail
    }

    return true;
}

// Fuzz with oversized data
bool FuzzOversizedData(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 4) {
        return false;
    }

    try {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;

        uint32_t code = static_cast<uint32_t>(
            IConcurrentTaskServiceIpcCode::COMMAND_REPORT_DATA);

        // Write huge amounts of data
        for (int i = 0; i < 1000 && fdp.remaining_bytes() > 0; i++) {
            data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
        }

        ConcurrentTaskService service;
        service.OnRemoteRequest(code, data, reply, option);
    } catch (...) {
        // May fail due to size limits
    }

    return true;
}

// Fuzz with negative sizes
bool FuzzNegativeSizes(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 8) {
        return false;
    }

    try {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;

        uint32_t code = static_cast<uint32_t>(
            IConcurrentTaskServiceIpcCode::COMMAND_QUERY_INTERVAL);

        // Write negative values where positive expected
        data.WriteInt32(fdp.ConsumeIntegralInRange<int32_t>(-1000, -1));
        data.WriteInt32(fdp.ConsumeIntegralInRange<int32_t>(-1000, -1));

        ConcurrentTaskService service;
        service.OnRemoteRequest(code, data, reply, option);
    } catch (...) {
        // Expected
    }

    return true;
}

// Fuzz Client with service unavailable
bool FuzzClientWithoutService(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 8) {
        return false;
    }

    try {
        // Try to use client when service may not be running
        ConcurrentTaskClient& client = ConcurrentTaskClient::GetInstance();

        int operation = fdp.ConsumeIntegralInRange<int>(0, 5);

        switch (operation) {
            case 0: {
                std::unordered_map<std::string, std::string> payload;
                payload["test"] = fdp.ConsumeRandomLengthString(64);
                client.ReportData(
                    fdp.ConsumeIntegral<uint32_t>(),
                    fdp.ConsumeIntegral<int64_t>(),
                    payload);
                break;
            }
            case 1: {
                std::unordered_map<std::string, std::string> payload;
                client.ReportSceneInfo(fdp.ConsumeIntegral<uint32_t>(), payload);
                break;
            }
            case 2: {
                IntervalReply reply;
                client.QueryInterval(fdp.ConsumeIntegral<int>(), reply);
                break;
            }
            case 3: {
                DeadlineReply reply;
                std::unordered_map<pid_t, uint32_t> payload;
                client.QueryDeadline(fdp.ConsumeIntegral<int>(), reply, payload);
                break;
            }
            case 4: {
                IntervalReply reply;
                client.SetAudioDeadline(
                    fdp.ConsumeIntegral<int>(),
                    fdp.ConsumeIntegral<int>(),
                    fdp.ConsumeIntegral<int>(),
                    reply);
                break;
            }
            case 5: {
                std::unordered_map<std::string, std::string> payload;
                client.RequestAuth(payload);
                break;
            }
        }

        // Test stop and reconnect
        client.StopRemoteObject();
    } catch (...) {
        // May throw if service unavailable
    }

    return true;
}

// Fuzz MessageParcel with random type sequences
bool FuzzRandomTypeSequence(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 12) {
        return false;
    }

    try {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;

        uint32_t code = fdp.ConsumeIntegralInRange<uint32_t>(0, 10);

        // Write random sequence of different types
        int numWrites = fdp.ConsumeIntegralInRange<int>(1, 20);
        for (int i = 0; i < numWrites && fdp.remaining_bytes() > 0; i++) {
            int writeType = fdp.ConsumeIntegralInRange<int>(0, 7);

            switch (writeType) {
                case 0:
                    data.WriteBool(fdp.ConsumeBool());
                    break;
                case 1:
                    data.WriteInt8(fdp.ConsumeIntegral<int8_t>());
                    break;
                case 2:
                    data.WriteInt16(fdp.ConsumeIntegral<int16_t>());
                    break;
                case 3:
                    data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
                    break;
                case 4:
                    data.WriteInt64(fdp.ConsumeIntegral<int64_t>());
                    break;
                case 5:
                    data.WriteUint32(fdp.ConsumeIntegral<uint32_t>());
                    break;
                case 6:
                    data.WriteString(fdp.ConsumeRandomLengthString(64));
                    break;
                case 7:
                    data.WriteDouble(fdp.ConsumeFloatingPoint<double>());
                    break;
            }
        }

        ConcurrentTaskService service;
        service.OnRemoteRequest(code, data, reply, option);
    } catch (...) {
        // Expected to fail with mismatched types
    }

    return true;
}

// Fuzz with empty parcels
bool FuzzEmptyParcel(FuzzedDataProvider &fdp)
{
    try {
        MessageParcel data;  // Empty
        MessageParcel reply;
        MessageOption option;

        // All valid codes with empty data
        uint32_t codes[] = {
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REPORT_DATA),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REPORT_SCENE_INFO),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_QUERY_INTERVAL),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_QUERY_DEADLINE),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_SET_AUDIO_DEADLINE),
            static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REQUEST_AUTH),
        };

        for (uint32_t code : codes) {
            MessageParcel emptyData;
            ConcurrentTaskService service;
            service.OnRemoteRequest(code, emptyData, reply, option);
        }
    } catch (...) {
        // Expected
    }

    return true;
}

// Fuzz IPC data converters
bool FuzzIpcDataConverters(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < 20) {
        return false;
    }

    try {
        ConcurrentTaskService service;

        // Test IpcIntervalReply <-> IntervalReply conversion
        IpcIntervalReply ipcReply;
        ipcReply.rtgId = fdp.ConsumeIntegral<int>();
        ipcReply.tid = fdp.ConsumeIntegral<int>();
        ipcReply.paramA = fdp.ConsumeIntegral<int>();
        ipcReply.paramB = fdp.ConsumeIntegral<int>();
        ipcReply.bundleName = fdp.ConsumeRandomLengthString(128);

        IntervalReply converted = service.IpcToQueryRs(ipcReply);
        IpcIntervalReply backConverted = service.QueryRsToIpc(converted);

        // Test IpcDeadlineReply conversion
        IpcDeadlineReply ipcDdl;
        ipcDdl.setStatus = fdp.ConsumeBool();

        DeadlineReply ddlConverted = service.IpcToDdlReply(ipcDdl);

        (void)backConverted;
        (void)ddlConverted;
    } catch (...) {
        // Should not throw
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
    int choice = fdp.ConsumeIntegralInRange<int>(0, 7);

    switch (choice) {
        case 0:
            OHOS::FuzzMalformedParcel(fdp);
            break;
        case 1:
            OHOS::FuzzTruncatedParcel(fdp);
            break;
        case 2:
            OHOS::FuzzOversizedData(fdp);
            break;
        case 3:
            OHOS::FuzzNegativeSizes(fdp);
            break;
        case 4:
            OHOS::FuzzClientWithoutService(fdp);
            break;
        case 5:
            OHOS::FuzzRandomTypeSequence(fdp);
            break;
        case 6:
            OHOS::FuzzEmptyParcel(fdp);
            break;
        case 7:
            OHOS::FuzzIpcDataConverters(fdp);
            break;
    }

    return 0;
}
