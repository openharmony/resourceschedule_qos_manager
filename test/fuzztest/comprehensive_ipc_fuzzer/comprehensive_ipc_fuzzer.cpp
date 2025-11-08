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
#include <string>
#include <unordered_map>
#include "concurrent_task_service.h"
#include "concurrent_task_client.h"
#include "message_parcel.h"
#include "message_option.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::ConcurrentTask;

namespace OHOS {

namespace {
constexpr size_t MIN_FUZZ_INPUT_SIZE = 4;
constexpr size_t MIN_REQUIRED_BYTES = 4;
constexpr size_t MIN_MALFORMED_PARCEL_BYTES = 16;
constexpr size_t MIN_TRUNCATED_PARCEL_BYTES = 8;
constexpr size_t MIN_NEGATIVE_SIZE_BYTES = 8;
constexpr size_t MIN_CLIENT_BYTES = 8;
constexpr size_t MIN_RANDOM_SEQUENCE_BYTES = 12;
constexpr size_t MIN_IPC_CONVERTER_BYTES = 20;
constexpr uint32_t INVALID_IPC_CODE = 999;
constexpr uint32_t INVALID_IPC_CODE_MASK = 0xFFFFFFFF;
constexpr size_t MAX_RANDOM_DATA_SIZE = 512;
constexpr int MAX_OVERSIZED_WRITES = 1000;
constexpr int NEGATIVE_SIZE_MIN_VALUE = -1000;
constexpr int NEGATIVE_SIZE_MAX_VALUE = -1;
constexpr size_t PAYLOAD_STRING_LENGTH = 64;
constexpr uint32_t IPC_CODE_RANDOM_MAX = 10;
constexpr int MAX_TYPE_WRITE_COUNT = 20;
constexpr size_t LONG_PAYLOAD_STRING_LENGTH = 128;
enum class IpcFuzzTarget : int {
    MALFORMED = 0,
    TRUNCATED,
    OVERSIZED,
    NEGATIVE_SIZES,
    CLIENT_WITHOUT_SERVICE,
    RANDOM_TYPE_SEQUENCE,
    EMPTY_PARCEL,
    IPC_DATA_CONVERTERS
};

enum class ClientOperation : int {
    REPORT_DATA = 0,
    REPORT_SCENE_INFO,
    QUERY_INTERVAL,
    QUERY_DEADLINE,
    SET_AUDIO_DEADLINE,
    REQUEST_AUTH
};

enum class ParcelSequenceWriteType : int {
    BOOL_VALUE = 0,
    INT8_VALUE,
    INT16_VALUE,
    INT32_VALUE,
    INT64_VALUE,
    UINT32_VALUE,
    STRING_VALUE,
    DOUBLE_VALUE
};

constexpr int MAX_FUZZ_TARGET_INDEX = static_cast<int>(IpcFuzzTarget::IPC_DATA_CONVERTERS);

void ReportDataOperation(ConcurrentTaskClient &client, FuzzedDataProvider &fdp)
{
    std::unordered_map<std::string, std::string> payload;
    payload["test"] = fdp.ConsumeRandomLengthString(PAYLOAD_STRING_LENGTH);
    client.ReportData(
        fdp.ConsumeIntegral<uint32_t>(),
        fdp.ConsumeIntegral<int64_t>(),
        payload);
}

void ReportSceneInfoOperation(ConcurrentTaskClient &client, FuzzedDataProvider &fdp)
{
    std::unordered_map<std::string, std::string> payload;
    client.ReportSceneInfo(fdp.ConsumeIntegral<uint32_t>(), payload);
}

void QueryIntervalOperation(ConcurrentTaskClient &client, FuzzedDataProvider &fdp)
{
    IntervalReply reply;
    client.QueryInterval(fdp.ConsumeIntegral<int>(), reply);
}

void QueryDeadlineOperation(ConcurrentTaskClient &client, FuzzedDataProvider &fdp)
{
    DeadlineReply reply;
    std::unordered_map<pid_t, uint32_t> payload;
    client.QueryDeadline(fdp.ConsumeIntegral<int>(), reply, payload);
}

void SetAudioDeadlineOperation(ConcurrentTaskClient &client, FuzzedDataProvider &fdp)
{
    IntervalReply reply;
    client.SetAudioDeadline(
        fdp.ConsumeIntegral<int>(),
        fdp.ConsumeIntegral<int>(),
        fdp.ConsumeIntegral<int>(),
        reply);
}

void RequestAuthOperation(ConcurrentTaskClient &client)
{
    std::unordered_map<std::string, std::string> payload;
    client.RequestAuth(payload);
}

bool DispatchClientOperation(ClientOperation operation, ConcurrentTaskClient &client, FuzzedDataProvider &fdp)
{
    switch (operation) {
        case ClientOperation::REPORT_DATA:
            ReportDataOperation(client, fdp);
            return true;
        case ClientOperation::REPORT_SCENE_INFO:
            ReportSceneInfoOperation(client, fdp);
            return true;
        case ClientOperation::QUERY_INTERVAL:
            QueryIntervalOperation(client, fdp);
            return true;
        case ClientOperation::QUERY_DEADLINE:
            QueryDeadlineOperation(client, fdp);
            return true;
        case ClientOperation::SET_AUDIO_DEADLINE:
            SetAudioDeadlineOperation(client, fdp);
            return true;
        case ClientOperation::REQUEST_AUTH:
            RequestAuthOperation(client);
            return true;
        default:
            return true;
    }
}
}

// Fuzz IPC with malformed MessageParcel data
bool FuzzMalformedParcel(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_MALFORMED_PARCEL_BYTES) {
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
            INVALID_IPC_CODE,  // Invalid code
            INVALID_IPC_CODE_MASK  // Invalid code
        };

        uint32_t code = fdp.PickValueInArray(codes);

        // Write random data to parcel
        size_t dataSize = fdp.ConsumeIntegralInRange<size_t>(0, MAX_RANDOM_DATA_SIZE);
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
    if (fdp.remaining_bytes() < MIN_TRUNCATED_PARCEL_BYTES) {
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
    if (fdp.remaining_bytes() < MIN_REQUIRED_BYTES) {
        return false;
    }

    try {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;

        uint32_t code = static_cast<uint32_t>(
            IConcurrentTaskServiceIpcCode::COMMAND_REPORT_DATA);

        // Write huge amounts of data
        for (int i = 0; i < MAX_OVERSIZED_WRITES && fdp.remaining_bytes() > 0; i++) {
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
    if (fdp.remaining_bytes() < MIN_NEGATIVE_SIZE_BYTES) {
        return false;
    }

    try {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;

        uint32_t code = static_cast<uint32_t>(
            IConcurrentTaskServiceIpcCode::COMMAND_QUERY_INTERVAL);

        // Write negative values where positive expected
        data.WriteInt32(fdp.ConsumeIntegralInRange<int32_t>(NEGATIVE_SIZE_MIN_VALUE, NEGATIVE_SIZE_MAX_VALUE));
        data.WriteInt32(fdp.ConsumeIntegralInRange<int32_t>(NEGATIVE_SIZE_MIN_VALUE, NEGATIVE_SIZE_MAX_VALUE));

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
    if (fdp.remaining_bytes() < MIN_CLIENT_BYTES) {
        return false;
    }

    try {
        // Try to use client when service may not be running
        ConcurrentTaskClient& client = ConcurrentTaskClient::GetInstance();
        auto operation = static_cast<ClientOperation>(fdp.ConsumeIntegralInRange<int>(
            0, static_cast<int>(ClientOperation::REQUEST_AUTH)));
        DispatchClientOperation(operation, client, fdp);

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
    if (fdp.remaining_bytes() < MIN_RANDOM_SEQUENCE_BYTES) {
        return false;
    }

    try {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;

        uint32_t code = fdp.ConsumeIntegralInRange<uint32_t>(0, IPC_CODE_RANDOM_MAX);

        // Write random sequence of different types
        int numWrites = fdp.ConsumeIntegralInRange<int>(1, MAX_TYPE_WRITE_COUNT);
        for (int i = 0; i < numWrites && fdp.remaining_bytes() > 0; i++) {
            auto writeType = static_cast<ParcelSequenceWriteType>(fdp.ConsumeIntegralInRange<int>(
                0, static_cast<int>(ParcelSequenceWriteType::DOUBLE_VALUE)));

            switch (writeType) {
                case ParcelSequenceWriteType::BOOL_VALUE:
                    data.WriteBool(fdp.ConsumeBool());
                    break;
                case ParcelSequenceWriteType::INT8_VALUE:
                    data.WriteInt8(fdp.ConsumeIntegral<int8_t>());
                    break;
                case ParcelSequenceWriteType::INT16_VALUE:
                    data.WriteInt16(fdp.ConsumeIntegral<int16_t>());
                    break;
                case ParcelSequenceWriteType::INT32_VALUE:
                    data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
                    break;
                case ParcelSequenceWriteType::INT64_VALUE:
                    data.WriteInt64(fdp.ConsumeIntegral<int64_t>());
                    break;
                case ParcelSequenceWriteType::UINT32_VALUE:
                    data.WriteUint32(fdp.ConsumeIntegral<uint32_t>());
                    break;
                case ParcelSequenceWriteType::STRING_VALUE:
                    data.WriteString(fdp.ConsumeRandomLengthString(PAYLOAD_STRING_LENGTH));
                    break;
                case ParcelSequenceWriteType::DOUBLE_VALUE:
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
    if (fdp.remaining_bytes() < MIN_IPC_CONVERTER_BYTES) {
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
        ipcReply.bundleName = fdp.ConsumeRandomLengthString(LONG_PAYLOAD_STRING_LENGTH);

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
    if (size < MIN_FUZZ_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Randomly choose which fuzzing function to execute
    auto choice = static_cast<IpcFuzzTarget>(fdp.ConsumeIntegralInRange<int>(
        0, MAX_FUZZ_TARGET_INDEX));

    switch (choice) {
        case IpcFuzzTarget::MALFORMED:
            OHOS::FuzzMalformedParcel(fdp);
            break;
        case IpcFuzzTarget::TRUNCATED:
            OHOS::FuzzTruncatedParcel(fdp);
            break;
        case IpcFuzzTarget::OVERSIZED:
            OHOS::FuzzOversizedData(fdp);
            break;
        case IpcFuzzTarget::NEGATIVE_SIZES:
            OHOS::FuzzNegativeSizes(fdp);
            break;
        case IpcFuzzTarget::CLIENT_WITHOUT_SERVICE:
            OHOS::FuzzClientWithoutService(fdp);
            break;
        case IpcFuzzTarget::RANDOM_TYPE_SEQUENCE:
            OHOS::FuzzRandomTypeSequence(fdp);
            break;
        case IpcFuzzTarget::EMPTY_PARCEL:
            OHOS::FuzzEmptyParcel(fdp);
            break;
        case IpcFuzzTarget::IPC_DATA_CONVERTERS:
            OHOS::FuzzIpcDataConverters(fdp);
            break;
        default:
            break;
    }

    return 0;
}
