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
#define private public
#include "concurrent_task_client.h"
#include "concurrent_task_service_ability.h"
#include "concurrent_task_controller_interface.h"
#undef private
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
const int START_TIME = 20;
const int END_TIME = 40;
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

bool FuzzConcurrentTaskServiceReportData(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = fdp.ConsumeIntegral<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REPORT_DATA);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceReportSceneInfo(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = fdp.ConsumeIntegral<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REPORT_SCENE_INFO);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceQueryInterval(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = fdp.ConsumeIntegral<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_QUERY_INTERVAL);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceQueryDeadline(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = fdp.ConsumeIntegral<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_QUERY_DEADLINE);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceSetAudioDeadline(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = fdp.ConsumeIntegral<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_SET_AUDIO_DEADLINE);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceRequestAuth(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = fdp.ConsumeIntegral<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(IConcurrentTaskServiceIpcCode::COMMAND_REQUEST_AUTH);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceSetThreadQos(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
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
    }
    return true;
}

bool FuzzConcurrentTaskServiceSetQosForOtherThread(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
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
    }
    return true;
}

bool FuzzConcurrentTaskServiceResetThreadQos(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
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
    }
    return true;
}

bool FuzzConcurrentTaskServiceResetQosForOtherThread(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        int tid = fdp.ConsumeIntegral<int>();
        QOS::ResetQosForOtherThread(tid);
    }
    return true;
}

void FuzzQosPolicyInit(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int)) {
        QosPolicy qosPolicy;
        qosPolicy.Init();
    }
    return;
}

bool FuzzQosInterfaceEnableRtg(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        bool flag = fdp.ConsumeIntegral<bool>();
        EnableRtg(flag);
    }
    return true;
}

bool FuzzQosInterfaceQosLeave(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
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
    }
    return true;
}

bool FuzzConcurrentTaskServiceAbilityOnStart(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int32_t) + sizeof(int32_t)) {
        int32_t sysAbilityId = fdp.ConsumeIntegral<int32_t>();
        if ((sysAbilityId > ASSET_SERVICE_ID) && (sysAbilityId < VENDOR_SYS_ABILITY_ID_BEGIN)) {
            bool runOnCreate = true;
            ConcurrentTaskServiceAbility concurrenttaskserviceability =
                ConcurrentTaskServiceAbility(sysAbilityId, runOnCreate);
            concurrenttaskserviceability.OnStart();
        }
    }
    return true;
}

bool FuzzConcurrentTaskServiceAbilityOnAddSystemAbility(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t)) {
        int32_t sysAbilityId = fdp.ConsumeIntegral<int32_t>();
        int32_t taskServiceId = fdp.ConsumeIntegral<int32_t>();
        std::string deviceId = std::to_string(fdp.ConsumeIntegral<int32_t>());
        if ((sysAbilityId > ASSET_SERVICE_ID && sysAbilityId < VENDOR_SYS_ABILITY_ID_BEGIN) &&
            (taskServiceId > ASSET_SERVICE_ID && taskServiceId < VENDOR_SYS_ABILITY_ID_BEGIN)) {
            bool runOnCreate = true;
            ConcurrentTaskServiceAbility concurrenttaskserviceability =
                ConcurrentTaskServiceAbility(taskServiceId, runOnCreate);
            concurrenttaskserviceability.OnAddSystemAbility(sysAbilityId, deviceId);
        }
    }
    return true;
}

bool FuzzConcurrentTaskServiceAbilityOnRemoveSystemAbility(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t)) {
        int32_t sysAbilityId = fdp.ConsumeIntegral<int32_t>();
        int32_t taskServiceId = fdp.ConsumeIntegral<int32_t>();
        std::string deviceId = std::to_string(fdp.ConsumeIntegral<int32_t>());
        if ((sysAbilityId > ASSET_SERVICE_ID && sysAbilityId < VENDOR_SYS_ABILITY_ID_BEGIN) &&
            (taskServiceId > ASSET_SERVICE_ID && taskServiceId < VENDOR_SYS_ABILITY_ID_BEGIN)) {
            bool runOnCreate = true;
            ConcurrentTaskServiceAbility concurrenttaskserviceability =
                ConcurrentTaskServiceAbility(taskServiceId, runOnCreate);
            concurrenttaskserviceability.OnRemoveSystemAbility(sysAbilityId, deviceId);
        }
    }
    return true;
}

bool FuzzConcurrentTaskClientReportData(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(pid_t) + sizeof(uint32_t)) {
        uint32_t resType = fdp.ConsumeIntegral<uint32_t>();
        int64_t value = fdp.ConsumeIntegral<int64_t>();
        std::unordered_map<std::string, std::string> mapPayload;
        mapPayload["218211"] = std::to_string(fdp.ConsumeIntegral<int32_t>());
        ConcurrentTaskClient::GetInstance().ReportData(resType, value, mapPayload);
    }
    return true;
}

bool FuzzConcurrentTaskClientReportSceneInfo(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(pid_t) + sizeof(uint32_t)) {
        uint32_t type = fdp.ConsumeIntegral<uint32_t>();
        std::unordered_map<std::string, std::string> mapPayload;
        mapPayload["218222"] = std::to_string(fdp.ConsumeIntegral<int32_t>());
        ConcurrentTaskClient::GetInstance().ReportSceneInfo(type, mapPayload);
    }
    return true;
}

bool FuzzConcurrentTaskClientQueryInterval(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        int queryItem = fdp.ConsumeIntegral<int>();
        queryItem = queryItem % (QURRY_TYPE_MAX + 1);
        IntervalReply queryRs;
        ConcurrentTaskClient::GetInstance().QueryInterval(queryItem, queryRs);
    }
    return true;
}

bool FuzzConcurrentTaskClientQueryDeadline(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(pid_t) + sizeof(uint32_t)) {
        int queryItem = fdp.ConsumeIntegral<int>();
        queryItem = queryItem % (QURRY_TYPE_MAX + 1);
        DeadlineReply ddlReply;
        pid_t pid = fdp.ConsumeIntegral<pid_t>();
        uint32_t qos = fdp.ConsumeIntegral<uint32_t>();
        std::unordered_map<pid_t, uint32_t> mapPayload;
        mapPayload.insert(std::pair<pid_t, uint32_t>(pid, qos));
        ConcurrentTaskClient::GetInstance().QueryDeadline(queryItem, ddlReply, mapPayload);
    }
    return true;
}

bool FuzzConcurrentTaskClientSetAudioDeadline(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        int queryItem = fdp.ConsumeIntegral<int>();
        queryItem = queryItem % (AUDIO_DDL_REMOVE_THREAD + 1);
        IntervalReply queryRs;
        ConcurrentTaskClient::GetInstance().SetAudioDeadline(queryItem, START_TIME, END_TIME, queryRs);
    }
    return true;
}

bool FuzzConcurrentTaskClinetRequestAuth(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int32_t)) {
        MessageParcel data1;
        std::unordered_map<std::string, std::string> mapPayload;
        mapPayload["2182"] = std::to_string(fdp.ConsumeIntegral<int32_t>());
        ConcurrentTaskClient::GetInstance().RequestAuth(mapPayload);
    }
    return true;
}

bool FuzzConcurrentTaskClientStopRemoteObject(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int)) {
        ConcurrentTaskClient::GetInstance().StopRemoteObject();
    }

    return true;
}

bool FuzzConcurrentTaskControllerInterfaceReportData(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(uint32_t) + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
        uint32_t resType = fdp.ConsumeIntegral<uint32_t>();
        int64_t value = fdp.ConsumeIntegral<int64_t>();
        std::unordered_map<std::string, std::string> payload;
        payload["1111"] = std::to_string(fdp.ConsumeIntegral<uint32_t>());
        payload["2222"] = std::to_string(fdp.ConsumeIntegral<uint32_t>());
        TaskControllerInterface::GetInstance().ReportData(resType, value, payload);
    }
    return true;
}

bool FuzzConcurrentTaskControllerInterfaceReportSceneInfo(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
        uint32_t resType = fdp.ConsumeIntegral<uint32_t>();
        std::unordered_map<std::string, std::string> payload;
        payload["1111"] = std::to_string(fdp.ConsumeIntegral<uint32_t>());
        payload["2222"] = std::to_string(fdp.ConsumeIntegral<uint32_t>());
        TaskControllerInterface::GetInstance().ReportSceneInfo(resType, payload);
    }
    return true;
}

bool FuzzConcurrentTaskControllerInterfaceQueryInterval(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        ConcurrentTaskService s = ConcurrentTaskService();
        int queryItem = fdp.ConsumeIntegral<int>();
        queryItem = queryItem % (QURRY_TYPE_MAX + 1);
        IntervalReply queryRs;
        TaskControllerInterface::GetInstance().QueryInterval(queryItem, queryRs);
    }
    return true;
}

bool FuzzConcurrentTaskControllerInterfaceQueryDeadline(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int) + sizeof(int)) {
        int deadlineType = fdp.ConsumeIntegral<int>();
        deadlineType = deadlineType % (MSG_GAME + 1);
        DeadlineReply queryRs;
        std::unordered_map<std::string, std::string> payload;
        payload["2123"] = std::to_string(fdp.ConsumeIntegral<int>());
        payload["2333"] = std::to_string(fdp.ConsumeIntegral<int>());
        ConcurrentTaskService s = ConcurrentTaskService();
        TaskControllerInterface::GetInstance().QueryDeadline(deadlineType, queryRs, payload);
    }
    return true;
}

bool FuzzConcurrentTaskControllerInterfaceSetAudioDeadline(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        ConcurrentTaskService s = ConcurrentTaskService();
        int queryItem = fdp.ConsumeIntegral<int>();
        queryItem = queryItem % (AUDIO_DDL_REMOVE_THREAD + 1);
        IntervalReply queryRs;
        TaskControllerInterface::GetInstance().SetAudioDeadline(queryItem, START_TIME, END_TIME, queryRs);
    }
    return true;
}

bool FuzzConcurrentTaskControllerInterfaceRequestAuth(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int) + sizeof(int)) {
        std::unordered_map<std::string, std::string> payload;
        payload["2187"] = std::to_string(fdp.ConsumeIntegral<int>());
        payload["2376"] = std::to_string(fdp.ConsumeIntegral<int>());
        ConcurrentTaskService s = ConcurrentTaskService();
        TaskControllerInterface::GetInstance().RequestAuth(payload);
    }
    return true;
}

bool FuzzConcurrentTaskControllerInterfaceInit(const uint8_t* data, size_t size)
{
    TaskControllerInterface::GetInstance().Init();
    return true;
}

bool FuzzConcurrentTaskControllerInterfaceRelease(const uint8_t* data, size_t size)
{
    TaskControllerInterface::GetInstance().Release();
    return true;
}

bool FuzzQosControllerGetThreadQosForOtherThread(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (size > sizeof(int)) {
        enum QosLevel level;
        int tid = fdp.ConsumeIntegral<int>();
        QosController::GetInstance().GetThreadQosForOtherThread(level, tid);
    }
    return true;
}
} // namespace OHOS

static void TaskControllerFuzzTestSuit(const uint8_t *data, size_t size)
{
    OHOS::FuzzQosControllerGetThreadQosForOtherThread(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzConcurrentTaskServiceReportData(data, size);
    OHOS::FuzzConcurrentTaskServiceReportSceneInfo(data, size);
    OHOS::FuzzConcurrentTaskServiceQueryDeadline(data, size);
    OHOS::FuzzConcurrentTaskServiceQueryInterval(data, size);
    OHOS::FuzzConcurrentTaskServiceSetAudioDeadline(data, size);
    OHOS::FuzzConcurrentTaskServiceRequestAuth(data, size);

    OHOS::FuzzConcurrentTaskServiceSetThreadQos(data, size);
    OHOS::FuzzConcurrentTaskServiceSetQosForOtherThread(data, size);
    OHOS::FuzzConcurrentTaskServiceResetThreadQos(data, size);
    OHOS::FuzzConcurrentTaskServiceResetQosForOtherThread(data, size);
    
    OHOS::FuzzQosPolicyInit(data, size);
    OHOS::FuzzQosInterfaceEnableRtg(data, size);
    OHOS::FuzzQosInterfaceQosLeave(data, size);

    OHOS::FuzzConcurrentTaskServiceAbilityOnStart(data, size);
    OHOS::FuzzConcurrentTaskServiceAbilityOnAddSystemAbility(data, size);
    OHOS::FuzzConcurrentTaskServiceAbilityOnRemoveSystemAbility(data, size);

    OHOS::FuzzConcurrentTaskClientReportData(data, size);
    OHOS::FuzzConcurrentTaskClientReportSceneInfo(data, size);
    OHOS::FuzzConcurrentTaskClientQueryDeadline(data, size);
    OHOS::FuzzConcurrentTaskClientQueryInterval(data, size);
    OHOS::FuzzConcurrentTaskClientSetAudioDeadline(data, size);
    OHOS::FuzzConcurrentTaskClinetRequestAuth(data, size);
    OHOS::FuzzConcurrentTaskClientStopRemoteObject(data, size);

    TaskControllerFuzzTestSuit(data, size);
    return 0;
}
