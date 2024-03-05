/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#undef private
#include "concurrent_task_service_proxy.h"
#include "concurrent_task_service.h"
#include "securec.h"
#include "qos.h"
#include "qos_interface.h"
#include "qos_policy.h"
#include "concurrent_task_client.h"
#include "system_ability_definition.h"
#include "concurrent_fuzzer.h"

using namespace OHOS::ConcurrentTask;
using namespace OHOS::QOS;

namespace OHOS {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;
#define  QUADRUPLE  4

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
template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (g_baseFuzzData == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    ErrCode ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
    if (ret != ERR_OK) {
        return {};
    }
    g_baseFuzzPos += objectSize;
    return object;
}

bool FuzzConcurrentTaskTryConnect(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    if (size < sizeof(int32_t)) {
        return false;
    }
    return ConcurrentTaskClient::GetInstance().TryConnect() == ERR_OK;
}

bool FuzzConcurrentTaskServiceReportData(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = GetData<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::REPORT_DATA);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceQueryInterval(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = GetData<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::QUERY_INTERVAL);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceQueryDeadline(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = GetData<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::QUERY_DEADLINE);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceRequestAuth(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        MessageParcel data1;
        Parcel parcel;
        sptr<IRemoteObject> iremoteobject = IRemoteObject::Unmarshalling(parcel);
        int intdata = GetData<int>();
        void *voiddata = &intdata;
        size_t size1 = sizeof(int);
        data1.WriteRemoteObject(iremoteobject);
        data1.WriteRawData(voiddata, size1);
        data1.ReadRawData(size1);
        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::REQUEST_AUTH);
        ConcurrentTaskService s = ConcurrentTaskService();
        s.OnRemoteRequest(code, data1, reply, option);
    }
    return true;
}

bool FuzzConcurrentTaskServiceStopRemoteObject(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    ConcurrentTaskClient::GetInstance().StopRemoteObject();
    return true;
}

bool FuzzConcurrentTaskServiceSetThreadQos(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        int level = GetData<int>();
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
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        int level = GetData<int>();
        int tid = GetData<int>();
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
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    QOS::ResetThreadQos();
    return true;
}

bool FuzzConcurrentTaskServiceResetQosForOtherThread(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        int tid = GetData<int>();
        QOS::ResetQosForOtherThread(tid);
    }
    return true;
}

void FuzzQosPolicyInit(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    QosPolicy qosPolicy;
    qosPolicy.Init();
    return;
}

bool FuzzQosInterfaceEnableRtg(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        bool flag = GetData<bool>();
        EnableRtg(flag);
    }
    return true;
}

bool FuzzQosInterfaceAuthEnable(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int)) {
        unsigned int pid = GetData<unsigned int>();
        unsigned int uaFlag = GetData<unsigned int>();
        unsigned int status = GetData<unsigned int>();
        AuthEnable(pid, uaFlag, status);
    }
    return true;
}

bool FuzzQosInterfaceAuthSwitch(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > QUADRUPLE * sizeof(unsigned int)) {
        unsigned int pid = GetData<unsigned int>();
        unsigned int rtgFlag = GetData<unsigned int>();
        unsigned int qosFlag = GetData<unsigned int>();
        unsigned int status = GetData<unsigned int>();
        AuthSwitch(pid, rtgFlag, qosFlag, status);
    }
    return true;
}

bool FuzzQosInterfaceAuthPause(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(unsigned int) + sizeof(unsigned int)) {
        unsigned int pid = GetData<unsigned int>();
        AuthPause(pid);
    }
    return true;
}

bool FuzzQosInterfaceAuthGet(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(unsigned int) + sizeof(unsigned int)) {
        unsigned int pid = GetData<unsigned int>();
        AuthGet(pid);
    }
    return true;
}

bool FuzzQosInterfaceAuthEnhance(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(unsigned int) + sizeof(unsigned int)) {
        unsigned int pid = GetData<unsigned int>();
        bool enhanceStatus = GetData<bool>();
        AuthEnhance(pid, enhanceStatus);
    }
    return true;
}

bool FuzzQosInterfaceQosLeave(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    QosLeave();
    return true;
}

bool FuzzConcurrentTaskServiceAbilityOnStart(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool runOnCreate = true;
    if (size > sizeof(int32_t) + sizeof(int32_t)) {
        int32_t sysAbilityId = GetData<int32_t>();
        if ((sysAbilityId > ASSET_SERVICE_ID) && (sysAbilityId < VENDOR_SYS_ABILITY_ID_BEGIN)) {
            ConcurrentTaskServiceAbility concurrenttaskserviceability =
                ConcurrentTaskServiceAbility(sysAbilityId, runOnCreate);
            concurrenttaskserviceability.OnStart();
        }
    }
    return true;
}

bool FuzzConcurrentTaskServiceAbilityOnStop(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool runOnCreate = true;
    if (size > sizeof(int32_t) + sizeof(int32_t)) {
        int32_t sysAbilityId = GetData<int32_t>();
        if ((sysAbilityId > ASSET_SERVICE_ID) && (sysAbilityId < VENDOR_SYS_ABILITY_ID_BEGIN)) {
            ConcurrentTaskServiceAbility concurrenttaskserviceability =
                ConcurrentTaskServiceAbility(sysAbilityId, runOnCreate);
            concurrenttaskserviceability.OnStop();
        }
    }
    return true;
}

bool FuzzConcurrentTaskServiceAbilityOnAddSystemAbility(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t)) {
        bool runOnCreate = true;
        int32_t sysAbilityId = GetData<int32_t>();
        int32_t taskServiceId = GetData<int32_t>();
        std::string deviceId = std::to_string(GetData<int32_t>());
        if ((sysAbilityId > ASSET_SERVICE_ID && sysAbilityId < VENDOR_SYS_ABILITY_ID_BEGIN) &&
            (taskServiceId > ASSET_SERVICE_ID && taskServiceId < VENDOR_SYS_ABILITY_ID_BEGIN)) {
            ConcurrentTaskServiceAbility concurrenttaskserviceability =
                ConcurrentTaskServiceAbility(taskServiceId, runOnCreate);
            concurrenttaskserviceability.OnAddSystemAbility(sysAbilityId, deviceId);
        }
    }
    return true;
}

bool FuzzConcurrentTaskServiceAbilityOnRemoveSystemAbility(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t)) {
        bool runOnCreate = true;
        int32_t sysAbilityId = GetData<int32_t>();
        int32_t taskServiceId = GetData<int32_t>();
        std::string deviceId = std::to_string(GetData<int32_t>());
        if ((sysAbilityId > ASSET_SERVICE_ID && sysAbilityId < VENDOR_SYS_ABILITY_ID_BEGIN) &&
            (taskServiceId > ASSET_SERVICE_ID && taskServiceId < VENDOR_SYS_ABILITY_ID_BEGIN)) {
            ConcurrentTaskServiceAbility concurrenttaskserviceability =
                ConcurrentTaskServiceAbility(taskServiceId, runOnCreate);
            concurrenttaskserviceability.OnRemoveSystemAbility(sysAbilityId, deviceId);
        }
    }
    return true;
}

bool FuzzConcurrentTaskServiceStubReportData(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(uint32_t) + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
        ConcurrentTaskService s = ConcurrentTaskService();
        uint32_t resType = GetData<uint32_t>();
        int64_t value = GetData<int64_t>();
        Json::Value jsValue;
        jsValue["1111"] = std::to_string(GetData<uint32_t>());
        jsValue["2222"] = std::to_string(GetData<uint32_t>());
        s.ReportData(resType, value, jsValue);
    }
    return true;
}

bool FuzzConcurrentTaskServiceStubQueryInterval(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        ConcurrentTaskService s = ConcurrentTaskService();
        int queryItem = GetData<int>();
        queryItem = queryItem % (QURRY_TYPE_MAX + 1);
        IntervalReply queryRs;
        s.QueryInterval(queryItem, queryRs);
    }
    return true;
}

bool FuzzConcurrentTaskServiceStubQueryDeadline(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int) + sizeof(int)) {
        int deadlineType = GetData<int>();
        deadlineType = deadlineType % (MSG_GAME + 1);
        DeadlineReply queryRs;
        Json::Value jsValue;
        jsValue["2123"] = std::to_string(GetData<int>());
        jsValue["2333"] = std::to_string(GetData<int>());
        ConcurrentTaskService s = ConcurrentTaskService();
        s.QueryDeadline(deadlineType, queryRs, jsValue);
    }
    return true;
}

bool FuzzConcurrentTaskServiceStubRequestAuth(const uint8_t* data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    if (size > sizeof(int) + sizeof(int)) {
        Json::Value payload;
        payload["2187"] = std::to_string(GetData<int>());
        payload["2376"] = std::to_string(GetData<int>());
        ConcurrentTaskService s = ConcurrentTaskService();
        s.RequestAuth(payload);
    }
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzConcurrentTaskTryConnect(data, size);
    OHOS::FuzzConcurrentTaskServiceReportData(data, size);
    OHOS::FuzzConcurrentTaskServiceRequestAuth(data, size);
    OHOS::FuzzConcurrentTaskServiceQueryInterval(data, size);
    OHOS::FuzzConcurrentTaskServiceStopRemoteObject(data, size);
    OHOS::FuzzConcurrentTaskServiceSetThreadQos(data, size);
    OHOS::FuzzConcurrentTaskServiceSetQosForOtherThread(data, size);
    OHOS::FuzzConcurrentTaskServiceResetThreadQos(data, size);
    OHOS::FuzzConcurrentTaskServiceResetQosForOtherThread(data, size);
    OHOS::FuzzConcurrentTaskServiceQueryDeadline(data, size);
    OHOS::FuzzQosPolicyInit(data, size);
    OHOS::FuzzQosInterfaceEnableRtg(data, size);
    OHOS::FuzzQosInterfaceAuthEnable(data, size);
    OHOS::FuzzQosInterfaceAuthSwitch(data, size);
    OHOS::FuzzQosInterfaceAuthGet(data, size);
    OHOS::FuzzQosInterfaceAuthEnhance(data, size);
    OHOS::FuzzQosInterfaceAuthPause(data, size);
    OHOS::FuzzQosInterfaceQosLeave(data, size);
    OHOS::FuzzConcurrentTaskServiceStubReportData(data, size);
    OHOS::FuzzConcurrentTaskServiceStubQueryInterval(data, size);
    OHOS::FuzzConcurrentTaskServiceStubQueryDeadline(data, size);
    OHOS::FuzzConcurrentTaskServiceStubRequestAuth(data, size);
    OHOS::FuzzConcurrentTaskServiceAbilityOnStart(data, size);
    OHOS::FuzzConcurrentTaskServiceAbilityOnStop(data, size);
    OHOS::FuzzConcurrentTaskServiceAbilityOnAddSystemAbility(data, size);
    OHOS::FuzzConcurrentTaskServiceAbilityOnRemoveSystemAbility(data, size);
    return 0;
}
