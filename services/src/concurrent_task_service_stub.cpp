/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "concurrent_task_service_stub.h"
#include "concurrent_task_log.h"
#include "concurrent_task_errors.h"
#include "string_ex.h"
#include "ipc_skeleton.h"
#include "ipc_util.h"

namespace OHOS {
namespace ConcurrentTask {
namespace {
    bool IsValidToken(MessageParcel& data)
    {
        std::u16string descriptor = ConcurrentTaskServiceStub::GetDescriptor();
        std::u16string remoteDescriptor = data.ReadInterfaceToken();
        return descriptor == remoteDescriptor;
    }
}

ConcurrentTaskServiceStub::ConcurrentTaskServiceStub()
{
    Init();
}

ConcurrentTaskServiceStub::~ConcurrentTaskServiceStub()
{
    funcMap_.clear();
}

int32_t ConcurrentTaskServiceStub::ReportDataInner(MessageParcel& data, [[maybe_unused]] MessageParcel& reply)
{
    if (!IsValidToken(data)) {
        return ERR_CONCURRENT_TASK_PARCEL_ERROR;
    }
    uint32_t type = 0;
    READ_PARCEL(data, Uint32, type, ERR_CONCURRENT_TASK_PARCEL_ERROR, ConcurrentTaskServiceStub);

    int64_t value = 0;
    READ_PARCEL(data, Int64, value, ERR_CONCURRENT_TASK_PARCEL_ERROR, ConcurrentTaskServiceStub);

    std::string payload;
    READ_PARCEL(data, String, payload, ERR_CONCURRENT_TASK_PARCEL_ERROR, ConcurrentTaskServiceStub);

    if (payload.empty()) {
        return ERR_OK;
    }
    ReportData(type, value, StringToJson(payload));
    return ERR_OK;
}

int32_t ConcurrentTaskServiceStub::QueryIntervalInner(MessageParcel& data, [[maybe_unused]] MessageParcel& reply)
{
    if (!IsValidToken(data)) {
        return ERR_CONCURRENT_TASK_PARCEL_ERROR;
    }
    int item;
    READ_PARCEL(data, Int32, item, ERR_CONCURRENT_TASK_PARCEL_ERROR, ConcurrentTaskServiceStub);
    IntervalReply queryRs;
    queryRs.rtgId = -1;
    queryRs.paramA = -1;
    queryRs.paramB = -1;
    queryRs.paramC = -1;
    QueryInterval(item, queryRs);
    WRITE_PARCEL(reply, Int32, queryRs.rtgId, ERR_CONCURRENT_TASK_PARCEL_ERROR, ConcurrentTaskServiceStub);
    WRITE_PARCEL(reply, Int32, queryRs.paramA, ERR_CONCURRENT_TASK_PARCEL_ERROR, ConcurrentTaskServiceStub);
    WRITE_PARCEL(reply, Int32, queryRs.paramB, ERR_CONCURRENT_TASK_PARCEL_ERROR, ConcurrentTaskServiceStub);
    WRITE_PARCEL(reply, Int32, queryRs.paramC, ERR_CONCURRENT_TASK_PARCEL_ERROR, ConcurrentTaskServiceStub);
    return ERR_OK;
}

int32_t ConcurrentTaskServiceStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    auto uid = IPCSkeleton::GetCallingUid();
    auto pid = IPCSkeleton::GetCallingPid();
    CONCUR_LOGD("ConcurrentTaskServiceStub::OnRemoteRequest, code = %{public}u, flags = %{public}d,"
        " uid = %{public}d pid = %{public}d", code, option.GetFlags(), uid, pid);

    auto itFunc = funcMap_.find(code);
    if (itFunc != funcMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc) {
            return requestFunc(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

Json::Value ConcurrentTaskServiceStub::StringToJson(const std::string& payload)
{
    bool res;
    Json::CharReaderBuilder readerBuilder;
    JSONCPP_STRING errs;
    std::unique_ptr<Json::CharReader> const jsonReader(readerBuilder.newCharReader());
    Json::Value root;
    if (!IsAsciiString(payload)) {
        CONCUR_LOGE("Payload is not ascii string");
        return root;
    }
    try {
        res = jsonReader->parse(payload.c_str(), payload.c_str() + payload.length(), &root, &errs);
    } catch (...) {
        CONCUR_LOGE("Unexpected json parse");
        return root;
    }
    if (!res || !errs.empty()) {
        CONCUR_LOGE("ConcurentTaskServiceStub::payload = %{public}s Incorrect JSON format ", payload.c_str());
    }
    return root;
}

void ConcurrentTaskServiceStub::Init()
{
    funcMap_ = {
        { static_cast<uint32_t>(ConcurrentTaskInterfaceCode::REPORT_DATA),
            [this](auto& data, auto& reply) {return ReportDataInner(data, reply); } },
        { static_cast<uint32_t>(ConcurrentTaskInterfaceCode::QUERY_INTERVAL),
            [this](auto& data, auto& reply) {return QueryIntervalInner(data, reply); } },
    };
}
} // namespace ResourceSchedule
} // namespace OHOS
