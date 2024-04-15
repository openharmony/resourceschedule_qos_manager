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

#include "concurrent_task_service_proxy.h"
#include "concurrent_task_log.h"
#include "concurrent_task_errors.h"

namespace OHOS {
namespace ConcurrentTask {
void ConcurrentTaskServiceProxy::ReportData(uint32_t resType, int64_t value, const Json::Value& payload)
{
    int32_t error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (!data.WriteInterfaceToken(ConcurrentTaskServiceProxy::GetDescriptor())) {
        CONCUR_LOGE("Write interface token failed in ReportData Proxy");
        return;
    }
    if (!data.WriteUint32(resType) || !data.WriteInt64(value) || !data.WriteString(payload.toStyledString())) {
        CONCUR_LOGE("Write info failed in ReportData Proxy");
        return;
    }
    uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::REPORT_DATA);
    error = Remote()->SendRequest(code, data, reply, option);
    if (error != NO_ERROR) {
        CONCUR_LOGE("Send request error: %{public}d", error);
        return;
    }
    CONCUR_LOGD("ConcurrentTaskServiceProxy::ReportData success.");
}

void ConcurrentTaskServiceProxy::QueryInterval(int queryItem, IntervalReply& queryRs)
{
    int32_t error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };

    if (!data.WriteInterfaceToken(ConcurrentTaskServiceProxy::GetDescriptor())) {
        CONCUR_LOGE("Write interface token failed in QueryInterval Proxy");
        return;
    }
    if (!data.WriteInt32(queryItem) || !data.WriteInt32(queryRs.tid)) {
        CONCUR_LOGE("Write info failed in QueryInterval Proxy");
        return;
    }

    uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::QUERY_INTERVAL);
    error = Remote()->SendRequest(code, data, reply, option);
    if (error != NO_ERROR) {
        CONCUR_LOGE("QueryInterval error: %{public}d", error);
        return;
    }
    queryRs.rtgId = -1;
    queryRs.tid = -1;
    queryRs.paramA = -1;
    queryRs.paramB = -1;
    queryRs.bundleName = "";

    if (!reply.ReadInt32(queryRs.rtgId) || !reply.ReadInt32(queryRs.tid)
        || !reply.ReadInt32(queryRs.paramA) || !reply.ReadInt32(queryRs.paramB)
        || !reply.ReadString(queryRs.bundleName)) {
        CONCUR_LOGE("Read info failed in QueryInterval Proxy");
        return;
    }
    return;
}

void ConcurrentTaskServiceProxy::QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload)
{
    int32_t error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };

    if (!data.WriteInterfaceToken(ConcurrentTaskServiceProxy::GetDescriptor())) {
        CONCUR_LOGE("Write interface token failed in QueryDeadline Proxy");
        return;
    }
    if (!data.WriteInt32(queryItem) || !data.WriteString(payload.toStyledString())) {
        CONCUR_LOGE("Write info failed in QueryDeadline Proxy");
        return;
    }
    uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::QUERY_DEADLINE);
    error = Remote()->SendRequest(code, data, reply, option);
    if (error != NO_ERROR) {
        CONCUR_LOGE("QueryDeadline error: %{public}d", error);
        return;
    }
    CONCUR_LOGD("ConcurrentTaskServiceProxy::QueryDeadline success.");
}

void ConcurrentTaskServiceProxy::RequestAuth(const Json::Value& payload)
{
    int32_t error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    if (!data.WriteInterfaceToken(ConcurrentTaskServiceProxy::GetDescriptor())) {
        CONCUR_LOGE("Write interface token failed in RequestAuth Proxy");
        return;
    }
    if (!data.WriteString(payload.toStyledString())) {
        CONCUR_LOGE("Write info failed in RequestAuth Proxy");
        return;
    }
    uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::REQUEST_AUTH);
    error = Remote()->SendRequest(code, data, reply, option);
    if (error != NO_ERROR) {
        CONCUR_LOGE("Send request error: %{public}d", error);
        return;
    }
    CONCUR_LOGD("ConcurrentTaskServiceProxy::RequestAuth success.");
}
} // namespace ConcurrentTask
} // namespace OHOS
