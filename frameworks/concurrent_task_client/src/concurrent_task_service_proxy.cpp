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
        return;
    }
    if (!data.WriteUint32(resType)) {
        return;
    }
    if (!data.WriteInt64(value)) {
        return;
    }
    if (!data.WriteString(payload.toStyledString())) {
        return;
    }
    error = Remote()->SendRequest(IConcurrentTaskService::REPORT_DATA, data, reply, option);
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
    queryRs.rtgId = -1;
    queryRs.paramA = -1;
    queryRs.paramB = -1;
    queryRs.paramC = -1;
    if (!data.WriteInterfaceToken(ConcurrentTaskServiceProxy::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt64(queryItem)) {
        return;
    }
    error = Remote()->SendRequest(IConcurrentTaskService::QUERY_INTERVAL, data, reply, option);
    if (error != NO_ERROR) {
        CONCUR_LOGE("QueryInterval error: %{public}d", error);
        return;
    }
    if (!reply.ReadInt32(queryRs.rtgId)) {
        return;
    }
    if (!reply.ReadInt32(queryRs.paramA)) {
        return;
    }
    if (!reply.ReadInt32(queryRs.paramB)) {
        return;
    }
    if (!reply.ReadInt32(queryRs.paramC)) {
        return;
    }
    return;
}
} // namespace ConcurrentTask
} // namespace OHOS