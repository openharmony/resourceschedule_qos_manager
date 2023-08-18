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
#include "ipc_util.h"

namespace OHOS {
namespace ConcurrentTask {
void ConcurrentTaskServiceProxy::ReportData(uint32_t resType, int64_t value, const Json::Value& payload)
{
    int32_t error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    WRITE_PARCEL(data, InterfaceToken, ConcurrentTaskServiceProxy::GetDescriptor(), , ConcurrentTaskServiceProxy);
    WRITE_PARCEL(data, Uint32, resType, , ConcurrentTaskServiceProxy);
    WRITE_PARCEL(data, Int64, value, , ConcurrentTaskServiceProxy);
    WRITE_PARCEL(data, String, payload.toStyledString(), , ConcurrentTaskServiceProxy);
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
    queryRs.rtgId = -1;
    queryRs.paramA = -1;
    queryRs.paramB = -1;
    queryRs.paramC = -1;
    WRITE_PARCEL(data, InterfaceToken, ConcurrentTaskServiceProxy::GetDescriptor(), , ConcurrentTaskServiceProxy);
    WRITE_PARCEL(data, Int64, queryItem, , ConcurrentTaskServiceProxy);

    uint32_t code = static_cast<uint32_t>(ConcurrentTaskInterfaceCode::QUERY_INTERVAL);
    error = Remote()->SendRequest(code, data, reply, option);
    if (error != NO_ERROR) {
        CONCUR_LOGE("QueryInterval error: %{public}d", error);
        return;
    }
    READ_PARCEL(reply, Int32, queryRs.rtgId, , ConcurrentTaskServiceProxy);
    READ_PARCEL(reply, Int32, queryRs.paramA, , ConcurrentTaskServiceProxy);
    READ_PARCEL(reply, Int32, queryRs.paramB, , ConcurrentTaskServiceProxy);
    READ_PARCEL(reply, Int32, queryRs.paramC, , ConcurrentTaskServiceProxy);
    return;
}
} // namespace ConcurrentTask
} // namespace OHOS