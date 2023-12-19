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

#ifndef CONCUURENT_TASK_INTERFACES_INNERAPI_CONCURRENT_TASK_CLIENT_INCLUDE_CONCUURENT_TASK_SERVICE_PROXY_H
#define CONCUURENT_TASK_INTERFACES_INNERAPI_CONCURRENT_TASK_CLIENT_INCLUDE_CONCUURENT_TASK_SERVICE_PROXY_H

#include "iremote_proxy.h"
#include "iremote_object.h"
#include "iconcurrent_task_service.h"
#include "concurrent_task_service_ipc_interface_code.h"

namespace OHOS {
namespace ConcurrentTask {
class ConcurrentTaskServiceProxy : public IRemoteProxy<IConcurrentTaskService> {
public:
    explicit ConcurrentTaskServiceProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IConcurrentTaskService>(impl) {}
    virtual ~ConcurrentTaskServiceProxy() {}

    void ReportData(uint32_t resType, int64_t value, const Json::Value& payload) override;
    void QueryInterval(int queryItem, IntervalReply& queryRs) override;
    void QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload) override;
    void RequestAuth(const Json::Value& payload) override;

private:
    DISALLOW_COPY_AND_MOVE(ConcurrentTaskServiceProxy);
    static inline BrokerDelegator<ConcurrentTaskServiceProxy> delegator_;
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCUURENT_TASK_INTERFACES_INNERAPI_CONCURRENT_TASK_CLIENT_INCLUDE_CONCUURENT_TASK_SERVICE_PROXY_H