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

#ifndef CONCURRENT_TASK_SERVICES_INTERFACES_INNERKITS_CONCURRENT_TASK_CLIENT_INCLUDE_ICONCURRENT_TASK_SERVICE_H
#define CONCURRENT_TASK_SERVICES_INTERFACES_INNERKITS_CONCURRENT_TASK_CLIENT_INCLUDE_ICONCURRENT_TASK_SERVICE_H

#include "iremote_broker.h"
#include "json/json.h"
#include "concurrent_task_type.h"

/* SAID:1912 */
namespace OHOS {
namespace ConcurrentTask {
class IConcurrentTaskService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ResourceSchedule.ConcurrentTaskService");

    virtual void ReportData(uint32_t resType, int64_t value, const Json::Value& payload) = 0;
    virtual void QueryInterval(int queryItem, IntervalReply& queryRs) = 0;
    virtual void QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload) = 0;
    virtual void RequestAuth(const Json::Value& payload) = 0;
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SERVICES_INTERFACES_INNERKITS_CONCURRENT_TASK_CLIENT_INCLUDE_ICONCURRENT_TASK_SERVICE_H
