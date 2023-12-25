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

#ifndef CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_SEVICE_H
#define CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_SEVICE_H

#include "concurrent_task_service_stub.h"
#include "concurrent_task_log.h"

namespace OHOS {
namespace ConcurrentTask {
class ConcurrentTaskService : public ConcurrentTaskServiceStub {
public:
    ConcurrentTaskService() {}
    ~ConcurrentTaskService() override = default;

    void ReportData(uint32_t resType, int64_t value, const Json::Value& payload) override;
    void QueryInterval(int queryItem, IntervalReply& queryRs) override;
    void QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload) override;
    void RequestAuth(const Json::Value& payload) override;
private:
    DISALLOW_COPY_AND_MOVE(ConcurrentTaskService);
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_SEVICE_H
