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

#include "concurrent_task_service.h"
#include "concurrent_task_controller.h"

namespace OHOS {
namespace ConcurrentTask {
void ConcurrentTaskService::ReportData(uint32_t resType, int64_t value, const Json::Value& payload)
{
    TaskController::GetInstance().ReportData(resType, value, payload);
}

void ConcurrentTaskService::QueryInterval(int queryItem, IntervalReply& queryRs)
{
    TaskController::GetInstance().QueryInterval(queryItem, queryRs);
}

void ConcurrentTaskService::QueryDeadline(int queryItem, DeadlineReply& queryRs, const Json::Value& payload)
{
    TaskController::GetInstance().QueryDeadline(queryItem, queryRs, payload);
}

void ConcurrentTaskService::RequestAuth(const Json::Value& payload)
{
    TaskController::GetInstance().RequestAuth(payload);
}

} // namespace ConcurrentTask
} // namespace OHOS
