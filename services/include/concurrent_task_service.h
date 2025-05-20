/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <unordered_map>
#include "json/json.h"
#include "concurrent_task_type.h"
#include "concurrent_task_idl_types.h"
#include "concurrent_task_service_stub.h"

namespace OHOS {
namespace ConcurrentTask {
class ConcurrentTaskService : public ConcurrentTaskServiceStub {
public:
    ConcurrentTaskService() {}
    ~ConcurrentTaskService() override = default;

    ErrCode ReportData(uint32_t resType, int64_t value,
                       const std::unordered_map<std::string, std::string>& payload) override;
    ErrCode ReportSceneInfo(uint32_t type, const std::unordered_map<std::string, std::string>& payload) override;
    ErrCode QueryInterval(int queryItem, IpcIntervalReply& IpcQueryRs) override;
    ErrCode QueryDeadline(int queryItem, const IpcDeadlineReply& IpcDdlReply,
                          const std::unordered_map<std::string, std::string>& payload) override;
    ErrCode SetAudioDeadline(int queryItem, int tid, int grpId, IpcIntervalReply& IpcQueryRs) override;
    ErrCode RequestAuth(const std::unordered_map<std::string, std::string>& payload) override;

    Json::Value MapToJson(const std::unordered_map<std::string, std::string>& dataMap);
    IntervalReply IpcToQueryRs(const IpcIntervalReply& IpcQueryRs);
    IpcIntervalReply QueryRsToIpc(const IntervalReply& queryRs);
    DeadlineReply IpcToDdlReply(const IpcDeadlineReply& IpcDdlReply);
private:
    DISALLOW_COPY_AND_MOVE(ConcurrentTaskService);
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_SEVICE_H
