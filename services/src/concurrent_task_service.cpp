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

#include "concurrent_task_service.h"
#include "concurrent_task_log.h"
#include "concurrent_task_controller_interface.h"

namespace OHOS {
namespace ConcurrentTask {

ErrCode ConcurrentTaskService::ReportData(
    uint32_t resType, int64_t value, const std::unordered_map<std::string, std::string>& payload)
{
    Json::Value payloadData = MapToJson(payload);
    TaskControllerInterface::GetInstance().ReportData(resType, value, payloadData);
    return ERR_OK;
}

ErrCode ConcurrentTaskService::ReportSceneInfo(
    uint32_t type, const std::unordered_map<std::string, std::string>& payload)
{
    Json::Value payloadData = MapToJson(payload);
    TaskControllerInterface::GetInstance().ReportSceneInfo(type, payloadData);
    return ERR_OK;
}

ErrCode ConcurrentTaskService::QueryInterval(int queryItem, IpcIntervalReply& IpcQueryRs)
{
    IntervalReply queryRs = IpcToQueryRs(IpcQueryRs);
    TaskControllerInterface::GetInstance().QueryInterval(queryItem, queryRs);
    IpcQueryRs = QueryRsToIpc(queryRs);
    return ERR_OK;
}

ErrCode ConcurrentTaskService::QueryDeadline(
    int queryItem, const IpcDeadlineReply& IpcDdlReply, const std::unordered_map<std::string, std::string>& payload)
{
    Json::Value payloadData = MapToJson(payload);
    DeadlineReply queryRs = IpcToDdlReply(IpcDdlReply);
    TaskControllerInterface::GetInstance().QueryDeadline(queryItem, queryRs, payloadData);
    return ERR_OK;
}

ErrCode ConcurrentTaskService::RequestAuth(const std::unordered_map<std::string, std::string>& payload)
{
    Json::Value payloadData = MapToJson(payload);
    TaskControllerInterface::GetInstance().RequestAuth(payloadData);
    return ERR_OK;
}

Json::Value ConcurrentTaskService::MapToJson(const std::unordered_map<std::string, std::string>& dataMap)
{
    Json::Value root;
    for (const auto& pair : dataMap) {
        root[pair.first] = pair.second;
    }
    return root;
}

IntervalReply ConcurrentTaskService::IpcToQueryRs(const IpcIntervalReply& IpcQueryRs)
{
    IntervalReply queryRs;
    queryRs.rtgId = IpcQueryRs.rtgId;
    queryRs.tid = IpcQueryRs.tid;
    queryRs.paramA = IpcQueryRs.paramA;
    queryRs.paramB = IpcQueryRs.paramB;
    queryRs.bundleName = IpcQueryRs.bundleName;
    return queryRs;
}

IpcIntervalReply ConcurrentTaskService::QueryRsToIpc(const IntervalReply& queryRs)
{
    IpcIntervalReply IpcQueryRs;
    IpcQueryRs.rtgId = queryRs.rtgId;
    IpcQueryRs.tid = queryRs.tid;
    IpcQueryRs.paramA = queryRs.paramA;
    IpcQueryRs.paramB = queryRs.paramB;
    IpcQueryRs.bundleName = queryRs.bundleName;
    return IpcQueryRs;
}

DeadlineReply ConcurrentTaskService::IpcToDdlReply(const IpcDeadlineReply& IpcDdlReply)
{
    DeadlineReply ddlReply;
    ddlReply.setStatus = IpcDdlReply.setStatus;
    return ddlReply;
}
} // namespace ConcurrentTask
} // namespace OHOS
