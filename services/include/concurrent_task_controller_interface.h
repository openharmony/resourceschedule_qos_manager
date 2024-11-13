/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_CONTROLLER_INTERFACE_H
#define CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_CONTROLLER_INTERFACE_H

#include <mutex>

#include "json/json.h"
#include "json/value.h"

#include "concurrent_task_type.h"
#include "func_loader.h"
#include "qos_policy.h"

namespace OHOS {
namespace ConcurrentTask {
using ReportDataFunc = void (*)(uint32_t resType, int64_t value, const Json::Value& payload);
using QueryIntervalFunc = void (*)(int queryItem, IntervalReply& queryRs);
using QueryDeadlineFunc = void (*)(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload);
using RequestAuthFunc = void (*)(const Json::Value& payload);
using InitFunc = void (*)();
using ReleaseFunc = void (*)();
using CreateNewRtgGrpFunc = int (*)(int prioType, int rtNum);

class TaskControllerInterface {
public:
    static TaskControllerInterface& GetInstance();
    TaskControllerInterface();
    virtual ~TaskControllerInterface() = default;
    void RequestAuth(const Json::Value& payload);
    void ReportData(uint32_t resType, int64_t value, const Json::Value& payload);
    void QueryInterval(int queryItem, IntervalReply& queryRs);
    void QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload);
    void Init();
    void Release();

private:
    bool LoadFunc();
    FuncLoader funcLoader_;
    std::mutex funcLoaderLock_;
    bool inited_ = false;
    QosPolicy qosPolicy_;

    ReportDataFunc reportDataFunc_ = nullptr;
    QueryIntervalFunc queryIntervalFunc_ = nullptr;
    QueryDeadlineFunc queryDeadlineFunc_ = nullptr;
    RequestAuthFunc requestAuthFunc_ = nullptr;
    InitFunc initFunc_ = nullptr;
    ReleaseFunc releaseFunc_ = nullptr;
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif