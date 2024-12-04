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

#include "concurrent_task_controller_interface.h"

#include <cinttypes>
#include <fcntl.h>
#include <hitrace_meter.h>
#include <mutex>
#include <sched.h>
#include <securec.h>
#include <unistd.h>

#include <linux/sched.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

#include "accesstoken_kit.h"
#include "concurrent_task_log.h"
#include "concurrent_task_type.h"
#include "ipc_skeleton.h"
#include "parameter.h"
#include "rtg_interface.h"

namespace OHOS {
namespace ConcurrentTask {
TaskControllerInterface::TaskControllerInterface() : funcLoader_("libtask_controller.z.so") {}

TaskControllerInterface& TaskControllerInterface::GetInstance()
{
    static TaskControllerInterface instance;
    return instance;
}

void TaskControllerInterface::RequestAuth(const Json::Value& payload)
{
    if (!inited_) {
        CONCUR_LOGE("[TaskControllerInterface] RequestAuth failed, funcLoader_ load func failed");
        return;
    }
    requestAuthFunc_(payload);
}

void TaskControllerInterface::ReportData(uint32_t resType, int64_t value, const Json::Value& payload)
{
    if (!inited_) {
        CONCUR_LOGE("[TaskControllerInterface] ReportData failed, funcLoader_ load func failed");
        return;
    }
    reportDataFunc_(resType, value, payload);
}

void TaskControllerInterface::ReportSceneInfo(uint32_t type, const Json::Value& payload)
{
    if (!inited_) {
        CONCUR_LOGE("[TaskControllerInterface] ReportSceneInfo failed, funcLoader_ load func failed");
        return;
    }
    reportSceneInfoFunc_(type, payload);
}

void TaskControllerInterface::QueryInterval(int queryItem, IntervalReply& queryRs)
{
    if (!inited_) {
        CONCUR_LOGE("[TaskControllerInterface] QueryInterval failed, funcLoader_ load func failed");
        return;
    }
    queryIntervalFunc_(queryItem, queryRs);
}

void TaskControllerInterface::QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload)
{
    if (!inited_) {
        CONCUR_LOGE("[TaskControllerInterface] QueryDeadline failed, funcLoader_ load func failed");
        return;
    }
    queryDeadlineFunc_(queryItem, ddlReply, payload);
}

void TaskControllerInterface::Init()
{
    std::lock_guard<std::mutex> autoLock(funcLoaderLock_);
    if (inited_) {
        return;
    }
    if (!LoadFunc()) {
        qosPolicy_.Init();
        CONCUR_LOGE("TaskControllerInterface load function failed.");
        return;
    }
    CONCUR_LOGI("TaskControllerInterface load function success.");
    inited_ = true;
    initFunc_();
}

void TaskControllerInterface::Release()
{
    if (!inited_) {
        CONCUR_LOGE("[TaskControllerInterface] Release failed, funcLoader_ load func failed");
        return;
    }
    releaseFunc_();
}

bool TaskControllerInterface::LoadFunc()
{
    reportDataFunc_ = ReportDataFunc(funcLoader_.LoadSymbol("ReportData"));
    reportSceneInfoFunc_ = ReportSceneInfoFunc(funcLoader_.LoadSymbol("ReportSceneInfo"));
    queryIntervalFunc_ = QueryIntervalFunc(funcLoader_.LoadSymbol("QueryInterval"));
    queryDeadlineFunc_ = QueryDeadlineFunc(funcLoader_.LoadSymbol("QueryDeadline"));
    requestAuthFunc_ = RequestAuthFunc(funcLoader_.LoadSymbol("RequestAuth"));
    initFunc_ = InitFunc(funcLoader_.LoadSymbol("Init"));
    releaseFunc_ = ReleaseFunc(funcLoader_.LoadSymbol("Release"));

    return funcLoader_.GetLoadSuccess();
}
} // namespace ConcurrentTask
} // namespace OHOS