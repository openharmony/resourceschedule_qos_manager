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

#ifndef CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_CONTROLLER_H
#define CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_CONTROLLER_H

#include <unordered_set>
#include <list>
#include <mutex>
#include <unordered_map>
#include <vector>
#include "json/json.h"
#include "concurrent_task_type.h"
#include "qos_manager.h"

namespace OHOS {
namespace ConcurrentTask {
class ForegroundAppRecord;

class TaskController {
public:
    static TaskController& GetInstance();
    TaskController() = default;
    virtual ~TaskController() = default;
    void ReportData(uint32_t resType, int64_t value, const Json::Value& payload);
    void QueryInterval(int queryItem, IntervalReply& queryRs);
    void Init();
    void Release();

private:
    bool CheckUid(pid_t uid);
    void TypeMapInit();
    void QosApplyInit();
    void SetSystemAuth(int uid, bool status);
    void TryCreateRsGroup();
    void QueryUi(pid_t uid, IntervalReply& queryRs);
    void QueryRender(pid_t uid, IntervalReply& queryRs);
    void QueryRenderService(pid_t uid, IntervalReply& queryRs);
    void QueryHwc(pid_t uid, IntervalReply& queryRs);
    int GetRequestType(std::string strRequstType);
    void DealSystemRequest(int requestType, const Json::Value& payload);
    void DealAppRequest(int requestType, const Json::Value& payload, pid_t uid);
    void NewForeground(int uid, const Json::Value& payload);
    void NewBackground(int uid);
    void NewAppStart(int uid);
    void AppKilled(int uid);
    std::list<ForegroundAppRecord>::iterator GetRecordOfUid(int uid);
    void PrintInfo();

    std::mutex appInfoLock_;
    std::list<ForegroundAppRecord> foregroundApp_ = {};
    std::unordered_map<std::string, int> msgType_ = {};
    QosManager qosManager_;
    std::vector<int> authApps_;
    int renderServiceGrpId_ = -1;
    int rsTid_ = -1;
    bool rtgEnabled_ = false;
};

class ForegroundAppRecord {
public:
    explicit ForegroundAppRecord(int uid, int uiTid);
    ~ForegroundAppRecord();

    void AddKeyThread(int tid, int prio = PRIO_NORMAL);
    bool BeginScene();
    bool EndScene();
    int GetUid();
    int GetGrpId();
    bool IsValid();
    void PrintKeyThreads();

private:
    int uid_ = 0;
    int grpId_ = 0;
    int uiTid_ = 0;
    std::unordered_set<int> keyThreads_;
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_CONTROLLER_H