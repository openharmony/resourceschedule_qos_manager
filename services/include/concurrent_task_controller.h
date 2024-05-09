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
#include <atomic>
#include "json/json.h"
#include "concurrent_task_type.h"
#include "qos_policy.h"

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
    void QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload);
    void RequestAuth(const Json::Value& payload);
    void Init();
    void Release();
    int CreateNewRtgGrp(int prioType, int rtNum);

private:
    void TypeMapInit();
    void QosApplyInit();
    int TryCreateSystemGroup();
    void TryCreateHardwareGroup();
    void TryCreateRsGroup();
    void TryCreateRSMainGrp();
    void TryCreateRSRenderGrp();
    void QueryUi(pid_t uid, IntervalReply& queryRs);
    void QueryRender(pid_t uid, IntervalReply& queryRs);
    void QueryRenderService(pid_t uid, IntervalReply& queryRs);
    void QueryRenderServiceMain(pid_t uid, pid_t pid, IntervalReply& queryRs);
    void QueryRenderServiceRender(pid_t uid, pid_t pid, IntervalReply& queryRs);
    void QueryHardware(pid_t uid, pid_t pid, IntervalReply& queryRs);
    void QueryExecutorStart(pid_t uid, pid_t pid, IntervalReply& queryRs);
    void QueryHwc(pid_t uid, IntervalReply& queryRs);
    int GetRequestType(std::string strRequstType);
    void DealSystemRequest(int requestType, const Json::Value& payload);
    void NewForeground(int uid, int pid);
    void NewBackground(int uid, int pid);
    void NewAppStart(int uid, int pid, const std::string& bundleName);
    void AppKilled(int uid, int pid);
    void ContinuousTaskProcess(int uid, int pid, int status);
    void FocusStatusProcess(int uid, int pid, int status);
    int AuthSystemProcess(int pid);
    bool ModifySystemRate(const Json::Value& payload);
    void SetAppRate(const Json::Value& payload);
    int FindRateFromInfo(int uiTid, const Json::Value& payload);
    void SetRenderServiceRate(const Json::Value& payload);
    bool CheckJsonValid(const Json::Value& payload);
    void SetFrameRate(int rtgId, int rate);
    std::list<ForegroundAppRecord>::iterator GetRecordOfPid(int pid);
    void PrintInfo();
    bool ParsePayload(const Json::Value& payload, int& uid, int& pid, std::string& bundleName);
    std::string GetProcessNameByToken();
    void ModifyGameState(const Json::Value& payload);
    int GetGamePid(const std::string &gameMsg) const;
    GameStatus GetGameScene(const std::string &gameMsg) const;
    void NewForegroundAppRecord(int pid, int uiTid, bool ddlEnabled);

    std::mutex appInfoLock_;
    std::mutex rateInfoLock_;
    std::mutex executorStartLock_;
    std::list<ForegroundAppRecord> foregroundApp_ = {};
    std::list<int> rsThreads_ = {};
    std::unordered_map<std::string, int> msgType_ = {};
    QosPolicy qosPolicy_;
    std::vector<int> authApps_;
    int renderServiceMainGrpId_ = -1;
    int renderServiceRenderGrpId_ = -1;
    int renderServiceMainTid_ = -1;
    int renderServiceRenderTid_ = -1;
    int hardwareGrpId_ = -1;
    int hardwareTid_ = -1;
    int systemRate_ = 0;
    bool rtgEnabled_ = false;
    bool rsAuthed_ = false;
    std::atomic<int> curGamePid_ = -1;
    int executorNum_ = 0;
    std::map<int, std::string> appBundleName;

    const std::string RENDER_SERVICE_PROCESS_NAME = "render_service";
    const std::string RESOURCE_SCHEDULE_PROCESS_NAME = "resource_schedule_service";
    const std::string GAME_ACCELERATE_SCHED_PROCESS_NAME = "game_accelerate_schedule";
    const int32_t HWF_SERVICE_UID = 7700;
};

class ForegroundAppRecord {
public:
    explicit ForegroundAppRecord(int pid, int uiTid, bool createGrp = true);
    ~ForegroundAppRecord();

    void AddKeyThread(int tid, int prio = PRIO_NORMAL);
    bool BeginScene();
    bool EndScene();
    int GetPid() const;
    int GetGrpId() const;
    int GetRate() const;
    void SetRate(int appRate);
    int GetUiTid() const;
    void SetUiTid(int uiTid);
    void SetGrpId(int grpId);
    bool IsValid();
    void PrintKeyThreads();

private:
    int pid_ = 0;
    int grpId_ = 0;
    int rate_ = 0;
    int uiTid_ = 0;
    std::unordered_set<int> keyThreads_;
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_CONTROLLER_H
