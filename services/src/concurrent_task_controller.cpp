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

#include <fcntl.h>
#include <securec.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <hitrace_meter.h>
#include <linux/sched.h>

#include "concurrent_task_log.h"
#include "rtg_interface.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "concurrent_task_controller.h"

constexpr int RS_UID = 1003;
using namespace OHOS::RME;

namespace OHOS {
namespace ConcurrentTask {
namespace {
    const std::string INTERVAL_DDL = "ffrt.interval.renderthread";
    const std::string INTERVAL_APP_RATE = "persist.ffrt.interval.appRate";
    const std::string INTERVAL_RS_RATE = "persist.ffrt.interval.rsRate";
    constexpr int CURRENT_RATE = 120;
    constexpr int PARAM_TYPE = 1;
    const char RTG_SCHED_IPC_MAGIC = 0xAB;
    constexpr int RTG_TYPE_MAX = 3;
}

#define CMD_ID_SET_RTG \
    _IOWR(RTG_SCHED_IPC_MAGIC, SET_RTG, struct rtg_str_data)

TaskController& TaskController::GetInstance()
{
    static TaskController instance;
    return instance;
}

void TaskController::ReportData(uint32_t resType, int64_t value, const Json::Value& payload)
{
    pid_t uid = IPCSkeleton::GetInstance().GetCallingUid();
    if (!CheckUid(uid)) {
        CONCUR_LOGE("only system call can be allowed");
        return;
    }
    if (!CheckJsonValid(payload)) {
        return;
    }
    std::string strRequstType = "";
    try {
        strRequstType = payload["type"].asString();
    } catch (...) {
        CONCUR_LOGE("Unexpected type format");
        return;
    }
    if (strRequstType.length() == 0) {
        CONCUR_LOGE("Get payload type err");
        return;
    }
    int requstType = GetRequestType(strRequstType);
    DealSystemRequest(requstType, payload);
    PrintInfo();
}

void TaskController::QueryInterval(int queryItem, IntervalReply& queryRs)
{
    pid_t uid = IPCSkeleton::GetInstance().GetCallingUid();
    if (uid == 0) {
        CONCUR_LOGE("Uid is 0, error query");
        return;
    }
    switch (queryItem) {
        case QUERY_UI:
            QueryUi(uid, queryRs);
            break;
        case QUERY_RENDER:
            QueryRender(uid, queryRs);
            break;
        case QUERY_RENDER_SERVICE:
            QueryRenderService(uid, queryRs);
            break;
        case QUERY_COMPOSER:
            QueryHwc(uid, queryRs);
            break;
        default:
            break;
    }
}

void TaskController::QueryUi(int uid, IntervalReply& queryRs)
{
    if (uid == SYSTEM_UID) {
        return;
    }
    pid_t pid = IPCSkeleton::GetInstance().GetCallingPid();
    auto iter = GetRecordOfPid(pid);
    if (iter == foregroundApp_.end()) {
        CONCUR_LOGD("Query ui with pid %{public}d failed", pid);
        return;
    }
    int grpId = iter->GetGrpId();
    if (grpId <= 0) {
        CONCUR_LOGI("%{public}d Query ui with none grpid", pid);
        queryRs.rtgId = -1;
    } else {
        queryRs.rtgId = grpId;
    }
}

void TaskController::QueryRender(int uid, IntervalReply& queryRs)
{
    if (uid == SYSTEM_UID) {
        return;
    }
    pid_t pid = IPCSkeleton::GetInstance().GetCallingPid();
    auto iter = GetRecordOfPid(pid);
    if (iter == foregroundApp_.end()) {
        CONCUR_LOGD("Query render with pid %{public}d failed", pid);
        return;
    }
    int grpId = iter->GetGrpId();
    if (grpId <= 0) {
        CONCUR_LOGI("%{public}d Query render with none grpid", pid);
        queryRs.rtgId = -1;
    } else {
        queryRs.rtgId = grpId;
    }
}

void TaskController::QueryRenderService(int uid, IntervalReply& queryRs)
{
    if (renderServiceGrpId_ <= 0) {
        TryCreateRsGroup();
        CONCUR_LOGI("uid %{public}d query rs group failed and create %{public}d.", uid, renderServiceGrpId_);
        if (renderServiceGrpId_ <= 0) {
            CONCUR_LOGE("uid %{public}d create rs group failed", uid);
            return;
        }
    }
    queryRs.rtgId = renderServiceGrpId_;
    if (rsTid_ <= 0) {
        rsTid_ = queryRs.tid;
        int ret = AddThreadToRtg(rsTid_, renderServiceGrpId_, PRIO_RT);
        if (ret < 0) {
            CONCUR_LOGE("uid %{public}d tid %{public}d join rs group failed.", uid, rsTid_);
        }
    }
    SetFrameRateAndPrioType(renderServiceGrpId_, CURRENT_RATE, PARAM_TYPE);
}

void TaskController::QueryHwc(int uid, IntervalReply& queryRs)
{
    if (uid == SYSTEM_UID) {
        return;
    }
    pid_t pid = IPCSkeleton::GetInstance().GetCallingPid();
    auto iter = GetRecordOfPid(pid);
    if (iter == foregroundApp_.end()) {
        CONCUR_LOGD("Query ipc thread with pid %{public}d failed", pid);
        return;
    }
    int grpId = iter->GetGrpId();
    if (grpId <= 0) {
        CONCUR_LOGI("%{public}d Query ipc thread with none grpid", pid);
        queryRs.rtgId = -1;
    } else {
        queryRs.rtgId = grpId;
    }
}

void TaskController::Init()
{
    TypeMapInit();
    qosPolicy_.Init();
    TryCreateRsGroup();
}

void TaskController::Release()
{
    msgType_.clear();
    if (renderServiceGrpId_ <= 0) {
        return;
    }
    DestroyRtgGrp(renderServiceGrpId_);
    renderServiceGrpId_ = -1;
}

void TaskController::TypeMapInit()
{
    msgType_.clear();
    msgType_.insert(pair<std::string, int>("foreground", MSG_FOREGROUND));
    msgType_.insert(pair<std::string, int>("background", MSG_BACKGROUND));
    msgType_.insert(pair<std::string, int>("appStart", MSG_APP_START));
    msgType_.insert(pair<std::string, int>("appKilled", MSG_APP_KILLED));
    msgType_.insert(pair<std::string, int>("continuousStart", MSG_CONTINUOUS_TASK_START));
    msgType_.insert(pair<std::string, int>("continuousEnd", MSG_CONTINUOUS_TASK_END));
    msgType_.insert(pair<std::string, int>("authRequest", MSG_AUTH_REQUEST));
}

void TaskController::TryCreateRsGroup()
{
    if (!rtgEnabled_) {
        rtgEnabled_ = EnableRtg(true) < 0 ? false : true;
        if (!rtgEnabled_) {
            CONCUR_LOGE("Rtg enable failed");
            return;
        }
        CONCUR_LOGI("Enable Rtg");
    }
    renderServiceGrpId_ = CreateNewRtgGrp(PRIO_RT, MAX_KEY_THREADS);
    if (renderServiceGrpId_ <= 0) {
        CONCUR_LOGI("CreateRsRtgGroup with RT failed, try change to normal type.");
        renderServiceGrpId_ = CreateNewRtgGrp(PRIO_NORMAL, MAX_KEY_THREADS);
    }
    if (renderServiceGrpId_ <= 0) {
        CONCUR_LOGI("CreateRsRtgGroup failed! rtGrp:%{public}d", renderServiceGrpId_);
        return;
    }
}

int TaskController::GetRequestType(std::string strRequstType)
{
    auto iter = msgType_.find(strRequstType);
    if (iter == msgType_.end()) {
        return MSG_TYPE_MAX;
    }
    return msgType_[strRequstType];
}

bool TaskController::CheckUid(pid_t uid)
{
    if ((uid != SYSTEM_UID) && (uid != 0) && (uid != RS_UID)) {
        return false;
    }
    return true;
}

bool TaskController::ParsePayload(const Json::Value& payload, int& uid, int& pid)
{
    try {
        uid = stoi(payload["uid"].asString());
        pid = stoi(payload["pid"].asString());
    } catch(...) {
        CONCUR_LOGE("Unexpected uid or pid format");
        return false;
    }
    if (uid > 0 && pid > 0) {
        return true;
    }
    return false;
}

void TaskController::DealSystemRequest(int requestType, const Json::Value& payload)
{
    int uid = -1;
    int pid = -1;
    if (!ParsePayload(payload, uid, pid)) {
        return;
    }
    switch (requestType) {
        case MSG_FOREGROUND:
            NewForeground(uid, pid);
            break;
        case MSG_BACKGROUND:
            NewBackground(uid, pid);
            break;
        case MSG_APP_START:
            NewAppStart(uid, pid);
            break;
        case MSG_APP_KILLED:
            AppKilled(uid, pid);
            break;
        case MSG_CONTINUOUS_TASK_START:
        case MSG_CONTINUOUS_TASK_END:
            ContinuousTaskProcess(uid, pid, requestType);
            break;
        case MSG_AUTH_REQUEST:
            AuthRequestProcess(uid, pid);
            break;
        default:
            CONCUR_LOGE("Unknown system request");
            break;
    }
}

std::list<ForegroundAppRecord>::iterator TaskController::GetRecordOfPid(int pid)
{
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetPid() == pid) {
            return iter;
        }
    }
    return foregroundApp_.end();
}

void TaskController::NewForeground(int uid, int pid)
{
    int uiTid = pid;
    auto it = find(authApps_.begin(), authApps_.end(), pid);
    if (it == authApps_.end()) {
        CONCUR_LOGI("un-authed pid %{public}d", pid);
        return;
    }
    unsigned int pidParam = static_cast<unsigned int>(pid);
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_FOREGROUND);
    int ret = AuthEnable(pidParam, uaFlag, status);
    if (ret == 0) {
        CONCUR_LOGI("auth_enable %{public}d success", pid);
    } else {
        CONCUR_LOGE("auth_enable %{public}d fail with ret %{public}d", pid, ret);
    }
    bool found = false;
    bool ddlEnabled = OHOS::system::GetBoolParameter(INTERVAL_DDL, false);
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetPid() == pid) {
            found = true;
            if (ddlEnabled) {
                iter->AddKeyThread(uiTid, PRIO_RT);
            }
            iter->BeginScene();
        }
    }
    CONCUR_LOGI("pid %{public}d change to foreground.", pid);
    if (!found) {
        ForegroundAppRecord *tempRecord = new ForegroundAppRecord(pid, uiTid);
        if (tempRecord->IsValid()) {
            foregroundApp_.push_back(*tempRecord);
            if (ddlEnabled) {
                tempRecord->AddKeyThread(uiTid, PRIO_RT);
            }
            tempRecord->BeginScene();
        } else {
            delete tempRecord;
        }
    }
}

void TaskController::NewBackground(int uid, int pid)
{
    auto it = find(authApps_.begin(), authApps_.end(), pid);
    if (it == authApps_.end()) {
        CONCUR_LOGI("un-authed pid %{public}d", pid);
        return;
    }
    CONCUR_LOGI("pid %{public}d change to background.", pid);
    unsigned int pidParam = static_cast<unsigned int>(pid);

    int ret = AuthPause(pidParam);
    if (ret == 0) {
        CONCUR_LOGI("auth_pause %{public}d success", pid);
    } else {
        CONCUR_LOGI("auth_pause %{public}d fail with %{public}d", pid, ret);
    }
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetPid() == pid) {
            iter->EndScene();
            return;
        }
    }
}

void TaskController::NewAppStart(int uid, int pid)
{
    CONCUR_LOGI("pid %{public}d start.", pid);
    unsigned int pidParam = static_cast<unsigned int>(pid);
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_BACKGROUND);

    int ret = AuthEnable(pidParam, uaFlag, status);
    if (ret == 0) {
        CONCUR_LOGI("auth_enable %{public}d success", pid);
    } else {
        CONCUR_LOGE("auth_enable %{public}d fail with ret %{public}d", pid, ret);
        return;
    }
    authApps_.push_back(pid);
}

void TaskController::AppKilled(int uid, int pid)
{
    CONCUR_LOGI("pid %{public}d killed.", pid);
    unsigned int pidParam = static_cast<unsigned int>(pid);
    int ret = AuthDelete(pidParam);
    if (ret == 0) {
        CONCUR_LOGI("auth_delete %{public}d success", pid);
    } else {
        CONCUR_LOGE("auth_delete %{public}d fail with %{public}d", pid, ret);
    }
    std::lock_guard<std::mutex> lock(appInfoLock_);
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetPid() == pid) {
            foregroundApp_.erase(iter++);
            break;
        }
    }
    for (auto iter = authApps_.begin(); iter != authApps_.end(); iter++) {
        if (*iter == pid) {
            authApps_.erase(iter);
            break;
        }
    }
}

void TaskController::AuthRequestProcess(int uid, int pid)
{
    if (uid != RS_UID) {
        CONCUR_LOGE("uid %{public}d cannot request auth", uid);
        return;
    }
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_SYSTEM_SERVER);
    int ret = AuthEnable(pid, uaFlag, status);
    if (ret == 0) {
        CONCUR_LOGI("auth process %{public}d success", pid);
    } else {
        CONCUR_LOGI("auth process %{public}d failed, ret %{public}d", pid, ret);
    }
}

void TaskController::ContinuousTaskProcess(int uid, int pid, int status)
{
    int ret = -1;
    if (status == static_cast<int>(MSG_CONTINUOUS_TASK_START)) {
        ret = AuthEnhance(pid, true);
        CONCUR_LOGI("auth_enhance pid %{public}d start, ret %{public}d", pid, ret);
    } else if (status == static_cast<int>(MSG_CONTINUOUS_TASK_END)) {
        ret = AuthEnhance(pid, false);
        CONCUR_LOGI("auth_enhance pid %{public}d end, ret %{public}d", pid, ret);
    } else {
        CONCUR_LOGE("Invalid auth_enhance status %{public}d", status);
    }
}

void TaskController::QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload)
{
    pid_t uid = IPCSkeleton::GetInstance().GetCallingUid();
    if ((uid != RS_UID) && (uid != ROOT_UID)) {
        CONCUR_LOGE("only render service call can be allowed, but uid is %{public}d", uid);
        return;
    }
    switch (queryItem) {
        case DDL_RATE: {
            bool ret = ModifySystemRate(payload);
            ddlReply.setStatus = ret;
            break;
        }
        default: {
            break;
        }
    }
}

bool TaskController::ModifySystemRate(const Json::Value& payload)
{
    if (!CheckJsonValid(payload)) {
        CONCUR_LOGI("service receive json invalid");
        return false;
    }
    SetAppRate(payload);
    SetRenderServiceRate(payload);
    return true;
}

void TaskController::SetAppRate(const Json::Value& payload)
{
    int rtgId = 0;
    int uiTid = 0;
    int appRate = 0;
    int curAppRate = 0;
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        uiTid = iter->GetUiTid();
        rtgId = iter->GetGrpId();
        if (uiTid > 0 && rtgId > 0) {
            appRate = FindRateFromInfo(uiTid, payload);
            if (appRate > 0 && appRate != iter->GetRate()) {
                CONCUR_LOGI("set app rate %{public}d rtgId is %{public}d", appRate, rtgId);
                SetFrameRate(rtgId, appRate);
                iter->SetRate(appRate);
                curAppRate = appRate;
            }
        }
    }
    if (curAppRate != 0) {
        bool ret = OHOS::system::SetParameter(INTERVAL_APP_RATE, std::to_string(curAppRate));
        if (ret == false) {
            CONCUR_LOGI("set app rate param failed");
        }
        StartTrace(HITRACE_TAG_ACE,
            "SetAppRate:" + std::to_string(curAppRate) + " ret:" + std::to_string(ret));
        FinishTrace(HITRACE_TAG_ACE);
    }
}

int TaskController::FindRateFromInfo(int uiTid, const Json::Value& payload)
{
    int appRate = 0;
    if (payload[std::to_string(uiTid)].isNull()) {
        CONCUR_LOGI("FindRateFromInfo tid %{public}d is null", uiTid);
        return appRate;
    }
    try {
        appRate = stoi(payload[std::to_string(uiTid)].asString());
    } catch (...) {
        CONCUR_LOGI("application %{public}d is not in rtg_group", uiTid);
    }
    return appRate;
}

void TaskController::SetRenderServiceRate(const Json::Value& payload)
{
    int rsRate = FindRateFromInfo(rsTid_, payload);
    if (renderServiceGrpId_ > 0 && rsRate > 0 && rsRate != systemRate_) {
        CONCUR_LOGI("set rs rate %{public}d rtgId is %{public}d", rsRate, renderServiceGrpId_);
        SetFrameRate(renderServiceGrpId_, rsRate);
        systemRate_ = rsRate;
        bool ret = OHOS::system::SetParameter(INTERVAL_RS_RATE, std::to_string(rsRate));
        if (ret == false) {
            CONCUR_LOGI("set rs rate param failed");
        }
        StartTrace(HITRACE_TAG_ACE,
            "SetRSRate:" + std::to_string(rsRate) + " ret:" + std::to_string(ret));
        FinishTrace(HITRACE_TAG_ACE);
    }
}

bool TaskController::CheckJsonValid(const Json::Value& payload)
{
    Json::ValueType type = payload.type();
    if (type != Json::objectValue) {
        CONCUR_LOGE("error payload");
        return false;
    }
    if (payload.empty()) {
        CONCUR_LOGI("payload empty");
        return false;
    }
    return true;
}

void TaskController::SetFrameRate(int rtgId, int rate)
{
    if (rtgId > 0) {
        SetFrameRateAndPrioType(rtgId, rate, PARAM_TYPE);
    }
}

void TaskController::PrintInfo()
{
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        iter->PrintKeyThreads();
    }
}

int TaskController::CreateNewRtgGrp(int prioType, int rtNum)
{
    struct rtg_grp_data grp_data;
    int ret;
    char fileName[] = "/proc/self/sched_rtg_ctrl";
    int fd = open(fileName, O_RDWR);
    if (fd < 0) {
        CONCUR_LOGE("Open file /proc/self/sched_rth_ctrl, errno = %{public}d", errno);
        return fd;
    }
    (void)memset_s(&grp_data, sizeof(struct rtg_grp_data), 0, sizeof(struct rtg_grp_data));
    if ((prioType > 0) && (prioType < RTG_TYPE_MAX)) {
        grp_data.prio_type = prioType;
    }
    if (rtNum > 0) {
        grp_data.rt_cnt = rtNum;
    }
    grp_data.rtg_cmd = CMD_CREATE_RTG_GRP;
    ret = ioctl(fd, CMD_ID_SET_RTG, &grp_data);
    if (ret < 0) {
        CONCUR_LOGE("create rtg grp failed, errno = %{public}d (%{public}s)", errno, strerror(errno));
    } else {
        CONCUR_LOGI("create rtg grp success, get rtg id %{public}d.", ret);
    }
    close(fd);
    return ret;
}

ForegroundAppRecord::ForegroundAppRecord(int pid, int uiTid)
{
    pid_ = pid;
    uiTid_ = uiTid;
    if (OHOS::system::GetBoolParameter(INTERVAL_DDL, false)) {
        grpId_ = TaskController::GetInstance().CreateNewRtgGrp(PRIO_RT, MAX_KEY_THREADS);
    } else {
        grpId_ = -1;
    }
}

ForegroundAppRecord::~ForegroundAppRecord()
{
    if (grpId_ > 0) {
        DestroyRtgGrp(grpId_);
    }
}

void ForegroundAppRecord::AddKeyThread(int tid, int prio)
{
    int rtgPrio = (prio >= PRIO_NORMAL) ? PRIO_NORMAL : PRIO_RT;
    if (keyThreads_.find(tid) != keyThreads_.end()) {
        return;
    }
    if (grpId_ <= 0) {
        CONCUR_LOGI("Add key thread fail: Grp id not been created success.");
        return;
    }
    if (keyThreads_.size() >= MAX_KEY_THREADS) {
        CONCUR_LOGI("Add key thread fail: Key threads num limit.");
        return;
    }
    if (prio == RPIO_IN) {
        setpriority(PRIO_PROCESS, tid, -13); // -13 represent spcial nice in qos
    } else {
        int ret = AddThreadToRtg(tid, grpId_, rtgPrio);
        if (ret != 0) {
            CONCUR_LOGI("Add key thread fail: Kernel err report. ret is %{public}d", ret);
        } else {
            CONCUR_LOGI("Add key thread %{public}d", tid);
        }
        keyThreads_.insert(tid);
    }
}

bool ForegroundAppRecord::BeginScene()
{
    if (grpId_ <= 0) {
        CONCUR_LOGI("Error begin scene in pid %{public}d", pid_);
        return false;
    }
    OHOS::RME::BeginFrameFreq(grpId_, 0);
    OHOS::RME::EndFrameFreq(grpId_);
    return true;
}

bool ForegroundAppRecord::EndScene()
{
    grpId_ = SearchRtgForTid(uiTid_);
    if (grpId_ <= 0) {
        CONCUR_LOGI("Error end scene loss grpId_ in pid %{public}d", pid_);
        return false;
    }
    OHOS::RME::EndScene(grpId_);
    return true;
}

int ForegroundAppRecord::GetPid() const
{
    return pid_;
}

int ForegroundAppRecord::GetGrpId() const
{
    return grpId_;
}

void ForegroundAppRecord::SetRate(int appRate)
{
    rate_ = appRate;
}

int ForegroundAppRecord::GetRate() const
{
    return rate_;
}

void ForegroundAppRecord::SetUiTid(int uiTid)
{
    uiTid_ = uiTid;
}

int ForegroundAppRecord::GetUiTid() const
{
    return uiTid_;
}

bool ForegroundAppRecord::IsValid()
{
    if (pid_ > 0) {
        return true;
    }
    return false;
}

void ForegroundAppRecord::PrintKeyThreads()
{
    std::string strLog = "pid ";
    strLog.append(std::to_string(pid_));
    strLog.append(" has key threads: ");
    for (auto iter = keyThreads_.begin(); iter != keyThreads_.end(); iter++) {
        std::string temp = std::to_string(*iter);
        strLog.append(temp);
        strLog.append(", ");
    }
    CONCUR_LOGD("%{public}s", strLog.c_str());
}
} // namespace ConcurrentTask
} // namespace OHOS
