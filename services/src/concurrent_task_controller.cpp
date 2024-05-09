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
#include "accesstoken_kit.h"
#include "concurrent_task_log.h"
#include "rtg_interface.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "concurrent_task_controller.h"

using namespace OHOS::RME;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace ConcurrentTask {
namespace {
    const std::string INTERVAL_DDL = "persist.ffrt.interval.renderthread";
    const std::string INTERVAL_APP_RATE = "persist.ffrt.interval.appRate";
    const std::string INTERVAL_RS_RATE = "persist.ffrt.interval.rsRate";
    constexpr int CURRENT_RATE = 120;
    constexpr int PARAM_TYPE = 1;
    constexpr int UNI_APP_RATE_ID = -1;
    const char RTG_SCHED_IPC_MAGIC = 0xAB;
    constexpr int RTG_TYPE_MAX = 3;
    constexpr int RS_UID = 1003;
    constexpr int EXECUTOR_LIMIT_NUM = 3;
}

#define CMD_ID_SET_RTG \
    _IOWR(RTG_SCHED_IPC_MAGIC, SET_RTG, struct rtg_str_data)

TaskController& TaskController::GetInstance()
{
    static TaskController instance;
    return instance;
}

void TaskController::RequestAuth(const Json::Value& payload)
{
    pid_t uid = IPCSkeleton::GetInstance().GetCallingUid();
    if (uid != HWF_SERVICE_UID) {
        CONCUR_LOGE("Invalid uid %{public}d, only hwf service uid can call RequestAuth", uid);
        return;
    }
    pid_t pid = IPCSkeleton::GetInstance().GetCallingPid();
    AuthSystemProcess(pid);
}

void TaskController::ReportData(uint32_t resType, int64_t value, const Json::Value& payload)
{
    pid_t uid = IPCSkeleton::GetInstance().GetCallingUid();
    if (GetProcessNameByToken() != RESOURCE_SCHEDULE_PROCESS_NAME) {
        CONCUR_LOGE("Invalid uid %{public}d, only RSS can call ReportData", uid);
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
    pid_t pid = IPCSkeleton::GetInstance().GetCallingPid();
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
        case QUERY_RENDER_SERVICE_MAIN:
            QueryRenderServiceMain(uid, pid, queryRs);
            break;
        case QUERY_RENDER_SERVICE_RENDER:
            QueryRenderServiceRender(uid, pid, queryRs);
            break;
        case QUERY_COMPOSER:
            QueryHwc(uid, queryRs);
            break;
        case QUERY_HARDWARE:
            QueryHardware(uid, pid, queryRs);
            break;
        case QUERY_EXECUTOR_START:
            QueryExecutorStart(uid, pid, queryRs);
            break;
        default:
            break;
    }
}

std::string TaskController::GetProcessNameByToken()
{
    AccessTokenID tokenID = IPCSkeleton::GetInstance().GetCallingTokenID();
    NativeTokenInfo tokenInfo;
    if (AccessTokenKit::GetNativeTokenInfo(tokenID, tokenInfo) != AccessTokenKitRet::RET_SUCCESS) {
        return "";
    }
    return tokenInfo.processName;
}

void TaskController::QueryUi(int uid, IntervalReply& queryRs)
{
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
    queryRs.bundleName = appBundleName[pid];
}

void TaskController::QueryRender(int uid, IntervalReply& queryRs)
{
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
    if (uid != RS_UID) {
        return;
    }
    int queryTid = queryRs.tid;
    if (renderServiceMainGrpId_ <= 0) {
        TryCreateRSMainGrp();
        CONCUR_LOGI("uid %{public}d query rs group failed and create %{public}d.", uid, renderServiceMainGrpId_);
        if (renderServiceMainGrpId_ <= 0) {
            CONCUR_LOGE("uid %{public}d create rs group failed", uid);
            return;
        }
    }

    queryRs.rtgId = renderServiceMainGrpId_;
    if (queryTid <= 0) {
        return;
    }
    list<int>::iterator iter = find(rsThreads_.begin(), rsThreads_.end(), queryTid);
    if (iter != rsThreads_.end()) {
        return;
    }
    queryRs.rtgId = renderServiceMainGrpId_;
    int ret = AddThreadToRtg(queryTid, renderServiceMainGrpId_, PRIO_RT);
    if (ret < 0) {
        CONCUR_LOGE("uid %{public}d tid %{public}d join rs group failed", uid, queryTid);
        return;
    }
    CONCUR_LOGI("uid %{public}d tid %{public}d join rs group success in Query", uid, queryTid);
    SetFrameRateAndPrioType(renderServiceMainGrpId_, CURRENT_RATE, PARAM_TYPE);
}

void TaskController::QueryRenderServiceMain(int uid, int pid, IntervalReply& queryRs)
{
    if (GetProcessNameByToken() != RENDER_SERVICE_PROCESS_NAME) {
        return;
    }
    if (!rsAuthed_) {
        if (AuthSystemProcess(pid) != 0) {
            return;
        }
        rsAuthed_ = true;
    }
    if (renderServiceMainGrpId_ <= 0) {
        TryCreateRSMainGrp();
        CONCUR_LOGI("uid %{public}d query rs group failed and create %{public}d.", uid, renderServiceMainGrpId_);
        if (renderServiceMainGrpId_ <= 0) {
            CONCUR_LOGE("uid %{public}d create rs group failed", uid);
            return;
        }
    }
    queryRs.rtgId = renderServiceMainGrpId_;
    if (renderServiceMainTid_ <= 0) {
        renderServiceMainTid_ = queryRs.tid;
        int ret = AddThreadToRtg(renderServiceMainTid_, renderServiceMainGrpId_, PRIO_RT);
        if (ret < 0) {
            CONCUR_LOGE("uid %{public}d tid %{public}d join rs group failed.", uid, renderServiceMainTid_);
        }
    }
    SetFrameRateAndPrioType(renderServiceMainGrpId_, CURRENT_RATE, PARAM_TYPE);
}
 
void TaskController::QueryRenderServiceRender(int uid, int pid, IntervalReply& queryRs)
{
    if (GetProcessNameByToken() != RENDER_SERVICE_PROCESS_NAME) {
        return;
    }
    if (renderServiceRenderGrpId_ <= 0) {
        TryCreateRSRenderGrp();
        if (renderServiceRenderGrpId_ <= 0) {
            CONCUR_LOGE("uid %{public}d create rs group failed", uid);
            return;
        }
    }
    queryRs.rtgId = renderServiceRenderGrpId_;
    if (renderServiceRenderTid_ <= 0 || renderServiceRenderTid_ != queryRs.tid) {
        renderServiceRenderTid_ = queryRs.tid;
        int ret = AddThreadToRtg(renderServiceRenderTid_, renderServiceRenderGrpId_, PRIO_RT);
        if (ret < 0) {
            CONCUR_LOGE("uid %{public}d tid %{public}d join rs group failed.", uid, renderServiceMainGrpId_);
        }
    }
    SetFrameRateAndPrioType(renderServiceRenderGrpId_, CURRENT_RATE, PARAM_TYPE);
}

void TaskController::QueryHardware(int uid, int pid, IntervalReply& queryRs)
{
    if (uid != RS_UID) {
        return;
    }
    if (hardwareGrpId_ < 0) {
        return;
    }
    hardwareTid_ = queryRs.tid;
    TryCreateRSMainGrp();
    int ret = AddThreadToRtg(hardwareTid_, renderServiceMainGrpId_, PRIO_RT);
    if (ret < 0) {
        CONCUR_LOGE("uid %{public}d tid %{public}d join hardware group failed.", uid, hardwareTid_);
        return;
    }
    queryRs.rtgId = hardwareGrpId_;
}

void TaskController::QueryExecutorStart(int uid, int pid, IntervalReply& queryRs)
{
    if (uid != RS_UID) {
        return;
    }
    if (renderServiceMainGrpId_ < 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(executorStartLock_);
    if (executorNum_ >= EXECUTOR_LIMIT_NUM) {
        return;
    }
    if (queryRs.tid <= 0) {
        return;
    }
    int ret = AddThreadToRtg(queryRs.tid, renderServiceMainGrpId_, PRIO_RT);
    if (ret < 0) {
        CONCUR_LOGE("uid %{public}d tid %{public}d join executor group failed.", uid, renderServiceMainTid_);
        return;
    }
    executorNum_++;
    queryRs.rtgId = renderServiceMainGrpId_;
}

void TaskController::QueryHwc(int uid, IntervalReply& queryRs)
{
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
    if (renderServiceMainGrpId_ > 0) {
        DestroyRtgGrp(renderServiceMainGrpId_);
        renderServiceMainGrpId_ = -1;
    }
    if (renderServiceRenderGrpId_ > 0) {
        DestroyRtgGrp(renderServiceRenderGrpId_);
        renderServiceRenderGrpId_ = -1;
    }
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
    msgType_.insert(pair<std::string, int>("getFocus", MSG_GET_FOCUS));
    msgType_.insert(pair<std::string, int>("loseFocus", MSG_LOSE_FOCUS));
}

void TaskController::TryCreateRSMainGrp()
{
    if (renderServiceMainGrpId_ == -1) {
        renderServiceMainGrpId_ = TryCreateSystemGroup();
        hardwareGrpId_ = renderServiceMainGrpId_;
    }
}
 
void TaskController::TryCreateRSRenderGrp()
{
    if (renderServiceRenderGrpId_ == -1) {
        renderServiceRenderGrpId_ = TryCreateSystemGroup();
    }
}
 
void TaskController::TryCreateRsGroup()
{
    TryCreateRSMainGrp();
    TryCreateRSRenderGrp();
}

int TaskController::TryCreateSystemGroup()
{
    if (!rtgEnabled_) {
        rtgEnabled_ = EnableRtg(true) < 0 ? false : true;
        if (!rtgEnabled_) {
            CONCUR_LOGE("Rtg enable failed");
            return -1;
        }
        CONCUR_LOGI("Enable Rtg");
    }
    int grpId = CreateNewRtgGrp(PRIO_RT, MAX_KEY_THREADS);
    if (grpId <= 0) {
        CONCUR_LOGI("CreateRsRtgGroup with RT failed, try change to normal type.");
        grpId = CreateNewRtgGrp(PRIO_NORMAL, MAX_KEY_THREADS);
    }
    if (grpId <= 0) {
        CONCUR_LOGI("CreateRsRtgGroup failed! rtGrp:%{public}d", grpId);
        return -1;
    }
    return grpId;
}

int TaskController::GetRequestType(std::string strRequstType)
{
    auto iter = msgType_.find(strRequstType);
    if (iter == msgType_.end()) {
        return MSG_TYPE_MAX;
    }
    return msgType_[strRequstType];
}

bool TaskController::ParsePayload(const Json::Value& payload, int& uid, int& pid, std::string& bundleName)
{
    try {
        uid = stoi(payload["uid"].asString());
        pid = stoi(payload["pid"].asString());
        bundleName = payload["bundleName"].asString();
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
    std::string bundleName = "";
    if (!ParsePayload(payload, uid, pid, bundleName)) {
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
            NewAppStart(uid, pid, bundleName);
            break;
        case MSG_APP_KILLED:
            AppKilled(uid, pid);
            break;
        case MSG_CONTINUOUS_TASK_START:
        case MSG_CONTINUOUS_TASK_END:
            ContinuousTaskProcess(uid, pid, requestType);
            break;
        case MSG_GET_FOCUS:
        case MSG_LOSE_FOCUS:
            FocusStatusProcess(uid, pid, requestType);
            break;
        default:
            CONCUR_LOGE("Unknown system request");
            break;
    }
}

std::list<ForegroundAppRecord>::iterator TaskController::GetRecordOfPid(int pid)
{
    std::lock_guard<std::mutex> lock(appInfoLock_);
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
    int ret = AuthGet(pid);
    if (ret != static_cast<int>(AuthStatus::AUTH_STATUS_FOCUS)) {
        unsigned int pidParam = static_cast<unsigned int>(pid);
        unsigned int uaFlag = AF_RTG_ALL;
        unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_FOREGROUND);
        int ret = AuthEnable(pidParam, uaFlag, status);
        if (ret == 0) {
            CONCUR_LOGI("auth_enable %{public}d success", pid);
        } else {
            CONCUR_LOGE("auth_enable %{public}d fail with ret %{public}d", pid, ret);
        }
        CONCUR_LOGI("pid %{public}d change to foreground.", pid);
    } else {
        CONCUR_LOGI("pid %{public}d is already focus", pid);
    }
    bool found = false;
    bool ddlEnabled = OHOS::system::GetBoolParameter(INTERVAL_DDL, false);
    std::lock_guard<std::mutex> lock(appInfoLock_);
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetPid() == pid) {
            found = true;
            if (ddlEnabled && pid != curGamePid_) {
                iter->AddKeyThread(uiTid, PRIO_RT);
            }
            iter->BeginScene();
        }
    }
    if (!found) {
        NewForegroundAppRecord(pid, uiTid, ddlEnabled);
    }
}

void TaskController::NewForegroundAppRecord(int pid, int uiTid, bool ddlEnabled)
{
    ForegroundAppRecord *tempRecord = nullptr;
    if (pid == curGamePid_) {
        tempRecord = new ForegroundAppRecord(pid, uiTid, false);
    } else {
        tempRecord = new ForegroundAppRecord(pid, uiTid, true);
    }
    if (tempRecord->IsValid()) {
        foregroundApp_.push_back(*tempRecord);
        if (ddlEnabled && pid != curGamePid_) {
            tempRecord->AddKeyThread(uiTid, PRIO_RT);
        }
        tempRecord->BeginScene();
    } else {
        delete tempRecord;
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
    std::lock_guard<std::mutex> lock(appInfoLock_);
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetPid() == pid) {
            iter->EndScene();
            return;
        }
    }
}

void TaskController::NewAppStart(int uid, int pid, const std::string& bundleName)
{
    CONCUR_LOGI("pid %{public}d start.", pid);
    unsigned int pidParam = static_cast<unsigned int>(pid);
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_DEFAULT);

    int ret = AuthEnable(pidParam, uaFlag, status);
    if (ret == 0) {
        CONCUR_LOGI("auth_enable %{public}d success", pid);
    } else {
        CONCUR_LOGE("auth_enable %{public}d fail with ret %{public}d", pid, ret);
        return;
    }
    authApps_.push_back(pid);
    appBundleName[pid] = bundleName;
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
    appBundleName.erase(pid);
}

int TaskController::AuthSystemProcess(int pid)
{
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_SYSTEM_SERVER);
    int ret = AuthEnable(pid, uaFlag, status);
    if (ret == 0) {
        CONCUR_LOGI("auth process %{public}d success", pid);
    } else {
        CONCUR_LOGI("auth process %{public}d failed, ret %{public}d", pid, ret);
    }
    return ret;
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

void TaskController::FocusStatusProcess(int uid, int pid, int status)
{
    int ret = -1;
    unsigned int rtgFlag = AF_RTG_ALL;
    unsigned int qosFlag = AF_QOS_DELEGATED;
    if (status == static_cast<int>(MSG_GET_FOCUS)) {
        ret = AuthSwitch(pid, rtgFlag, qosFlag, static_cast<unsigned int>(AuthStatus::AUTH_STATUS_FOCUS));
        CONCUR_LOGI("pid %{public}d get focus. ret %{public}d", pid, ret);
    } else if (status == static_cast<int>(MSG_LOSE_FOCUS)) {
        ret = AuthSwitch(pid, rtgFlag, qosFlag, static_cast<unsigned int>(AuthStatus::AUTH_STATUS_FOREGROUND));
        CONCUR_LOGI("pid %{public}d lose focus. ret %{public}d", pid, ret);
    } else {
        CONCUR_LOGE("Invalid focus status %{public}d", status);
    }
}

void TaskController::QueryDeadline(int queryItem, DeadlineReply& ddlReply, const Json::Value& payload)
{
    pid_t uid = IPCSkeleton::GetInstance().GetCallingUid();
    std::string processName = GetProcessNameByToken();
    if (processName != RENDER_SERVICE_PROCESS_NAME && processName != GAME_ACCELERATE_SCHED_PROCESS_NAME) {
        CONCUR_LOGE("Invalid uid %{public}d, only RS or RSS can call QueryDeadline", uid);
        return;
    }
    switch (queryItem) {
        case DDL_RATE: {
            ModifySystemRate(payload);
            break;
        }
        case MSG_GAME: {
            ModifyGameState(payload);
            break;
        }
        default: {
            break;
        }
    }
}

void TaskController::ModifyGameState(const Json::Value& payload)
{
    if (!CheckJsonValid(payload)) {
        CONCUR_LOGE("[MSG_GAME]receive json invalid");
        return;
    }
    if (payload["gameMsg"].isNull()) {
        CONCUR_LOGE("[MSG_GAME]message is null");
        return;
    }
    std::string gameMsg = payload["gameMsg"].asString();
    int oldGamePid = curGamePid_;
    int newGamePid = GetGamePid(gameMsg);
    curGamePid_ = newGamePid;
    CONCUR_LOGI("[MSG_GAME]current game pid is %{public}d, old game pid is %{public}d",
                newGamePid, oldGamePid);
    if (curGamePid_ == -1) {
        return;
    }
    std::lock_guard<std::mutex> lock(appInfoLock_);
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetPid() == curGamePid_ && iter->GetGrpId() >= 0) {
            CONCUR_LOGI("[MSG_GAME]destroy rtg grp, pid is %{public}d grpId is %{public}d",
                        iter->GetPid(), iter->GetGrpId());
            DestroyRtgGrp(iter->GetGrpId());
            iter->SetGrpId(-1);
            break;
        }
    }
    return;
}

int TaskController::GetGamePid(const std::string &gameMsg) const
{
    GameStatus status = GetGameScene(gameMsg);
    CONCUR_LOGI("[MSG_GAME]gamescene status %{public}d", status);
    int gamePid = -1;
    if (status == GAME_ENTRY_MSG) {
        size_t pos = gameMsg.find(",");
        if (pos == string::npos) {
            return -1;
        }
        int ret = sscanf_s(gameMsg.substr(0, pos).c_str(), "{\"gamePid\":\"%d\"", &gamePid);
        if (ret == -1) {
            CONCUR_LOGE("[MSG_GAME]message parsing failed, ret is %{public}d", ret);
        } else {
            CONCUR_LOGI("[MSG_GAME]message parsing success");
        }
    }
    return gamePid;
}

GameStatus TaskController::GetGameScene(const std::string &gameMsg) const
{
    if (gameMsg.find("gameScene\":\"1") != std::string::npos) {
        return GAME_ENTRY_MSG;
    }
    if (gameMsg.find("gameScene\":\"0") != std::string::npos) {
        return GAME_EXIT_MSG;
    }
    if (gameMsg.find("cameraScene\":\"1") != std::string::npos) {
        return CAMERA_ENTRY_MSG;
    }
    if (gameMsg.find("cameraScene\":\"0") != std::string::npos) {
        return CAMERA_EXIT_MSG;
    }
    if (gameMsg.find("GTXGamePid\":") != std::string::npos) {
        return GAME_GTX_MSG;
    }
    return STATUS_MSG_MAX;
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
    int uniAppRate = FindRateFromInfo(UNI_APP_RATE_ID, payload);
    if (uniAppRate > 0) {
        CONCUR_LOGD("set unified app rate %{public}d", uniAppRate);
        bool ret = OHOS::system::SetParameter(INTERVAL_APP_RATE, std::to_string(uniAppRate));
        if (ret == false) {
            CONCUR_LOGI("set app rate param failed");
        }
        StartTrace(HITRACE_TAG_ACE,
            "SetAppRate:" + std::to_string(uniAppRate) + " ret:" + std::to_string(ret));
        FinishTrace(HITRACE_TAG_ACE);
        return;
    }
    std::lock_guard<std::mutex> lock(appInfoLock_);
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        uiTid = iter->GetUiTid();
        rtgId = iter->GetGrpId();
        if (uiTid <= 0 || rtgId <= 0) {
            continue;
        }
        appRate = FindRateFromInfo(uiTid, payload);
        if (appRate > 0 && appRate != iter->GetRate()) {
            CONCUR_LOGI("set app rate %{public}d rtgId is %{public}d, old rate is %{public}d",
                        appRate, rtgId, iter->GetRate());
            SetFrameRate(rtgId, appRate);
            iter->SetRate(appRate);
        }
    }
    return;
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
    int rsRate = FindRateFromInfo(renderServiceMainTid_, payload);
    std::lock_guard<std::mutex> lock(rateInfoLock_);
    if (renderServiceMainGrpId_ > 0 && rsRate > 0 && rsRate != systemRate_) {
        CONCUR_LOGD("set rs rate %{public}d rtgId is %{public}d, old rate is %{public}d",
                    rsRate, renderServiceMainGrpId_, systemRate_);
        SetFrameRate(renderServiceMainGrpId_, rsRate);
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
    std::lock_guard<std::mutex> lock(appInfoLock_);
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

ForegroundAppRecord::ForegroundAppRecord(int pid, int uiTid, bool createGrp)
{
    pid_ = pid;
    uiTid_ = uiTid;
    if (OHOS::system::GetBoolParameter(INTERVAL_DDL, false) && createGrp) {
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
        CONCUR_LOGI("Add key thread fail: Grp id not been created success, tid is %{public}d", tid);
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
    OHOS::RME::BeginFrameFreq(0);
    OHOS::RME::EndFrameFreq(0);
    return true;
}

bool ForegroundAppRecord::EndScene()
{
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

void ForegroundAppRecord::SetGrpId(int grpId)
{
    grpId_ = grpId;
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
