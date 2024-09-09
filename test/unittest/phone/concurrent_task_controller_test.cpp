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

#include <cinttypes>
#include <sys/resource.h>
#include <sched.h>
#include <linux/sched.h>
#include "gtest/gtest.h"
#include "parameters.h"
#define private public
#include "concurrent_task_controller.h"
#include "rtg_interface.h"
#include "ipc_skeleton.h"
#include "concurrent_task_log.h"
#undef private

namespace OHOS {
namespace FFRT_TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::ConcurrentTask;
using namespace std;


class ConcurrentTaskControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConcurrentTaskControllerTest::SetUpTestCase()
{
}

void ConcurrentTaskControllerTest::TearDownTestCase()
{
}

void ConcurrentTaskControllerTest::SetUp()
{
}

void ConcurrentTaskControllerTest::TearDown()
{
}

/**
 * @tc.name: ReportDataTest
 * @tc.desc: Test whether the ReportDataTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, ReportDataTest, TestSize.Level1)
{
    uint32_t resType = 0;
    int64_t value = 0;
    const Json::Value payload;
    TaskController repData;
    repData.ReportData(resType, value, payload);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, QueryIntervalTest, TestSize.Level1)
{
    TaskController queInt;
    int queryItem = QUERY_UI;
    IntervalReply queryRs = {87, 657, 357, 214};
    queInt.QueryInterval(queryItem, queryRs);
    queryItem = QUERY_RENDER;
    queInt.QueryInterval(queryItem, queryRs);
    queryItem = QUERY_RENDER_SERVICE;
    queInt.QueryInterval(queryItem, queryRs);
    queryItem = QUERY_COMPOSER;
    queInt.QueryInterval(queryItem, queryRs);
    queryItem = QURRY_TYPE_MAX;
    queInt.QueryInterval(queryItem, queryRs);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, InitTest, TestSize.Level1)
{
    TaskController::GetInstance().Init();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, TypeMapInitTest, TestSize.Level1)
{
    TaskController::GetInstance().TypeMapInit();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, TryCreateRsGroupTest, TestSize.Level1)
{
    TaskController::GetInstance().rtgEnabled_ = false;
    TaskController::GetInstance().TryCreateRsGroup();
    TaskController::GetInstance().rtgEnabled_ = true;
    TaskController::GetInstance().TryCreateRsGroup();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, TryCreateRSMainGrpTest, TestSize.Level1)
{
    TaskController::GetInstance().rtgEnabled_ = false;
    TaskController::GetInstance().TryCreateRSMainGrp();
    TaskController::GetInstance().rtgEnabled_ = true;
    TaskController::GetInstance().TryCreateRSMainGrp();
}
 
/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, TryCreateRSRenderGrpTest, TestSize.Level1)
{
    TaskController::GetInstance().rtgEnabled_ = false;
    TaskController::GetInstance().TryCreateRSRenderGrp();
    TaskController::GetInstance().rtgEnabled_ = true;
    TaskController::GetInstance().TryCreateRSRenderGrp();
}

/**
 * @tc.name:QueryRenderServiceTest
 * @tc.desc: Test whether the QueryRenderService interface is normal
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, QueryRenderServiceTest, TestSize.Level1)
{
    int uid = SYSTEM_UID;
    IntervalReply queryRs = {87, 657, 357, 214};
    TaskController::GetInstance().QueryRenderService(uid, queryRs);
    int grpId = TaskController::GetInstance().renderServiceMainGrpId_;
    EXPECT_TRUE(grpId > 0);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, QueryRenderServiceMainTest, TestSize.Level1)
{
    int uid = SYSTEM_UID;
    int pid = getpid();
    IntervalReply queryRs = {87, 657, 357, 214};
    TaskController::GetInstance().QueryRenderServiceMain(uid, pid, queryRs);
    int flag = TaskController::GetInstance().renderServiceMainGrpId_;
    TaskController::GetInstance().renderServiceMainGrpId_ = 1;
    TaskController::GetInstance().QueryRenderServiceMain(uid, pid, queryRs);
    TaskController::GetInstance().renderServiceMainGrpId_ = -1;
    TaskController::GetInstance().QueryRenderServiceMain(uid, pid, queryRs);
    TaskController::GetInstance().renderServiceMainGrpId_ = flag;
    TaskController::GetInstance().QueryRenderServiceMain(uid, pid, queryRs);
}
 
/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, QueryRenderServiceRenderTest, TestSize.Level1)
{
    int uid = SYSTEM_UID;
    int pid = getpid();
    IntervalReply queryRs = {87, 657, 357, 214};
    TaskController::GetInstance().QueryRenderServiceRender(uid, pid, queryRs);
    int flag = TaskController::GetInstance().renderServiceRenderGrpId_;
    TaskController::GetInstance().renderServiceRenderGrpId_ = 1;
    TaskController::GetInstance().QueryRenderServiceRender(uid, pid, queryRs);
    TaskController::GetInstance().renderServiceRenderGrpId_ = -1;
    TaskController::GetInstance().QueryRenderServiceRender(uid, pid, queryRs);
    TaskController::GetInstance().renderServiceRenderGrpId_ = flag;
    TaskController::GetInstance().QueryRenderServiceRender(uid, pid, queryRs);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, GetRequestTypeTest, TestSize.Level1)
{
    std::string strRequstType = "test";
    int ret = TaskController::GetInstance().GetRequestType(strRequstType);
    EXPECT_EQ(ret, MSG_TYPE_MAX);
    TaskController::GetInstance().msgType_["test"] = 8;
    ret = TaskController::GetInstance().GetRequestType(strRequstType);
    EXPECT_EQ(ret, 8);
    TaskController::GetInstance().msgType_.erase("test");
    ret = TaskController::GetInstance().GetRequestType(strRequstType);
    EXPECT_EQ(ret, MSG_TYPE_MAX);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, NewForegroundTest, TestSize.Level1)
{
    TaskController fore;
    int uid = getuid();
    int tid = gettid();
    fore.NewForeground(uid, tid);
    fore.NewBackground(uid, tid);
    fore.NewAppStart(uid, tid, "");
    fore.NewForeground(uid, tid);
    fore.NewBackground(uid, tid);
    fore.ContinuousTaskProcess(uid, tid, static_cast<int>(MSG_CONTINUOUS_TASK_START));
    fore.FocusStatusProcess(uid, tid, static_cast<int>(MSG_GET_FOCUS));
    fore.FocusStatusProcess(uid, tid, static_cast<int>(MSG_LOSE_FOCUS));
    fore.AppKilled(uid, tid);
    tid = 574;
    fore.foregroundApp_.push_back(ForegroundAppRecord(tid, 0));
    fore.foregroundApp_.push_back(ForegroundAppRecord(1, 0));
    fore.foregroundApp_.push_back(ForegroundAppRecord(3, 0));
    auto iter = fore.foregroundApp_.begin();
    EXPECT_EQ(iter->GetPid(), tid);
    fore.NewForeground(uid, tid);
    fore.NewBackground(uid, tid);
    fore.NewAppStart(uid, tid, "");
    fore.NewForeground(uid, tid);
    fore.NewBackground(uid, tid);
    fore.ContinuousTaskProcess(uid, tid, static_cast<int>(MSG_CONTINUOUS_TASK_END));
    fore.AppKilled(uid, tid);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, PrintInfoTest, TestSize.Level1)
{
    TaskController print;
    print.foregroundApp_.push_back(ForegroundAppRecord(1, 0));
    print.foregroundApp_.push_back(ForegroundAppRecord(3, 0));
    print.foregroundApp_.push_back(ForegroundAppRecord(5, 0));
    auto iter = print.foregroundApp_.begin();
    EXPECT_NE(iter, print.foregroundApp_.end());
    print.PrintInfo();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, AddKeyThreadTest, TestSize.Level1)
{
    int uid = 758;
    int tid = 45;
    int tid2 = 46;
    int tid3 = 47;
    int tid4 = 48;
    int tid5 = 49;
    int prio = PRIO_NORMAL;
    ForegroundAppRecord foregroundapprecord = ForegroundAppRecord(tid, 0);
    foregroundapprecord.AddKeyThread(tid, prio);
    foregroundapprecord.keyThreads_.insert(tid);
    foregroundapprecord.AddKeyThread(tid, prio);
    foregroundapprecord.grpId_ = -1;
    foregroundapprecord.AddKeyThread(tid, prio);
    foregroundapprecord.grpId_ = 1;
    foregroundapprecord.AddKeyThread(tid, prio);
    foregroundapprecord.keyThreads_.insert(tid2);
    foregroundapprecord.keyThreads_.insert(tid3);
    foregroundapprecord.keyThreads_.insert(tid4);
    foregroundapprecord.keyThreads_.insert(tid5);
    foregroundapprecord.keyThreads_.insert(tid5);
    foregroundapprecord.AddKeyThread(tid, prio);
    prio = RPIO_IN;
    foregroundapprecord.keyThreads_.insert(tid);
    prio = PRIO_RT;
    foregroundapprecord.keyThreads_.insert(tid);
    foregroundapprecord.AddKeyThread(tid, prio);
    foregroundapprecord.keyThreads_.clear();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, BeginSceneTest, TestSize.Level1)
{
    int pid = 758;
    ForegroundAppRecord foregroundapprecord = ForegroundAppRecord(pid, 0);
    foregroundapprecord.BeginScene();
    foregroundapprecord.EndScene();
    foregroundapprecord.grpId_ = -1;
    foregroundapprecord.BeginScene();
    foregroundapprecord.EndScene();
    foregroundapprecord.grpId_ = 1;
    foregroundapprecord.BeginScene();
    foregroundapprecord.EndScene();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, IsValidTest, TestSize.Level1)
{
    int pid = 758;
    ForegroundAppRecord foregroundapprecord = ForegroundAppRecord(pid, 0);
    EXPECT_EQ(foregroundapprecord.GetPid(), foregroundapprecord.pid_);
    EXPECT_EQ(foregroundapprecord.GetGrpId(), foregroundapprecord.grpId_);
    foregroundapprecord.pid_ = -1;
    foregroundapprecord.grpId_ = 1;
    EXPECT_EQ(foregroundapprecord.IsValid(), false);
    foregroundapprecord.pid_ = -1;
    foregroundapprecord.grpId_ = -1;
    EXPECT_EQ(foregroundapprecord.IsValid(), false);
    foregroundapprecord.pid_ = 1;
    foregroundapprecord.grpId_ = -1;
    EXPECT_EQ(foregroundapprecord.IsValid(), true);
    foregroundapprecord.pid_ = 1;
    foregroundapprecord.grpId_ = 1;
    EXPECT_EQ(foregroundapprecord.IsValid(), true);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, PrintKeyThreadsTest, TestSize.Level1)
{
    int pid = 758;
    ForegroundAppRecord foregroundapprecord = ForegroundAppRecord(pid, 0);
    foregroundapprecord.keyThreads_.insert(1);
    foregroundapprecord.keyThreads_.insert(3);
    foregroundapprecord.keyThreads_.insert(5);
    foregroundapprecord.keyThreads_.insert(7);
    foregroundapprecord.keyThreads_.insert(9);
    auto iter = foregroundapprecord.keyThreads_.begin();
    EXPECT_NE(iter, foregroundapprecord.keyThreads_.end());
    foregroundapprecord.PrintKeyThreads();
}


/**
 * @tc.name: QueryDeadlineTest
 * @tc.desc: Test whether the QueryDeadlineTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, QueryDeadlineTest, TestSize.Level1)
{
    int queryItem = DDL_RATE;
    DeadlineReply ddlReply = { false };
    const Json::Value payload;
    TaskController::GetInstance().QueryDeadline(queryItem, ddlReply, payload);
}

/**
 * @tc.name: ModifySystemRateTest
 * @tc.desc: Test whether the ModifySystemRate interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, ModifySystemRateTest, TestSize.Level1)
{
    Json::Value payload;
    TaskController::GetInstance().ModifySystemRate(payload);
    payload["1111"] = "60";
    TaskController::GetInstance().ModifySystemRate(payload);
}

/**
 * @tc.name: SetAppRate
 * @tc.desc: Test whether the SetAppRate interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, SetAppRateTest, TestSize.Level1)
{
    Json::Value payload;
    ForegroundAppRecord foreApp1 = ForegroundAppRecord(758, 758);
    foreApp1.SetRate(60);
    TaskController::GetInstance().foregroundApp_.push_back(foreApp1);
    TaskController::GetInstance().foregroundApp_.begin()->grpId_ = 1;
    payload["758"] = "120";
    TaskController::GetInstance().SetAppRate(payload);
    int curAppRate = TaskController::GetInstance().foregroundApp_.begin()->GetRate();
    EXPECT_EQ(curAppRate, 120);
    payload["-1"] = "120";
    TaskController::GetInstance().SetAppRate(payload);
    EXPECT_EQ(OHOS::system::GetIntParameter("persist.ffrt.interval.appRate", 0), 120);
}

/**
 * @tc.name: FindRateFromInfo
 * @tc.desc: Test whether the FindRateFromInfo interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, FindRateFromInfoTest, TestSize.Level1)
{
    Json::Value payload;
    payload["758"] = "120";
    payload["759"] = "120XXY";
    int ret = TaskController::GetInstance().FindRateFromInfo(754, payload);
    EXPECT_EQ(ret, 0);
    ret = TaskController::GetInstance().FindRateFromInfo(758, payload);
    EXPECT_EQ(ret, 120);
    TaskController::GetInstance().FindRateFromInfo(759, payload);
}

/**
 * @tc.name: SetRenderServiceRate
 * @tc.desc: Test whether the SetRenderServiceRate interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, SetRenderServiceRateTest, TestSize.Level1)
{
    Json::Value payload;
    payload["758"] = "120";
    TaskController::GetInstance().renderServiceMainTid_ = 758;
    TaskController::GetInstance().systemRate_ = 0;
    TaskController::GetInstance().renderServiceMainGrpId_ = 1;
    TaskController::GetInstance().SetRenderServiceRate(payload);
    EXPECT_EQ(TaskController::GetInstance().systemRate_, 120);
    EXPECT_EQ(OHOS::system::GetIntParameter("persist.ffrt.interval.rsRate", 0), 120);
}

/**
 * @tc.name: SetFrameRate
 * @tc.desc: Test whether the SetFrameRate interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, SetFrameRateTest, TestSize.Level1)
{
    TaskController::GetInstance().SetFrameRate(758, 120);
    TaskController::GetInstance().SetFrameRate(0, 120);
}

/**
 * @tc.name: GetPid
 * @tc.desc: Test whether the GetPid interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, GetPidTest, TestSize.Level1)
{
    ForegroundAppRecord foreApp = ForegroundAppRecord(758, 0);
    EXPECT_EQ(foreApp.GetPid(), 758);
}

/**
 * @tc.name: GetUiTid
 * @tc.desc: Test whether the GetUiTid interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, GetUiTidTest, TestSize.Level1)
{
    ForegroundAppRecord foreApp = ForegroundAppRecord(758, 758);
    EXPECT_EQ(foreApp.GetUiTid(), 758);
}

/**
 * @tc.name: SetRate
 * @tc.desc: Test whether the SetRate interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, SetRateTest, TestSize.Level1)
{
    ForegroundAppRecord foreApp = ForegroundAppRecord(758, 758);
    foreApp.SetRate(120);
    EXPECT_EQ(foreApp.GetRate(), 120);
}

/**
 * @tc.name: SetUiTid
 * @tc.desc: Test whether the SetUiTid interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, SetUiTidTest, TestSize.Level1)
{
    ForegroundAppRecord foreApp = ForegroundAppRecord(758, 758);
    EXPECT_EQ(foreApp.GetUiTid(), 758);
    foreApp.SetUiTid(755);
    EXPECT_EQ(foreApp.GetUiTid(), 755);
}

/**
 * @tc.name: SetGrpId
 * @tc.desc: Test whether the SetGrpId interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, SetGrpId, TestSize.Level1)
{
    ForegroundAppRecord foreApp = ForegroundAppRecord(758, 758);
    foreApp.SetGrpId(-1);
    EXPECT_EQ(foreApp.GetGrpId(), -1);
}

/**
 * @tc.name: GetGameScene
 * @tc.desc: Test whether the GetGameScene interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, GetGameScene, TestSize.Level1)
{
    std::string testMsg = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\","
                          "\"gameScene\":\"1\",\"renderThread\":\"5579\"}";
    GameStatus status = TaskController::GetInstance().GetGameScene(testMsg);
    EXPECT_EQ(status, GAME_ENTRY_MSG);
    testMsg = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\",\"gameScene\":\"0\"}";
    status = TaskController::GetInstance().GetGameScene(testMsg);
    EXPECT_EQ(status, GAME_EXIT_MSG);
    testMsg = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\",\"gameScene\":\"2\"}";
    status = TaskController::GetInstance().GetGameScene(testMsg);
    EXPECT_EQ(status, STATUS_MSG_MAX);
    testMsg = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\",\"cameraScene\":\"1\"}";
    status = TaskController::GetInstance().GetGameScene(testMsg);
    EXPECT_EQ(status, CAMERA_ENTRY_MSG);
    testMsg = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\",\"cameraScene\":\"0\"}";
    status = TaskController::GetInstance().GetGameScene(testMsg);
    EXPECT_EQ(status, CAMERA_EXIT_MSG);
}

/**
 * @tc.name: GetGamePid
 * @tc.desc: Test whether the GetGamePid interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, GetGamePid, TestSize.Level1)
{
    std::string testMsg = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\","
                          "\"gameScene\":\"1\",\"renderThread\":\"5579\"}";
    int gamePid = TaskController::GetInstance().GetGamePid(testMsg);
    EXPECT_EQ(gamePid, 5578);
    testMsg = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\",\"gameScene\":\"0\"}";
    gamePid = TaskController::GetInstance().GetGamePid(testMsg);
    EXPECT_EQ(gamePid, -1);
    testMsg = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\",\"gameScene\":\"2\"}";
    gamePid = TaskController::GetInstance().GetGamePid(testMsg);
    EXPECT_EQ(gamePid, -1);
}

/**
 * @tc.name: NewForegroundAppRecord
 * @tc.desc: Test whether the NewForegroundAppRecord interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, NewForegroundAppRecord, TestSize.Level1)
{
    TaskController::GetInstance().curGamePid_ = 756;
    TaskController::GetInstance().NewForegroundAppRecord(756, 756, true);
    TaskController::GetInstance().NewForegroundAppRecord(757, 757, true);
    TaskController::GetInstance().NewForegroundAppRecord(757, 757, false);
}

/**
 * @tc.name: ModifyGameState
 * @tc.desc: Test whether the ModifyGameState interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, ModifyGameState, TestSize.Level1)
{
    Json::Value payload;
    payload["gameMsg"] = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\","
                         "\"gameScene\":\"1\",\"renderThread\":\"5579\"}";
    TaskController::GetInstance().ModifyGameState(payload);
    EXPECT_EQ(TaskController::GetInstance().curGamePid_, 5578);
    payload["gameMsg"] = "{\"gamePid\":\"5578\",\"packageName\":\"com.happyelements.OhosAnimal\","
                         "\"gameScene\":\"0\"}";
    TaskController::GetInstance().ModifyGameState(payload);
    EXPECT_EQ(TaskController::GetInstance().curGamePid_, -1);
}
}
}
