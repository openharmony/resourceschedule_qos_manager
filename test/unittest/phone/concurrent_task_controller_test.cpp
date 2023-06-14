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
HWTEST_F(ConcurrentTaskControllerTest, AuthHwcTest, TestSize.Level1)
{
    TaskController::GetInstance().SetHwcAuth(true);
    TaskController::GetInstance().SetHwcAuth(false);
    TaskController::GetInstance().SetHwcAuth(true);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, CheckUidTest, TestSize.Level1)
{
    int uid = SYSTEM_UID;
    bool ret = TaskController::GetInstance().CheckUid(uid);
    EXPECT_EQ(ret, true);
    uid = 0;
    ret = TaskController::GetInstance().CheckUid(uid);
    EXPECT_EQ(ret, true);
    uid = 100;
    ret = TaskController::GetInstance().CheckUid(uid);
    EXPECT_EQ(ret, false);
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
HWTEST_F(ConcurrentTaskControllerTest, QueryRenderServiceTest, TestSize.Level1)
{
    int uid = SYSTEM_UID;
    IntervalReply queryRs = {87, 657, 357, 214};
    TaskController::GetInstance().QueryRenderService(uid, queryRs);
    int flag = TaskController::GetInstance().renderServiceGrpId_;
    TaskController::GetInstance().renderServiceGrpId_ = 1;
    TaskController::GetInstance().QueryRenderService(uid, queryRs);
    TaskController::GetInstance().renderServiceGrpId_ = -1;
    TaskController::GetInstance().QueryRenderService(uid, queryRs);
    TaskController::GetInstance().renderServiceGrpId_ = flag;
    TaskController::GetInstance().QueryRenderService(uid, queryRs);
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
    int uid = 0;
    fore.NewForeground(uid);
    fore.NewBackground(uid);
    fore.NewAppStart(uid);
    fore.NewForeground(uid);
    fore.NewBackground(uid);
    fore.AppKilled(uid);
    uid = 574;
    fore.foregroundApp_.push_back(ForegroundAppRecord(574));
    fore.foregroundApp_.push_back(ForegroundAppRecord(1));
    fore.foregroundApp_.push_back(ForegroundAppRecord(3));
    auto iter = fore.foregroundApp_.begin();
    EXPECT_EQ(iter->GetUid(), uid);
    fore.NewForeground(uid);
    fore.NewBackground(uid);
    fore.NewAppStart(uid);
    fore.NewForeground(uid);
    fore.NewBackground(uid);
    fore.AppKilled(uid);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerTest, PrintInfoTest, TestSize.Level1)
{
    TaskController print;
    print.foregroundApp_.push_back(ForegroundAppRecord(1));
    print.foregroundApp_.push_back(ForegroundAppRecord(3));
    print.foregroundApp_.push_back(ForegroundAppRecord(5));
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
    ForegroundAppRecord foregroundapprecord = ForegroundAppRecord(uid);
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
    int uid = 758;
    ForegroundAppRecord foregroundapprecord = ForegroundAppRecord(uid);
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
    int uid = 758;
    ForegroundAppRecord foregroundapprecord = ForegroundAppRecord(uid);
    EXPECT_EQ(foregroundapprecord.GetUid(), foregroundapprecord.uid_);
    EXPECT_EQ(foregroundapprecord.GetGrpId(), foregroundapprecord.grpId_);
    foregroundapprecord.uid_ = -1;
    foregroundapprecord.grpId_ = 1;
    EXPECT_EQ(foregroundapprecord.IsValid(), false);
    foregroundapprecord.uid_ = -1;
    foregroundapprecord.grpId_ = -1;
    EXPECT_EQ(foregroundapprecord.IsValid(), false);
    foregroundapprecord.uid_ = 1;
    foregroundapprecord.grpId_ = -1;
    EXPECT_EQ(foregroundapprecord.IsValid(), false);
    foregroundapprecord.uid_ = 1;
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
    int uid = 758;
    ForegroundAppRecord foregroundapprecord = ForegroundAppRecord(uid);
    foregroundapprecord.keyThreads_.insert(1);
    foregroundapprecord.keyThreads_.insert(3);
    foregroundapprecord.keyThreads_.insert(5);
    foregroundapprecord.keyThreads_.insert(7);
    foregroundapprecord.keyThreads_.insert(9);
    auto iter = foregroundapprecord.keyThreads_.begin();
    EXPECT_NE(iter, foregroundapprecord.keyThreads_.end());
    foregroundapprecord.PrintKeyThreads();
}
}
}