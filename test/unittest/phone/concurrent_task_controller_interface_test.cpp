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
#include "concurrent_task_controller_interface.h"
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

class ConcurrentTaskControllerInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConcurrentTaskControllerInterfaceTest::SetUpTestCase() {}

void ConcurrentTaskControllerInterfaceTest::TearDownTestCase() {}

void ConcurrentTaskControllerInterfaceTest::SetUp() {}

void ConcurrentTaskControllerInterfaceTest::TearDown() {}

/**
 * @tc.name: RequestAuthTest
 * @tc.desc: Test whether the ReportDataTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerInterfaceTest, RequestAuthTest, TestSize.Level1)
{
    const Json::Value payload;
    TaskControllerInterface repData;
    repData.RequestAuth(payload);
}

/**
 * @tc.name: ReportDataTest
 * @tc.desc: Test whether the ReportDataTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerInterfaceTest, ReportDataTest, TestSize.Level1)
{
    uint32_t resType = 0;
    int64_t value = 0;
    const Json::Value payload;
    TaskControllerInterface repData;
    repData.ReportData(resType, value, payload);
}

/**
 * @tc.name: QueryDeadlineTest
 * @tc.desc: Test whether the QueryDeadlineTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerInterfaceTest, QueryDeadlineTest, TestSize.Level1)
{
    int queryItem = DDL_RATE;
    DeadlineReply ddlReply = {false};
    const Json::Value payload;
    TaskControllerInterface::GetInstance().QueryDeadline(queryItem, ddlReply, payload);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerInterfaceTest, QueryIntervalTest, TestSize.Level1)
{
    TaskControllerInterface queInt;
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
HWTEST_F(ConcurrentTaskControllerInterfaceTest, InitTest, TestSize.Level1)
{
    TaskControllerInterface::GetInstance().Init();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskControllerInterfaceTest, ReleaseTest, TestSize.Level1)
{
    TaskControllerInterface::GetInstance().Release();
}
} // namespace FFRT_TEST
} // namespace OHOS