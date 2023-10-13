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

#include "gtest/gtest.h"
#include "concurrent_task_service.h"
#include "concurrent_task_controller.h"

namespace OHOS {
namespace FFRT_TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::ConcurrentTask;


class ConcurrentTaskServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConcurrentTaskServiceTest::SetUpTestCase()
{
}

void ConcurrentTaskServiceTest::TearDownTestCase()
{
}

void ConcurrentTaskServiceTest::SetUp()
{
}

void ConcurrentTaskServiceTest::TearDown()
{
}

/**
 * @tc.name: QueryIntervalTest
 * @tc.desc: Test whether the QueryInterval interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceTest, QueryIntervalTest, TestSize.Level1)
{
    int queryItem = 0;
    IntervalReply queryRs = {87, 657, 357, 214};
    ConcurrentTaskService queInt;
    queInt.QueryInterval(queryItem, queryRs);
}

/**
 * @tc.name: QueryDeadlineTest
 * @tc.desc: Test whether the QueryDeadline interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceTest, QueryDeadlineTest, TestSize.Level1)
{
    int queryItem = 0;
    DeadlineReply ddlReply = { false };
    Json::Value payload;
    payload["1111"] = "60";
    payload["2222"] = "90";
    ConcurrentTaskService queInt;
    queInt.QueryDeadline(queryItem, ddlReply, payload);
}
}
}