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
#include "concurrent_task_client.h"

namespace OHOS {
namespace FFRT_TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::ConcurrentTask;


class ConcurrentTaskClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConcurrentTaskClientTest::SetUpTestCase()
{
}

void ConcurrentTaskClientTest::TearDownTestCase()
{
}

void ConcurrentTaskClientTest::SetUp()
{
}

void ConcurrentTaskClientTest::TearDown()
{
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskClientTest, ReportDataTest, TestSize.Level1)
{
    uint32_t resType = 0;
    int64_t value = 3587;
    std::unordered_map<std::string, std::string> payload;
    payload["uid"] = "3587";
    payload["pid"] = "12345";
    payload["type"] = "appStart";
    ConcurrentTaskClient::GetInstance().ReportData(resType, value, payload);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskClientTest, QueryIntervalTest, TestSize.Level1)
{
    int queryItem = 3;
    IntervalReply queryRs = {87, 657, 357, 214};
    ConcurrentTaskClient::GetInstance().QueryInterval(queryItem, queryRs);
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskClientTest, StopRemoteObjectTest, TestSize.Level1)
{
    ConcurrentTaskClient::GetInstance().StopRemoteObject();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
*/
HWTEST_F(ConcurrentTaskClientTest, QueryDeadlineTest, TestSize.Level1)
{
    int queryItem = 0;
    DeadlineReply ddlReply = { false };
    std::unordered_map<pid_t, uint32_t> payload;
    payload[1111] = 60;
    payload[2222] = 90;
    ConcurrentTaskClient::GetInstance().QueryDeadline(queryItem, ddlReply, payload);
}

/**
 * @tc.name: RequestAuthTest
 * @tc.desc: Test whether the RequestAuth interface are normal.
 * @tc.type: FUNC
*/
HWTEST_F(ConcurrentTaskClientTest, RequestAuthTest, TestSize.Level1)
{
    std::unordered_map<std::string, std::string> payload;
    payload["uid"] = "3587";
    payload["pid"] = "12345";
    ConcurrentTaskClient::GetInstance().RequestAuth(payload);
}
}
}