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

#include <map>
#include <string>
#include <unistd.h>
#include <iostream>
#include "gtest/gtest.h"
#include "concurrent_task_log.h"
#include "concurrent_task_client.h"

namespace OHOS {
namespace ConcurrentTask {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::ConcurrentTask;
using namespace std;

constexpr int HUGE_ITEM = 1000000;

class ConcurrentSvcIntfTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static int QueryInterval(int item)
{
    IntervalReply rs;
    rs.rtgId = -1;
    cout << "start to query renderService" <<endl;
    OHOS::ConcurrentTask::ConcurrentTaskClient::GetInstance().QueryInterval(
        item, rs);
    return rs.rtgId;
}

void ConcurrentSvcIntfTest::SetUpTestCase()
{
}

void ConcurrentSvcIntfTest::TearDownTestCase()
{
}

void ConcurrentSvcIntfTest::SetUp()
{
}

void ConcurrentSvcIntfTest::TearDown()
{
}

/**
 * @tc.name: QueryBeforeGetPriv
 * @tc.desc: Before get privlege, render query result should be wrong
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentSvcIntfTest, QueryBeforeGetPriv, TestSize.Level1)
{
    int grpId = QueryInterval(QUERY_RENDER);
    EXPECT_EQ(grpId, -1);
}

/**
 * @tc.name: QueryHugeItem
 * @tc.desc: If query a huge item, should return invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentSvcIntfTest, QueryHugeItem, TestSize.Level1)
{
    int grpId = QueryInterval(HUGE_ITEM);
    EXPECT_LT(grpId, 0);
}

/**
 * @tc.name: QueryNagativeItem
 * @tc.desc: If query a huge item, should return invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentSvcIntfTest, QueryNagativeItem, TestSize.Level1)
{
    int grpId = QueryInterval(-1);
    EXPECT_LT(grpId, 0);
}

/**
 * @tc.name: QuerySystemUid
 * @tc.desc: Confirm the test binary can execute seteuid function.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentSvcIntfTest, QueryRenderServiceTest, TestSize.Level1)
{
    int grpId = QueryInterval(QUERY_RENDER_SERVICE_MAIN);
#if TDD_MUSL
    EXPECT_GT(grpId, 0);
#else
    (void)grpId;
#endif
}

/**
 * @tc.name: QuerySystemUid
 * @tc.desc: Qu.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentSvcIntfTest, QueryInvalidValueTest, TestSize.Level1)
{
    int grpId = QueryInterval(QURRY_TYPE_MAX);
    EXPECT_LT(grpId, 0);
}
}
}
