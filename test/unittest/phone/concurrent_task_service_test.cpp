/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "json/json.h"

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
    IpcIntervalReply IpcQueryRs = {87, 657, 357, 214};
    ConcurrentTaskService queInt;
    queInt.QueryInterval(queryItem, IpcQueryRs);
    EXPECT_NE(IpcQueryRs.tid, -1);
}

/**
 * @tc.name: QueryDeadlineTest
 * @tc.desc: Test whether the QueryDeadline interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceTest, QueryDeadlineTest, TestSize.Level1)
{
    int queryItem = 0;
    IpcDeadlineReply IpcDdlReply = { false };
    std::unordered_map<std::string, std::string> payload;
    payload["1111"] = "60";
    payload["2222"] = "90";
    ConcurrentTaskService queInt;
    queInt.QueryDeadline(queryItem, IpcDdlReply, payload);
    EXPECT_FALSE(payload.empty());
}

/**
 * @tc.name: MapToJsonTest
 * @tc.desc: Test MapToJson function with a non-empty and empty map
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceTest, MapToJsonTest, TestSize.Level1)
{
    ConcurrentTaskService service;

    std::unordered_map<std::string, std::string> dataMap = {{"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
    Json::Value expectedJson;
    expectedJson["key1"] = "value1";
    expectedJson["key2"] = "value2";
    expectedJson["key3"] = "value3";
    Json::Value resultJson = service.MapToJson(dataMap);
    EXPECT_EQ(expectedJson, resultJson);

    std::unordered_map<std::string, std::string> dataMap2;
    Json::Value expectedJson2;
    Json::Value resultJson2 = service.MapToJson(dataMap2);
    EXPECT_EQ(expectedJson2, resultJson2);
}

/**
 * @tc.name: IpcToQueryRsTest
 * @tc.desc: Test whether the IpcToQueryRsTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceTest, IpcToQueryRsTest, TestSize.Level1)
{
    IpcIntervalReply ipcQueryRs;
    ipcQueryRs.rtgId = 1;
    ipcQueryRs.tid = 2;
    ipcQueryRs.paramA = 3;
    ipcQueryRs.paramB = 4;
    ipcQueryRs.bundleName = "testBundle";

    IntervalReply expectedQueryRs;
    expectedQueryRs.rtgId = 1;
    expectedQueryRs.tid = 2;
    expectedQueryRs.paramA = 3;
    expectedQueryRs.paramB = 4;
    expectedQueryRs.bundleName = "testBundle";

    ConcurrentTaskService service;
    IntervalReply actualQueryRs = service.IpcToQueryRs(ipcQueryRs);

    EXPECT_EQ(expectedQueryRs.rtgId, actualQueryRs.rtgId);
    EXPECT_EQ(expectedQueryRs.tid, actualQueryRs.tid);
    EXPECT_EQ(expectedQueryRs.paramA, actualQueryRs.paramA);
    EXPECT_EQ(expectedQueryRs.paramB, actualQueryRs.paramB);
    EXPECT_EQ(expectedQueryRs.bundleName, actualQueryRs.bundleName);
}

/**
 * @tc.name: QueryRsToIpcTest
 * @tc.desc: Test whether the QueryRsToIpcTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceTest, QueryRsToIpcTest, TestSize.Level1)
{
    IntervalReply queryRs;
    queryRs.paramB = 4;
    queryRs.tid = 2;
    queryRs.paramA = 3;
    queryRs.rtgId = 1;
    queryRs.bundleName = "mockedBundleName";

    ConcurrentTaskService service;
    IpcIntervalReply actualIpcQueryRs = service.QueryRsToIpc(queryRs);

    EXPECT_EQ(actualIpcQueryRs.rtgId, queryRs.rtgId);
    EXPECT_EQ(actualIpcQueryRs.tid, queryRs.tid);
    EXPECT_EQ(actualIpcQueryRs.paramA, queryRs.paramA);
    EXPECT_EQ(actualIpcQueryRs.paramB, queryRs.paramB);
    EXPECT_EQ(actualIpcQueryRs.bundleName, queryRs.bundleName);
}

/**
 * @tc.name: IpcToDdlReplyTest
 * @tc.desc: Test whether the IpcToDdlReplyTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceTest, IpcToDdlReplyTest, TestSize.Level1)
{
    IpcDeadlineReply IpcDdlReply;
    IpcDdlReply.setStatus = 123;

    DeadlineReply expectedDdlReply;
    expectedDdlReply.setStatus = IpcDdlReply.setStatus;

    ConcurrentTaskService service;
    DeadlineReply resultDdlReply = service.IpcToDdlReply(IpcDdlReply);

    EXPECT_EQ(expectedDdlReply.setStatus, resultDdlReply.setStatus);
}

/**
 * @tc.name: SetAudioDeadline
 * @tc.desc: Test whether the SetAudioDeadline interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceTest, SetAudioDeadlineTest, TestSize.Level1)
{
    int queryItem = AUDIO_DDL_CREATE_GRP;
    IpcIntervalReply IpcQueryRs = { 0 };
    ConcurrentTaskService queInt;
    queInt.SetAudioDeadline(queryItem, -1, -1, IpcQueryRs);
    EXPECT_NE(IpcQueryRs.rtgId, -1);
    queryItem = AUDIO_DDL_ADD_THREAD;
    queInt.SetAudioDeadline(queryItem, gettid(), IpcQueryRs.rtgId, IpcQueryRs);
    EXPECT_EQ(IpcQueryRs.paramA, 0);
    queryItem = AUDIO_DDL_REMOVE_THREAD;
    queInt.SetAudioDeadline(queryItem, gettid(), IpcQueryRs.rtgId, IpcQueryRs);
    EXPECT_EQ(IpcQueryRs.paramA, 0);
    queryItem = AUDIO_DDL_DESTROY_GRP;
    queInt.SetAudioDeadline(queryItem, -1, IpcQueryRs.rtgId, IpcQueryRs);
    EXPECT_EQ(IpcQueryRs.paramA, 0);
}

}  // namespace FFRT_TEST
}  // namespace OHOS
