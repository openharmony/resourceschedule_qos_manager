/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <unistd.h>
#include "gtest/gtest.h"
#include "c/qos.h"

namespace OHOS {
namespace QOS {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::QOS;

class QoSNdkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void QoSNdkTest::SetUpTestCase()
{
}

void QoSNdkTest::TearDownTestCase()
{
}

void QoSNdkTest::SetUp()
{
}

void QoSNdkTest::TearDown()
{
}

/**
 * @tc.name: SetThreadQoSNdkTest
 * @tc.desc: Verify the Set QoSLevel function.
 * @tc.type: FUNC
 */
HWTEST_F(QoSNdkTest, SetThreadQoSNdkTest0, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_BACKGROUND);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, SetThreadQoSNdkTest1, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_UTILITY);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, SetThreadQoSNdkTest2, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEFAULT);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, SetThreadQoSNdkTest3, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INITIATED);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, SetThreadQoSNdkTest4, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, SetThreadQoSNdkTest5, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INTERACTIVE);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, SetThreadQoSNdkTestExt, TestSize.Level1)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level(-1));
    EXPECT_EQ(val, -1);
    val = OH_QoS_SetThreadQoS(QoS_Level(6));
    EXPECT_EQ(val, -1);
    val = OH_QoS_SetThreadQoS(QoS_Level(1024));
    EXPECT_EQ(val, -1);
}

/**
 * @tc.name: ResetThreadQoSNdkTest
 * @tc.desc: Verify the Reset QoSLevel function.
 * @tc.type: FUNC
 */
HWTEST_F(QoSNdkTest, ResetThreadQoSNdkTest0, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_BACKGROUND);
    EXPECT_EQ(val, 0);
    val = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, ResetThreadQoSNdkTest1, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_UTILITY);
    EXPECT_EQ(val, 0);
    val = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, ResetThreadQoSNdkTest2, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEFAULT);
    EXPECT_EQ(val, 0);
    val = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, ResetThreadQoSNdkTest3, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INITIATED);
    EXPECT_EQ(val, 0);
    val = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, ResetThreadQoSNdkTest4, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(val, 0);
    val = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QoSNdkTest, ResetThreadQoSNdkTest5, TestSize.Level0)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INTERACTIVE);
    EXPECT_EQ(val, 0);
    val = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(val, 0);
}

/**
 * @tc.name: GetThreadQoSNdkTest
 * @tc.desc: Verify the Get QoSLevel function.
 * @tc.type: FUNC
 */
HWTEST_F(QoSNdkTest, GetThreadQoSNdkTest0, TestSize.Level1)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_BACKGROUND);
    EXPECT_EQ(val, 0);
    enum QoS_Level level;
    val = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(level, QoS_Level::QOS_BACKGROUND);
}

HWTEST_F(QoSNdkTest, GetThreadQoSNdkTest1, TestSize.Level1)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_UTILITY);
    EXPECT_EQ(val, 0);
    enum QoS_Level level;
    val = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(level, QoS_Level::QOS_UTILITY);
}

HWTEST_F(QoSNdkTest, GetThreadQoSNdkTest2, TestSize.Level1)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEFAULT);
    EXPECT_EQ(val, 0);
    enum QoS_Level level;
    val = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(level, QoS_Level::QOS_DEFAULT);
}

HWTEST_F(QoSNdkTest, GetThreadQoSNdkTest3, TestSize.Level1)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INITIATED);
    EXPECT_EQ(val, 0);
    enum QoS_Level level;
    val = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(level, QoS_Level::QOS_USER_INITIATED);
}

HWTEST_F(QoSNdkTest, GetThreadQoSNdkTest4, TestSize.Level1)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(val, 0);
    enum QoS_Level level;
    val = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(level, QoS_Level::QOS_DEADLINE_REQUEST);
}

HWTEST_F(QoSNdkTest, GetThreadQoSNdkTest5, TestSize.Level1)
{
    int val = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INTERACTIVE);
    EXPECT_EQ(val, 0);
    enum QoS_Level level;
    val = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(level, QoS_Level::QOS_USER_INTERACTIVE);
}

HWTEST_F(QoSNdkTest, GetThreadQoSNdkTestExt, TestSize.Level1)
{
    int val = OH_QoS_GetThreadQoS(nullptr);
    EXPECT_EQ(val, -1);
    enum QoS_Level level;

    val = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(val, 0);
    val = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(val, -1);
}
} // QOS
} // OHOS