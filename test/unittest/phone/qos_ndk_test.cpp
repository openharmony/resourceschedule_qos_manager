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
 * @tc.name: QoSNdkTest
 * @tc.desc: Verify the Set and Reset QoSLevel function.
 * @tc.type: FUNC
 */
HWTEST_F(QoSNdkTest, SetThreadQoSNdkTest1, TestSize.Level1)
{
    int ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_BACKGROUND);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_UTILITY);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEFAULT);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INITIATED);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INTERACTIVE);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_SetThreadQoS(QoS_Level(-1));
    EXPECT_EQ(ret, -1);
    ret = OH_QoS_SetThreadQoS(QoS_Level(6));
    EXPECT_EQ(ret, -1);
    ret = OH_QoS_SetThreadQoS(QoS_Level(1024));
    EXPECT_EQ(ret, -1);
}

HWTEST_F(QoSNdkTest, ResetThreadQoSNdkTest, TestSize.Level1)
{
    int ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_BACKGROUND);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(ret, 0);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_UTILITY);
    EXPECT_EQ(ret, 0);
    ret =  OH_QoS_ResetThreadQoS();
    EXPECT_EQ(ret, 0);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEFAULT);
    EXPECT_EQ(ret, 0);
    ret =  OH_QoS_ResetThreadQoS();
    EXPECT_EQ(ret, 0);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INITIATED);
    EXPECT_EQ(ret, 0);
    ret =  OH_QoS_ResetThreadQoS();
    EXPECT_EQ(ret, 0);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(ret, 0);
    ret =  OH_QoS_ResetThreadQoS();
    EXPECT_EQ(ret, 0);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INTERACTIVE);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(QoSNdkTest, GetThreadQoSNdkTest1, TestSize.Level1)
{
    int ret = OH_QoS_GetThreadQoS(nullptr);
    EXPECT_EQ(ret, -1);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_BACKGROUND);
    EXPECT_EQ(ret, 0);
    enum QoS_Level level;
    ret = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(level, QoS_Level::QOS_BACKGROUND);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_UTILITY);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(level, QoS_Level::QOS_UTILITY);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEFAULT);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(level, QoS_Level::QOS_DEFAULT);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INITIATED);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(level, QoS_Level::QOS_USER_INITIATED);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(level, QoS_Level::QOS_DEADLINE_REQUEST);

    ret = OH_QoS_SetThreadQoS(QoS_Level::QOS_USER_INTERACTIVE);
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(level, QoS_Level::QOS_USER_INTERACTIVE);

    ret = OH_QoS_ResetThreadQoS();
    EXPECT_EQ(ret, 0);
    ret = OH_QoS_GetThreadQoS(&level);
    EXPECT_EQ(ret, -1);
}
} // QOS
} // OHOS