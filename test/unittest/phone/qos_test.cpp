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

#include <cstdio>
#include <unistd.h>
#include "gtest/gtest.h"
#include "qos.h"

namespace OHOS {
namespace QOS {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::QOS;

class QosTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void QosTest::SetUpTestCase()
{
}

void QosTest::TearDownTestCase()
{
}

void QosTest::SetUp()
{
}

void QosTest::TearDown()
{
}

/**
 * @tc.name: QosTest
 * @tc.desc: Verify the Set and Reset QosLevel function.
 * @tc.type: FUNC
 */
HWTEST_F(QosTest, SetThreadQosTest1, TestSize.Level1)
{
    int ret = SetThreadQos(QosLevel::QOS_USER_INITIATED);
    EXPECT_EQ(ret, 0);
    ret = SetThreadQos(QosLevel::QOS_DEFAULT);
    EXPECT_EQ(ret, 0);
    ret = SetThreadQos(QosLevel::QOS_UTILITY);
    EXPECT_EQ(ret, 0);
    ret = SetThreadQos(QosLevel::QOS_BACKGROUND);
    EXPECT_EQ(ret, 0);
    ret = SetThreadQos(QosLevel::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(ret, 0);
    ret = SetThreadQos(QosLevel::QOS_USER_INTERACTIVE);
    EXPECT_EQ(ret, 0);
    ret = SetThreadQos(QosLevel::QOS_KEY_BACKGROUND);
    EXPECT_EQ(ret, 0);
    ret = SetThreadQos(QosLevel::QOS_MAX);
    EXPECT_EQ(ret, -1);
    ret = SetThreadQos(QosLevel(-1));
    EXPECT_EQ(ret, -1);
}

HWTEST_F(QosTest, SetThreadQosTest2, TestSize.Level1)
{
    int ret = SetQosForOtherThread(QosLevel::QOS_USER_INITIATED, gettid());
    EXPECT_EQ(ret, 0);
    ret = SetQosForOtherThread(QosLevel::QOS_DEFAULT, gettid());
    EXPECT_EQ(ret, 0);
    ret = SetQosForOtherThread(QosLevel::QOS_UTILITY, gettid());
    EXPECT_EQ(ret, 0);
    ret = SetQosForOtherThread(QosLevel::QOS_BACKGROUND, gettid());
    EXPECT_EQ(ret, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest1, TestSize.Level1)
{
    int ret = SetThreadQos(QosLevel::QOS_USER_INITIATED);
    EXPECT_EQ(ret, 0);
    ret = ResetThreadQos();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest2, TestSize.Level1)
{
    int ret = SetQosForOtherThread(QosLevel::QOS_USER_INITIATED, gettid());
    EXPECT_EQ(ret, 0);
    ret = ResetQosForOtherThread(gettid());
    EXPECT_EQ(ret, 0);
}

HWTEST_F(QosTest, GetThreadQosTest1, TestSize.Level1)
{
    int ret = SetThreadQos(QosLevel::QOS_USER_INITIATED);
    EXPECT_EQ(ret, 0);
    enum QosLevel level;
    ret = GetThreadQos(level);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_USER_INITIATED));
    ret = SetThreadQos(QosLevel::QOS_USER_INTERACTIVE);
    EXPECT_EQ(ret, 0);
    ret = GetThreadQos(level);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_USER_INTERACTIVE));
}

HWTEST_F(QosTest, GetThreadQosTest2, TestSize.Level1)
{
    int ret = ResetThreadQos();
    EXPECT_EQ(ret, 0);
    enum QosLevel level;
    ret = GetThreadQos(level);
    EXPECT_EQ(ret, -1);
}
} // QOS
} // OHOS