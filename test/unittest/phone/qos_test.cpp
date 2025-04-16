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
 * @tc.name: SetThreadQosTest
 * @tc.desc: Verify the Set QosLevel function.
 * @tc.type: FUNC
 */
HWTEST_F(QosTest, SetThreadQosTest0, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_BACKGROUND);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetThreadQosTest1, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_UTILITY);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetThreadQosTest2, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_DEFAULT);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetThreadQosTest3, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_USER_INITIATED);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetThreadQosTest4, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetThreadQosTest5, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_USER_INTERACTIVE);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetThreadQosTest6, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_KEY_BACKGROUND);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetThreadQosTest7, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_MAX);
    EXPECT_EQ(val, -1);
}

HWTEST_F(QosTest, SetThreadQosTestExt, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel(-1));
    EXPECT_EQ(val, -1);
    val = SetThreadQos(QosLevel(6));
    EXPECT_EQ(val, 0);
    val = SetThreadQos(QosLevel(1024));
    EXPECT_EQ(val, -1);
}

/**
 * @tc.name: SetQosForOtherThreadTest
 * @tc.desc: Verify the Set QosLevel For Other function.
 * @tc.type: FUNC
 */
HWTEST_F(QosTest, SetQosForOtherThreadTest0, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel::QOS_BACKGROUND, gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetQosForOtherThreadTest1, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel::QOS_UTILITY, gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetQosForOtherThreadTest2, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel::QOS_DEFAULT, gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetQosForOtherThreadTest3, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel::QOS_USER_INITIATED, gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetQosForOtherThreadTest4, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel::QOS_DEADLINE_REQUEST, gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetQosForOtherThreadTest5, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel::QOS_USER_INTERACTIVE, gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetQosForOtherThreadTest6, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_KEY_BACKGROUND, gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, SetQosForOtherThreadTest7, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_MAX, gettid());
    EXPECT_EQ(val, -1);
}

HWTEST_F(QosTest, SetQosForOtherThreadTestExt, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel(-1), gettid());
    EXPECT_EQ(val, -1);
    val = SetQosForOtherThread(QosLevel(6), gettid());
    EXPECT_EQ(val, 0);
    val = SetQosForOtherThread(QosLevel(1024), gettid());
    EXPECT_EQ(val, -1);
}

/**
 * @tc.name: ResetThreadQosTest
 * @tc.desc: Verify the Reset QosLevel function.
 * @tc.type: FUNC
 */
HWTEST_F(QosTest, ResetThreadQosTest0, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_BACKGROUND);
    EXPECT_EQ(val, 0);
    val = ResetThreadQos();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest1, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_UTILITY);
    EXPECT_EQ(val, 0);
    val = ResetThreadQos();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest2, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_DEFAULT);
    EXPECT_EQ(val, 0);
    val = ResetThreadQos();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest3, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_USER_INITIATED);
    EXPECT_EQ(val, 0);
    val = ResetThreadQos();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest4, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(val, 0);
    val = ResetThreadQos();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest5, TestSize.Level0)
{
    int val = SetThreadQos(QosLevel::QOS_USER_INTERACTIVE);
    EXPECT_EQ(val, 0);
    val = ResetThreadQos();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest6, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_KEY_BACKGROUND);
    EXPECT_EQ(val, 0);
    val = ResetThreadQos();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetThreadQosTest7, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_MAX);
    EXPECT_EQ(val, -1);
    val = ResetThreadQos();
    EXPECT_EQ(val, -1);
}

HWTEST_F(QosTest, ResetThreadQosTestExt, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel(6));
    EXPECT_EQ(val, 0);
    val = ResetThreadQos();
    EXPECT_EQ(val, 0);

    val = SetThreadQos(QosLevel(-1));
    EXPECT_EQ(val, -1);
    val = ResetThreadQos();
    EXPECT_EQ(val, -1);
 
    val = SetThreadQos(QosLevel(1024));
    EXPECT_EQ(val, -1);
    val = ResetThreadQos();
    EXPECT_EQ(val, -1);
}

/**
 * @tc.name: ResetQosForOtherThreadTest
 * @tc.desc: Verify the Reset QosLevel For Other function.
 * @tc.type: FUNC
 */
HWTEST_F(QosTest, ResetQosForOtherThreadTest0, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_BACKGROUND, gettid());
    EXPECT_EQ(val, 0);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetQosForOtherThreadTest1, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_UTILITY, gettid());
    EXPECT_EQ(val, 0);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetQosForOtherThreadTest2, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_DEFAULT, gettid());
    EXPECT_EQ(val, 0);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetQosForOtherThreadTest3, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_USER_INITIATED, gettid());
    EXPECT_EQ(val, 0);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetQosForOtherThreadTest4, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_DEADLINE_REQUEST, gettid());
    EXPECT_EQ(val, 0);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetQosForOtherThreadTest5, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_USER_INTERACTIVE, gettid());
    EXPECT_EQ(val, 0);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetQosForOtherThreadTest6, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel::QOS_KEY_BACKGROUND, gettid());
    EXPECT_EQ(val, 0);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosTest, ResetQosForOtherThreadTest7, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel::QOS_MAX, gettid());
    EXPECT_EQ(val, -1);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, -1);
}

HWTEST_F(QosTest, ResetQosForOtherThreadTestExt, TestSize.Level0)
{
    int val = SetQosForOtherThread(QosLevel(6), gettid());
    EXPECT_EQ(val, 0);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, 0);

    val = SetQosForOtherThread(QosLevel(-1), gettid());
    EXPECT_EQ(val, -1);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, -1);
 
    val = SetQosForOtherThread(QosLevel(1024), gettid());
    EXPECT_EQ(val, -1);
    val = ResetQosForOtherThread(gettid());
    EXPECT_EQ(val, -1);
}

/**
 * @tc.name: GetThreadQosTest
 * @tc.desc: Verify the Get QosLevel function.
 * @tc.type: FUNC
 */
HWTEST_F(QosTest, GetThreadQosTest0, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_BACKGROUND);
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetThreadQos(level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_BACKGROUND));
}

HWTEST_F(QosTest, GetThreadQosTest1, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_UTILITY);
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetThreadQos(level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_UTILITY));
}

HWTEST_F(QosTest, GetThreadQosTest2, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_DEFAULT);
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetThreadQos(level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_DEFAULT));
}

HWTEST_F(QosTest, GetThreadQosTest3, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_USER_INITIATED);
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetThreadQos(level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_USER_INITIATED));
}

HWTEST_F(QosTest, GetThreadQosTest4, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_DEADLINE_REQUEST);
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetThreadQos(level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_DEADLINE_REQUEST));
}

HWTEST_F(QosTest, GetThreadQosTest5, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_USER_INTERACTIVE);
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetThreadQos(level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_USER_INTERACTIVE));
}

HWTEST_F(QosTest, GetThreadQosTest6, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_KEY_BACKGROUND);
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetThreadQos(level);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_KEY_BACKGROUND));
}

HWTEST_F(QosTest, GetThreadQosTestExt, TestSize.Level1)
{
    int val = SetThreadQos(QosLevel::QOS_MAX);
    EXPECT_NE(val, 0);
    enum QosLevel level2;
    val = GetThreadQos(level2);
    EXPECT_EQ(val, 0);
    EXPECT_NE(static_cast<unsigned int>(level2), static_cast<unsigned int>(QosLevel::QOS_MAX));
 
    val = SetThreadQos((QosLevel)-1);
    EXPECT_NE(val, 0);
    enum QosLevel level3;
    val = GetThreadQos(level3);
    EXPECT_EQ(val, 0);
    EXPECT_NE(static_cast<unsigned int>(level3), static_cast<unsigned int>((QosLevel)-1));
 
    val = SetThreadQos((QosLevel)1024);
    EXPECT_NE(val, 0);
    enum QosLevel level4;
    val = GetThreadQos(level4);
    EXPECT_EQ(val, 0);
    EXPECT_NE(static_cast<unsigned int>(level4), static_cast<unsigned int>((QosLevel)1024));
}

/**
 * @tc.name: GetQosForOtherThread
 * @tc.desc: Verify the Get QosLevel For Other function.
 * @tc.type: FUNC
 */
HWTEST_F(QosTest, GetQosForOtherThreadTest0, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_BACKGROUND, gettid());
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetQosForOtherThread(level, gettid());
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_BACKGROUND));
}

HWTEST_F(QosTest, GetQosForOtherThreadTest1, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_UTILITY, gettid());
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetQosForOtherThread(level, gettid());
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_UTILITY));
}

HWTEST_F(QosTest, GetQosForOtherThreadTest2, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_DEFAULT, gettid());
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetQosForOtherThread(level, gettid());
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_DEFAULT));
}

HWTEST_F(QosTest, GetQosForOtherThreadTest3, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_USER_INITIATED, gettid());
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetQosForOtherThread(level, gettid());
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_USER_INITIATED));
}

HWTEST_F(QosTest, GetQosForOtherThreadTest4, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_DEADLINE_REQUEST, gettid());
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetQosForOtherThread(level, gettid());
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_DEADLINE_REQUEST));
}

HWTEST_F(QosTest, GetQosForOtherThreadTest5, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_USER_INTERACTIVE, gettid());
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetQosForOtherThread(level, gettid());
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_USER_INTERACTIVE));
}

HWTEST_F(QosTest, GetQosForOtherThreadTest6, TestSize.Level1)
{
    int val = SetQosForOtherThread(QosLevel::QOS_KEY_BACKGROUND, gettid());
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetQosForOtherThread(level, gettid());
    EXPECT_EQ(val, 0);
    EXPECT_EQ(static_cast<unsigned int>(level), static_cast<unsigned int>(QosLevel::QOS_KEY_BACKGROUND));
}

HWTEST_F(QosTest, GetQosForOtherThreadTestExt, TestSize.Level1)
{
    int val = ResetThreadQos();
    EXPECT_EQ(val, 0);
    enum QosLevel level;
    val = GetThreadQos(level);
    EXPECT_EQ(val, -1);
}
} // QOS
} // OHOS