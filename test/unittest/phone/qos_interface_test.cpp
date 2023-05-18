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

#include "../include/qos_interface.h"

namespace OHOS {
namespace FFRT_TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::FFRT_TEST;
using namespace std;


class QosInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void QosInterfaceTest::SetUpTestCase()
{
}

void QosInterfaceTest::TearDownTestCase()
{
}

void QosInterfaceTest::SetUp()
{
}

void QosInterfaceTest::TearDown()
{
}

extern "C" {
/**
 * @tc.name: EnableRtgTest
 * @tc.desc: Test whether the OnRemoteRequest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, EnableRtgTest, TestSize.Level1)
{
    bool flag = true;
    int ret = EnableRtg(flag);
#if TDD_MUSL
    EXPECT_EQ(ret, 0);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: AuthEnableTest
 * @tc.desc: Test whether the OnRemoteRequest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthEnableTest, TestSize.Level1)
{
    unsigned int uid = 1;
    unsigned int uaFlag = 1;
    unsigned int status = 1;
    int ret = AuthEnable(uid, uaFlag, status);
#if TDD_MUSL
    EXPECT_EQ(ret, 0);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: AuthSwitchTest
 * @tc.desc: Test whether the AuthSwitch interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthSwitchTest, TestSize.Level1)
{
    unsigned int uid = 1;
    unsigned int rtgFlag = 1;
    unsigned int qosFlag = 1;
    unsigned int status = 1;
    int ret = AuthSwitch(uid, rtgFlag, qosFlag, status);
#if TDD_MUSL
    EXPECT_EQ(ret, 0);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: AuthDeleteTest
 * @tc.desc: Test whether the AuthDelete interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthDeleteTest, TestSize.Level1)
{
    unsigned int uid = 1;
    int ret = AuthDelete(uid);
#if TDD_MUSL
    EXPECT_EQ(ret, 0);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: AuthPauseTest
 * @tc.desc: Test whether the AuthPause interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthPauseTest, TestSize.Level1)
{
    unsigned int uid = 1;
    int ret = -1;
    ret = AuthPause(uid);
#if TDD_MUSL
    EXPECT_EQ(ret, -1);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: QosApplyTest
 * @tc.desc: Test whether the QosApply interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyTest, TestSize.Level1)
{
    unsigned int level = 1;
    int ret = -1;
    ret = QosApply(level);
#if TDD_MUSL
    EXPECT_EQ(ret, -1);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: AuthGetTest
 * @tc.desc: Test whether the AuthGet interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthGetTest, TestSize.Level1)
{
    unsigned int uid = 1000;
    unsigned int uaFlag1 = 0;
    unsigned int *uaFlag = &uaFlag1;
    unsigned int status1 = 0;
    unsigned int *status = &status1;
    int ret = AuthGet(uid, uaFlag, status);
#if TDD_MUSL
    EXPECT_GE(ret, 0);
#endif
    uid = -1;
    ret = AuthGet(uid, uaFlag, status);
#if TDD_MUSL
    EXPECT_EQ(ret, -1);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: QosApplyForOtherTest
 * @tc.desc: Test whether the QosApplyForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyForOtherTest, TestSize.Level1)
{
    unsigned int level = 1;
    int tid = 1;
    int ret = -1;
    ret = QosApplyForOther(level, tid);
#if TDD_MUSL
    EXPECT_EQ(ret, 0);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: QosLeaveTest
 * @tc.desc: Test whether the QosLeave interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveTest, TestSize.Level1)
{
    int ret = -1;
    ret = QosLeave();
#if TDD_MUSL
    EXPECT_EQ(ret, -1);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: QosLeaveForOtherTest
 * @tc.desc: Test whether the QosLeaveForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveForOtherTest, TestSize.Level1)
{
    int ret = -1;
    int tid = 1;
    ret = QosLeaveForOther(tid);
#if TDD_MUSL
    EXPECT_EQ(ret, 0);
#else
    (void)ret;
#endif
}

/**
 * @tc.name: QosPolicyTest
 * @tc.desc: Test whether the QosPolicy interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosPolicyTest, TestSize.Level1)
{
    int ret = -1;
    struct QosPolicyDatas *policyDatas = nullptr;
    ret = QosPolicy(policyDatas);
#if TDD_MUSL
    EXPECT_EQ(ret, -1);
#else
    (void)ret;
#endif
}
}
}
}