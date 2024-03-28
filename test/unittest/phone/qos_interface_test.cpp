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

#include <cstring>
#include <sys/utsname.h>

#include "gtest/gtest.h"

#include "qos_interface.h"

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
    bool IsLinuxOs();
};

bool QosInterfaceTest::IsLinuxOs()
{
    struct utsname nameData;
    uname(&nameData);
    int cmpNum = 5;
    return strncmp(nameData.sysname, "Linux", cmpNum) == 0 ? true : false;
}

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
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: AuthEnableTest
 * @tc.desc: Test whether the OnRemoteRequest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthEnableTest, TestSize.Level1)
{
    unsigned int pid = getpid();
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_BACKGROUND);
    int ret = AuthEnable(pid, uaFlag, status);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: AuthSwitchTest
 * @tc.desc: Test whether the AuthSwitch interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthSwitchTest, TestSize.Level1)
{
    unsigned int pid = getpid();
    unsigned int rtgFlag = AF_RTG_ALL;
    unsigned int qosFlag = AF_QOS_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_BACKGROUND);
    AuthEnable(pid, rtgFlag, status);
    status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_FOREGROUND);
    int ret = AuthSwitch(pid, rtgFlag, qosFlag, status);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: AuthDeleteTest
 * @tc.desc: Test whether the AuthDelete interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthDeleteTest, TestSize.Level1)
{
    unsigned int pid = getpid();
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_BACKGROUND);
    AuthEnable(pid, uaFlag, status);
    int ret = AuthDelete(pid);
    EXPECT_EQ(ret, 0);
    AuthEnable(pid, uaFlag, status);
}

/**
 * @tc.name: AuthPauseTest
 * @tc.desc: Test whether the AuthPause interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthPauseTest, TestSize.Level1)
{
    unsigned int pid = getpid();
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_BACKGROUND);
    AuthEnable(pid, uaFlag, status);
    int ret = AuthPause(pid);
    EXPECT_EQ(ret, 0);
    AuthEnable(pid, uaFlag, status);
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
#if defined(ARM64_TEST) && ARM64_TEST
    EXPECT_EQ(ret, 0);
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
    unsigned int pid = getpid();
    unsigned int uaFlag1 = 0;
    unsigned int *uaFlag = &uaFlag1;
    unsigned int status1 = 0;
    unsigned int *status = &status1;
    int ret = AuthGet(pid);
    if (!IsLinuxOs()) {
        return;
    }
    EXPECT_GE(ret, 0);
    pid = -1;
    ret = AuthGet(pid);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: AuthEnhanceTest
 * @tc.desc: Test whether the AuthEnhance interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, AuthEnhanceTest, TestSize.Level1)
{
    unsigned int pid = getpid();
    bool enhanceStatus = false;
    int ret = AuthEnhance(pid, enhanceStatus);
    EXPECT_EQ(ret, 0);
    enhanceStatus = false;
    ret = AuthEnhance(pid, enhanceStatus);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: QosApplyForOtherTest
 * @tc.desc: Test whether the QosApplyForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyForOtherTest, TestSize.Level1)
{
    unsigned int level = 1;
    int tid = gettid();
    int ret = -1;
    ret = QosApplyForOther(level, tid);
#if defined(ARM64_TEST) && ARM64_TEST
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
#if defined(ARM64_TEST) && ARM64_TEST
    EXPECT_EQ(ret, 0);
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
    int tid = gettid();
    int level = 1;
    ret = QosApplyForOther(level, tid);
    ret = QosLeaveForOther(tid);
#if defined(ARM64_TEST) && ARM64_TEST
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

static struct QosPolicyDatas g_defaultQosPolicy = {
    .policyType = QOS_POLICY_DEFAULT,
    .policyFlag = QOS_FLAG_ALL,
    .policys = {
        {0, 0, 0, 1024, 0},
        {0, 0, 0, 1024, 0},
        {0, 0, 0, 1024, 0},
        {0, 0, 0, 1024, 0},
        {0, 0, 0, 1024, 0},
        {0, 0, 0, 1024, 0},
        {0, 0, 0, 1024, 0},
    }
};

HWTEST_F(QosInterfaceTest, QosPolicyTest, TestSize.Level1)
{
    int ret = -1;
    struct QosPolicyDatas *policyDatas = nullptr;
    ret = QosPolicySet(policyDatas);
    EXPECT_EQ(ret, -1);
#if defined(ARM64_TEST) && ARM64_TEST
    unsigned int pid = getpid();
    unsigned int rtgFlag = AF_RTG_ALL;
    unsigned int qosFlag = AF_QOS_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_FOREGROUND);
    ret = AuthSwitch(pid, rtgFlag, qosFlag, status);
    EXPECT_EQ(ret, 0);
    ret = QosPolicySet(&g_defaultQosPolicy);
    EXPECT_EQ(ret, 0);
#endif
}

/**
 * @tc.name: QosGetTest
 * @tc.desc: Test whether the QosGet interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetTest, TestSize.Level1)
{
    int qos;
    unsigned int level = 4;
    int ret = QosApply(level);
    EXPECT_EQ(ret, 0);
    ret = QosGet(qos);
    sleep(5);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);
}

/**
 * @tc.name: QosGetForOtherTest
 * @tc.desc: Test whether the QosGetForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetForOtherTest, TestSize.Level1)
{
    int qos;
    unsigned int level = 3;
    int tid = gettid();
    int ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);
    ret = QosGetForOther(tid, qos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);
}
}
}
}
