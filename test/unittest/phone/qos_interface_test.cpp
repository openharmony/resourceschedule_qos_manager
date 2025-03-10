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
 * @tc.name: QosApplyTest1
 * @tc.desc: Test whether the QosApply interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyTest1, TestSize.Level1)
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
 * @tc.name: QosApplyTest2
 * @tc.desc: Test whether the QosApply interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyTest2, TestSize.Level1)
{
    unsigned int level = 0;
    int ret = -1;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);

    level = 1;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);

    level = 2;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);

    level = 3;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);

    level = 4;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);

    level = 5;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);

    level = 6;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);

    level = 7;
    ret = QosApply(level);
    EXPECT_EQ(ret, -1);

    level = 1024;
    ret = QosApply(level);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: QosApplyForOtherTest1
 * @tc.desc: Test whether the QosApplyForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyForOtherTest1, TestSize.Level1)
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
 * @tc.name: QosApplyForOtherTest2
 * @tc.desc: Test whether the QosApplyForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyForOtherTest2, TestSize.Level1)
{
    unsigned int level = 0;
    int tid = gettid();
    int ret = -1;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);

    level = 1;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);

    level = 2;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);

    level = 3;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);

    level = 4;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);

    level = 5;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);

    level = 6;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);

    level = 7;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, -1);

    level = 1024;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: QosLeaveTest1
 * @tc.desc: Test whether the QosLeave interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveTest1, TestSize.Level1)
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
 * @tc.name: QosLeaveTest2
 * @tc.desc: Test whether the QosLeave interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveTest2, TestSize.Level1)
{
    int ret = -1;
    ret = QosApply(0);
    EXPECT_EQ(ret, 0);
    ret = QosLeave();
    EXPECT_EQ(ret, 0);

    ret = QosApply(1);
    EXPECT_EQ(ret, 0);
    ret = QosLeave();
    EXPECT_EQ(ret, 0);

    ret = QosApply(2);
    EXPECT_EQ(ret, 0);
    ret = QosLeave();
    EXPECT_EQ(ret, 0);

    ret = QosApply(3);
    EXPECT_EQ(ret, 0);
    ret = QosLeave();
    EXPECT_EQ(ret, 0);

    ret = QosApply(4);
    EXPECT_EQ(ret, 0);
    ret = QosLeave();
    EXPECT_EQ(ret, 0);

    ret = QosApply(5);
    EXPECT_EQ(ret, 0);
    ret = QosLeave();
    EXPECT_EQ(ret, 0);

    ret = QosApply(6);
    EXPECT_EQ(ret, 0);
    ret = QosLeave();
    EXPECT_EQ(ret, 0);

    ret = QosApply(7);
    EXPECT_EQ(ret, -1);
    ret = QosLeave();
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: QosLeaveForOtherTest1
 * @tc.desc: Test whether the QosLeaveForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveForOtherTest1, TestSize.Level1)
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
 * @tc.name: QosLeaveForOtherTest2
 * @tc.desc: Test whether the QosLeaveForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveForOtherTest2, TestSize.Level1)
{
    int ret = -1;
    int tid = gettid();
    ret = QosApplyForOther(0, tid);
    EXPECT_EQ(ret, 0);
    ret = QosLeaveForOther(tid);
    EXPECT_EQ(ret, 0);

    ret = QosApplyForOther(1, tid);
    EXPECT_EQ(ret, 0);
    ret = QosLeaveForOther(tid);
    EXPECT_EQ(ret, 0);

    ret = QosApplyForOther(2, tid);
    EXPECT_EQ(ret, 0);
    ret = QosLeaveForOther(tid);
    EXPECT_EQ(ret, 0);

    ret = QosApplyForOther(3, tid);
    EXPECT_EQ(ret, 0);
    ret = QosLeaveForOther(tid);
    EXPECT_EQ(ret, 0);

    ret = QosApplyForOther(4, tid);
    EXPECT_EQ(ret, 0);
    ret = QosLeaveForOther(tid);
    EXPECT_EQ(ret, 0);

    ret = QosApplyForOther(5, tid);
    EXPECT_EQ(ret, 0);
    ret = QosLeaveForOther(tid);
    EXPECT_EQ(ret, 0);

    ret = QosApplyForOther(6, tid);
    EXPECT_EQ(ret, 0);
    ret = QosLeaveForOther(tid);
    EXPECT_EQ(ret, 0);

    ret = QosApplyForOther(7, tid);
    EXPECT_EQ(ret, -1);
    ret = QosLeaveForOther(tid);
    EXPECT_EQ(ret, -1);
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
}

/**
 * @tc.name: QosGetTest1
 * @tc.desc: Test whether the QosGet interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetTest1, TestSize.Level1)
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
 * @tc.name: QosGetTest2
 * @tc.desc: Test whether the QosGet interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetTest2, TestSize.Level1)
{
    int qos;
    unsigned int level = 0;
    int ret = QosApply(level);
    EXPECT_EQ(ret, 0);
    ret = QosGet(qos);
    sleep(1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 1;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);
    ret = QosGet(qos);
    sleep(1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 2;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);
    ret = QosGet(qos);
    sleep(1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 3;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);
    ret = QosGet(qos);
    sleep(1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);
}

/**
 * @tc.name: QosGetTest3
 * @tc.desc: Test whether the QosGet interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetTest3, TestSize.Level1)
{
    int qos;
    unsigned int level = 4;
    int ret = QosApply(level);
    EXPECT_EQ(ret, 0);
    ret = QosGet(qos);
    sleep(1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 5;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);
    ret = QosGet(qos);
    sleep(1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 6;
    ret = QosApply(level);
    EXPECT_EQ(ret, 0);
    ret = QosGet(qos);
    sleep(1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);
}

/**
 * @tc.name: QosGetForOtherTest1
 * @tc.desc: Test whether the QosGetForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetForOtherTest1, TestSize.Level1)
{
    int qos;
    unsigned int level = 0;
    int tid = gettid();
    int ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);
    sleep(1);
    ret = QosGetForOther(tid, qos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 1;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);
    sleep(1);
    ret = QosGetForOther(tid, qos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 2;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);
    sleep(1);
    ret = QosGetForOther(tid, qos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 3;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);
    sleep(1);
    ret = QosGetForOther(tid, qos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);
}

/**
 * @tc.name: QosGetForOtherTest2
 * @tc.desc: Test whether the QosGetForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetForOtherTest2, TestSize.Level1)
{
    int qos;
    unsigned int level = 4;
    int tid = gettid();
    int ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);
    sleep(1);
    ret = QosGetForOther(tid, qos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 5;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);
    sleep(1);
    ret = QosGetForOther(tid, qos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);

    level = 6;
    ret = QosApplyForOther(level, tid);
    EXPECT_EQ(ret, 0);
    sleep(1);
    ret = QosGetForOther(tid, qos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(qos, level);
}
}
}
}
