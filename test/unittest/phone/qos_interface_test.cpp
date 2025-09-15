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
    int val = EnableRtg(flag);
    EXPECT_EQ(val, 0);
}

/**
 * @tc.name: QosApplyTest
 * @tc.desc: Test whether the QosApply interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyTest1, TestSize.Level1)
{
    unsigned int level = 1;
    int val = -1;
    val = QosApply(level);
#if defined(ARM64_TEST) && ARM64_TEST
    EXPECT_EQ(val, 0);
#else
    (void)val;
#endif
}

/**
 * @tc.name: QosApplyFuncTest
 * @tc.desc: Test whether the QosApply interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyFuncTest0, TestSize.Level0)
{
    unsigned int level = 0;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyFuncTest1, TestSize.Level0)
{
    unsigned int level = 1;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyFuncTest2, TestSize.Level0)
{
    unsigned int level = 2;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyFuncTest3, TestSize.Level0)
{
    unsigned int level = 3;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyFuncTest4, TestSize.Level0)
{
    unsigned int level = 4;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyFuncTest5, TestSize.Level0)
{
    unsigned int level = 5;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyFuncTest6, TestSize.Level1)
{
    unsigned int level = 6;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
}


HWTEST_F(QosInterfaceTest, QosApplyFuncTestExt, TestSize.Level1)
{
    unsigned int level = 7;
    int val = QosApply(level);
    EXPECT_EQ(val, -1);

    level = 1024;
    val = QosApply(level);
    EXPECT_EQ(val, -1);

    level = -1;
    val = QosApply(level);
    EXPECT_EQ(val, -1);
}

/**
 * @tc.name: QosApplyForOtherTest
 * @tc.desc: Test whether the QosApplyForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyForOtherTest1, TestSize.Level1)
{
    unsigned int level = 1;
    int tid = gettid();
    int val = -1;
    val = QosApplyForOther(level, tid);
#if defined(ARM64_TEST) && ARM64_TEST
    EXPECT_EQ(val, 0);
#else
    (void)val;
#endif
}

/**
 * @tc.name: QosApplyForOtherFuncTest
 * @tc.desc: Test whether the QosApplyForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosApplyForOtherFuncTest0, TestSize.Level0)
{
    unsigned int level = 0;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyForOtherFuncTest1, TestSize.Level0)
{
    unsigned int level = 1;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyForOtherFuncTest2, TestSize.Level0)
{
    unsigned int level = 2;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyForOtherFuncTest3, TestSize.Level0)
{
    unsigned int level = 3;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyForOtherFuncTest4, TestSize.Level0)
{
    unsigned int level = 4;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyForOtherFuncTest5, TestSize.Level0)
{
    unsigned int level = 5;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyForOtherFuncTest6, TestSize.Level1)
{
    unsigned int level = 6;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosApplyForOtherFuncTestExt, TestSize.Level1)
{
    unsigned int level = 7;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, -1);

    level = 1024;
    val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, -1);

    level = -1;
    val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, -1);
}

/**
 * @tc.name: QosLeaveTest
 * @tc.desc: Test whether the QosLeave interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveTest, TestSize.Level1)
{
    int val = -1;
    val = QosLeave();
#if defined(ARM64_TEST) && ARM64_TEST
    EXPECT_EQ(val, 0);
#else
    (void)val;
#endif
}

/**
 * @tc.name: QosLeaveFuncTest
 * @tc.desc: Test whether the QosLeave interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveFuncTestExt0, TestSize.Level0)
{
    int level = 0;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosLeave();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveFuncTestExt1, TestSize.Level0)
{
    int level = 1;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosLeave();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveFuncTestExt2, TestSize.Level0)
{
    int level = 2;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosLeave();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveFuncTestExt3, TestSize.Level0)
{
    int level = 3;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosLeave();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveFuncTestExt4, TestSize.Level0)
{
    int level = 4;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosLeave();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveFuncTestExt5, TestSize.Level0)
{
    int level = 5;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosLeave();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveFuncTestExt6, TestSize.Level1)
{
    int level = 6;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosLeave();
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveFuncTestExt, TestSize.Level1)
{
    int val = -1;
    val = QosApply(7);
    EXPECT_EQ(val, -1);
    val = QosLeave();
    EXPECT_EQ(val, -1);

    val = QosApply(1024);
    EXPECT_EQ(val, -1);
    val = QosLeave();
    EXPECT_EQ(val, -1);
 
    val = QosApply(-1);
    EXPECT_EQ(val, -1);
    val = QosLeave();
    EXPECT_EQ(val, -1);
}

/**
 * @tc.name: QosLeaveForOtherTest
 * @tc.desc: Test whether the QosLeaveForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveForOtherTest, TestSize.Level1)
{
    int val = -1;
    int tid = gettid();
    int level = 1;
    val = QosApplyForOther(level, tid);
    val = QosLeaveForOther(tid);
#if defined(ARM64_TEST) && ARM64_TEST
    EXPECT_EQ(val, 0);
#else
    (void)val;
#endif
}

/**
 * @tc.name: QosLeaveForOtherFuncTest
 * @tc.desc: Test whether the QosLeaveForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosLeaveForOtherFuncTest0, TestSize.Level0)
{
    int level = 0;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveForOtherFuncTest1, TestSize.Level0)
{
    int level = 1;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveForOtherFuncTest2, TestSize.Level0)
{
    int level = 2;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveForOtherFuncTest3, TestSize.Level0)
{
    int level = 3;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveForOtherFuncTest4, TestSize.Level0)
{
    int level = 4;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveForOtherFuncTest5, TestSize.Level0)
{
    int level = 5;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveForOtherFuncTest6, TestSize.Level1)
{
    int level = 6;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, 0);
}

HWTEST_F(QosInterfaceTest, QosLeaveForOtherFuncTest, TestSize.Level1)
{
    int level = 7;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, -1);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, -1);

    level = 1024;
    tid = gettid();
    val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, -1);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, -1);
 
    level = -1;
    tid = gettid();
    val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, -1);
    val = QosLeaveForOther(tid);
    EXPECT_EQ(val, -1);
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
    int val = -1;
    struct QosPolicyDatas *policyDatas = nullptr;
    val = QosPolicySet(policyDatas);
    EXPECT_EQ(val, -1);
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
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosGet(qos);
    sleep(5);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

/**
 * @tc.name: QosGetFuncTest
 * @tc.desc: Test whether the QosGet interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetFuncTest0, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 0;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosGet(qos);
    sleep(1);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetFuncTest1, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 1;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosGet(qos);
    sleep(1);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetFuncTest2, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 2;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosGet(qos);
    sleep(1);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetFuncTest3, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 3;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosGet(qos);
    sleep(1);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetFuncTest4, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 4;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosGet(qos);
    sleep(1);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetFuncTest5, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 5;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosGet(qos);
    sleep(1);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetFuncTest6, TestSize.Level1)
{
    int qos = -1;
    unsigned int level = 6;
    int val = QosApply(level);
    EXPECT_EQ(val, 0);
    val = QosGet(qos);
    sleep(1);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

/**
 * @tc.name: QosGetForOtherFuncTest
 * @tc.desc: Test whether the QosGetForOther interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(QosInterfaceTest, QosGetForOtherTest0, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 0;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    sleep(1);
    val = QosGetForOther(tid, qos);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetForOtherTest1, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 1;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    sleep(1);
    val = QosGetForOther(tid, qos);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetForOtherTest2, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 2;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    sleep(1);
    val = QosGetForOther(tid, qos);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetForOtherTest3, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 3;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    sleep(1);
    val = QosGetForOther(tid, qos);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetForOtherTest4, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 4;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    sleep(1);
    val = QosGetForOther(tid, qos);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetForOtherTest5, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 5;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    sleep(1);
    val = QosGetForOther(tid, qos);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}

HWTEST_F(QosInterfaceTest, QosGetForOtherTest6, TestSize.Level0)
{
    int qos = -1;
    unsigned int level = 6;
    int tid = gettid();
    int val = QosApplyForOther(level, tid);
    EXPECT_EQ(val, 0);
    sleep(1);
    val = QosGetForOther(tid, qos);
    EXPECT_EQ(val, 0);
    EXPECT_EQ(qos, level);
}
}
}
}
