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
#include "qos_manager.h"

namespace OHOS {
namespace FFRT_TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::FFRT_TEST;
using namespace ConcurrentTask;
using namespace std;


class QosManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void QosManagerTest::SetUpTestCase()
{
}

void QosManagerTest::TearDownTestCase()
{
}

void QosManagerTest::SetUp()
{
}

void QosManagerTest::TearDown()
{
}

/**
 * @tc.name: DecDepRefTest
 * @tc.desc: Confirm the test binary can execute in root priv.
 * @tc.type: FUNC
 */
HWTEST_F(QosManagerTest, TaskHandleTest, TestSize.Level1)
{
    QosManager qosManager;
    qosManager.Init();
}
}
}