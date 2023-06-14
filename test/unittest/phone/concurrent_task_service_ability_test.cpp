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
#define private public
#include "concurrent_task_service_ability.h"
#undef private

namespace OHOS {
namespace FFRT_TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::ConcurrentTask;


class ConcurrentTaskServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConcurrentTaskServiceAbilityTest::SetUpTestCase()
{
}

void ConcurrentTaskServiceAbilityTest::TearDownTestCase()
{
}

void ConcurrentTaskServiceAbilityTest::SetUp()
{
}

void ConcurrentTaskServiceAbilityTest::TearDown()
{
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceAbilityTest, OnStartTest, TestSize.Level1)
{
    int32_t sysAbilityId = 8745;
    bool runOnCreate = true;
    ConcurrentTaskServiceAbility concurrenttaskserviceability = ConcurrentTaskServiceAbility(sysAbilityId, runOnCreate);
    concurrenttaskserviceability.OnStart();
    concurrenttaskserviceability.OnStart();
    concurrenttaskserviceability.OnStop();
}

/**
 * @tc.name: PushTaskTest
 * @tc.desc: Test whether the PushTask interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConcurrentTaskServiceAbilityTest, OnAddSystemAbilityTest, TestSize.Level1)
{
    int32_t sysAbilityId = 8745;
    bool runOnCreate = true;
    int32_t systemAbilityId = 6587;
    std::string deviceId = "test";
    ConcurrentTaskServiceAbility concurrenttaskserviceability = ConcurrentTaskServiceAbility(sysAbilityId, runOnCreate);
    concurrenttaskserviceability.OnStart();
    concurrenttaskserviceability.OnAddSystemAbility(systemAbilityId, deviceId);
    concurrenttaskserviceability.OnRemoveSystemAbility(systemAbilityId, deviceId);
    concurrenttaskserviceability.OnStop();
}
}
}