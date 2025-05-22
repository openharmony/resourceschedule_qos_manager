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

#include <cinttypes>
#include <sys/resource.h>
#include <sched.h>
#include <linux/sched.h>
#include "gtest/gtest.h"
#define private public
#include "func_loader.h"
#include "concurrent_task_controller_interface.h"
#include "rtg_interface.h"
#include "ipc_skeleton.h"
#include "concurrent_task_log.h"
#undef private

namespace OHOS {
namespace FFRT_TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::ConcurrentTask;
using namespace std;

class FuncLoaderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FuncLoaderTest::SetUpTestCase() {}

void FuncLoaderTest::TearDownTestCase() {}

void FuncLoaderTest::SetUp() {}

void FuncLoaderTest::TearDown() {}

/**
 * @tc.name: LoadFileTest
 * @tc.desc: Test whether the ReportDataTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(FuncLoaderTest, LoadFileTest, TestSize.Level1)
{
    FuncLoader funcLoader("111");
    funcLoader.LoadFile("222");
    EXPECT_FALSE(funcLoader.enable_);
}

/**
 * @tc.name: LoadSymbolTest
 * @tc.desc: Test whether the ReportDataTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(FuncLoaderTest, LoadSymbolTest, TestSize.Level1)
{
    FuncLoader funcLoader("/lib/libconcurrent_task_client.z.so");

    funcLoader.LoadSymbol("Init");
    funcLoader.LoadSymbol("Release");
    funcLoader.LoadSymbol("ReportData");
    funcLoader.LoadSymbol("ReportSceneInfo");
    funcLoader.LoadSymbol("QueryInterval");
    funcLoader.LoadSymbol("QueryDeadline");
    funcLoader.LoadSymbol("SetAudioDeadline");
    void* funcSym = funcLoader.LoadSymbol("RequestAuth");
    EXPECT_TRUE(funcSym == nullptr);
}

/**
 * @tc.name: GetLoadSuccessTest
 * @tc.desc: Test whether the ReportDataTest interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(FuncLoaderTest, GetLoadSuccessTest, TestSize.Level1)
{
    FuncLoader funcLoader("/lib/libconcurrent_task_client.z.so");
    bool ret = funcLoader.GetLoadSuccess();
    if (ret) {
        EXPECT_EQ(ret, true);
    } else {
        EXPECT_EQ(ret, false);
    }
}

} // namespace FFRT_TEST
} // namespace OHOS