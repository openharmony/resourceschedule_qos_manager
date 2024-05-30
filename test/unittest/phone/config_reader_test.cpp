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
#include <memory>
#include <string>
#define private public
#define protected public
#include "config_reader.h"
#undef private
#undef protected
#include "gtest/gtest.h"

namespace OHOS {
namespace FFRT_TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::ConcurrentTask;

class ConfigReaderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConfigReaderTest::SetUpTestCase()
{
}

void ConfigReaderTest::TearDownTestCase()
{
}

void ConfigReaderTest::SetUp()
{
    configReader_ = std::make_unique<ConfigReader>();
}

void ConfigReaderTest::TearDown()
{
}

/**
 * @tc.name: ConfigReaderTest
 * @tc.desc: Test whether the ConfigReader interface are normal.
 * @tc.type: FUNC
 */
HWTEST_F(ConfigReaderTest, ConfigReaderTest, TestSize.Level1)
{
}
}
}