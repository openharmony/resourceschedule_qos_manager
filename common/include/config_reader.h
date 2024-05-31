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
#ifndef CONCURRENT_TASK_SERVICES_COMMON_INCLUDE_CONFIG_READER_H
#define CONCURRENT_TASK_SERVICES_COMMON_INCLUDE_CONFIG_READER_H

#include <memory>
#include <unordered_set>
#include "libxml/parser.h"
#include "libxml/xpath.h"

namespace OHOS {
namespace ConcurrentTask {
class ConfigReader {
public:
    bool LoadFromConfigFile(const std::string& configFile);
    void GetRealConfigPath(const char* configName, std::string& configPath);
    bool IsUidAuth(pid_t uid);
    bool IsBundleNameAuth(std::string& bundleName);
private:
    bool IsValidNode(const xmlNode* currNode);
    bool FillinUidInfo(const xmlNode* currNode);
    bool FillinBundleNameInfo(const xmlNode* currNode);
    void ParseAuth(const xmlNode* currNode);
    void TestHilog();
    std::unordered_set<pid_t> authProcUidConfigs_;
    std::unordered_set<std::string> authProcBundleNameConfigs_;
};
} // namespace ConcurrentTask
} // namespace OHOS
#endif // CONCURRENT_TASK_SERVICES_COMMON_INCLUDE_CONFIG_READER_H
