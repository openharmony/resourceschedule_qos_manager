/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#define private public
#include "concurrent_task_client.h"
#undef private
#include "concurrent_task_service_proxy.h"
#include "securec.h"
#include "concurrent_fuzzer.h"

using namespace OHOS::ConcurrentTask;

namespace OHOS {
bool FuzzConcurrentTaskTryConnect(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    if (size < sizeof(int32_t)) {
        return false;
    }
    return ConcurrentTaskClient::GetInstance().TryConnect() == ERR_OK;
}

bool FuzzConcurrentTaskServiceReportData(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    if (size < sizeof(int32_t)) {
        return false;
    }

    std::string name((const char*) data, size);
    uint32_t resType = static_cast<uint32_t>(*data);
    int64_t value = static_cast<int64_t>(*data);
    std::unordered_map<std::string, std::string> payload;
    payload["name"] = name;
    OHOS::ConcurrentTask::ConcurrentTaskClient::GetInstance().ReportData(resType, value, payload);
    return true;
}

bool FuzzConcurrentTaskServiceQueryInterval(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    if (size < sizeof(int32_t)) {
        return false;
    }

    std::string name((const char*) data, size);
    int queryItem = static_cast<int>(*data);
    IntervalReply rs;
    rs.rtgId = -1;
    OHOS::ConcurrentTask::ConcurrentTaskClient::GetInstance().QueryInterval(queryItem, rs);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzConcurrentTaskTryConnect(data, size);
    OHOS::FuzzConcurrentTaskServiceReportData(data, size);
    OHOS::FuzzConcurrentTaskServiceQueryInterval(data, size);
    return 0;
}
