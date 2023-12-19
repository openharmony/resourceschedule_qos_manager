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

#ifndef CONCURRENT_TASK_SERVICES_IPC_INTERFACE_CODE_H
#define CONCURRENT_TASK_SERVICES_IPC_INTERFACE_CODE_H

/* SAID:1912 */
namespace OHOS {
namespace ConcurrentTask {
enum class ConcurrentTaskInterfaceCode {
    REPORT_DATA = 1,
    QUERY_INTERVAL = 2,
    QUERY_DEADLINE = 3,
    REQUEST_AUTH = 4,
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SERVICES_IPC_INTERFACE_CODE_H
