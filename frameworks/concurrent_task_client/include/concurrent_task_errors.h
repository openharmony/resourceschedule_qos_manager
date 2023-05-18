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

#ifndef CONCURRENT_TASK_SERVICE_INTERFACES_INNERAPI_CONCURRENT_TASK_CLIENT_INCLUDE_CONCURRENT_TASK_ERRORS_H
#define CONCURRENT_TASK_SERVICE_INTERFACES_INNERAPI_CONCURRENT_TASK_CLIENT_INCLUDE_CONCURRENT_TASK_ERRORS_H

#include "errors.h"

namespace OHOS {
namespace ConcurrentTask {
enum {
    CONCURRENT_TASK_MODULE_COMMON = 0x00,
    CONCURRENT_TASK_MODULE_SERVICE = 0x01,
};

constexpr ErrCode CONCURRENT_TASK_COMMON_ERR_OFFSET = ErrCodeOffset(SUBSYS_IAWARE, CONCURRENT_TASK_MODULE_COMMON);
enum {
    ERR_CONCURRENT_TASK_INVALID_PARAM = CONCURRENT_TASK_COMMON_ERR_OFFSET + 1,
    GET_CONCURRENT_TASK_SERVICE_FAILED,
};

constexpr ErrCode CONCURRENT_TASK_SERVICE_ERR_OFFSET = ErrCodeOffset(SUBSYS_IAWARE, CONCURRENT_TASK_MODULE_SERVICE);
enum {
    ERR_CONCURRENT_TASK_PARCEL_ERROR = CONCURRENT_TASK_SERVICE_ERR_OFFSET + 1,
    ERR_CONCURRENT_TASK_PERMISSION_DENIED,
    ERR_CONCURRENT_TASK_WRITE_FILE_FAILED,
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SERVICE_INTERFACES_INNERAPI_CONCURRENT_TASK_CLIENT_INCLUDE_CONCURRENT_TASK_ERRORS_H
