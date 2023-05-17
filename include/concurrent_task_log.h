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

#ifndef CONCURRENT_TASK_COMMON_INCLUDE_CONCURRENT_TASK_LOG_H
#define CONCURRENT_TASK_COMMON_INCLUDE_CONCURRENT_TASK_LOG_H

#include "hilog/log.h"

namespace OHOS {
namespace ConcurrentTask {
constexpr OHOS::HiviewDFX::HiLogLabel CONCUR_LABEL = {
    LOG_CORE,
    0xD001707,
    "CONCUR"
};

#define CONCUR_LOGF(...) (void)OHOS::HiviewDFX::HiLog::Fatal(CONCUR_LABEL, __VA_ARGS__)
#define CONCUR_LOGE(...) (void)OHOS::HiviewDFX::HiLog::Error(CONCUR_LABEL, __VA_ARGS__)
#define CONCUR_LOGW(...) (void)OHOS::HiviewDFX::HiLog::Warn(CONCUR_LABEL, __VA_ARGS__)
#define CONCUR_LOGI(...) (void)OHOS::HiviewDFX::HiLog::Info(CONCUR_LABEL, __VA_ARGS__)
#define CONCUR_LOGD(...) (void)OHOS::HiviewDFX::HiLog::Debug(CONCUR_LABEL, __VA_ARGS__)
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK
