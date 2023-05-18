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

#include "concurrent_task_service_ability.h"
#include "concurrent_task_log.h"
#include "concurrent_task_controller.h"
#include "concurrent_task_service.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace ConcurrentTask {
REGISTER_SYSTEM_ABILITY_BY_ID(ConcurrentTaskServiceAbility, CONCURRENT_TASK_SERVICE_ID, true);

void ConcurrentTaskServiceAbility::OnStart()
{
    TaskController::GetInstance().Init();
    if (!service_) {
        try {
            service_ = new ConcurrentTaskService();
        } catch (const std::bad_alloc& e) {
            CONCUR_LOGE("ConcurrentTaskServiceAbility:: new ConcurentTaskService failed.");
        }
    }
    if (!Publish(service_)) {
        CONCUR_LOGE("ConcurrentTaskServiceAbility:: Register service failed.");
    }
    CONCUR_LOGI("ConcurrentTaskServiceAbility ::OnStart.");
}

void ConcurrentTaskServiceAbility::OnStop()
{
    TaskController::GetInstance().Release();
    CONCUR_LOGI("ConcurrentTaskServiceAbility::OnStop!");
}

void ConcurrentTaskServiceAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    CONCUR_LOGI("ConcurrentTaskServiceAbility::Add");
}

void ConcurrentTaskServiceAbility::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    CONCUR_LOGI("ConcurrentTaskServiceAbility::Remove");
}
} // namespace ConcurrentTask
} // namespace OHOS
