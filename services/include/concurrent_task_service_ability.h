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

#ifndef CONCURRENT_TASK_SEVICES_INCLUDE_CONCURRENT_TASK_SERVICE_ABILITY_H
#define CONCURRENT_TASK_SEVICES_INCLUDE_CONCURRENT_TASK_SERVICE_ABILITY_H

#include "system_ability.h"
#include "concurrent_task_service.h"

namespace OHOS {
namespace ConcurrentTask {
class ConcurrentTaskServiceAbility : public SystemAbility {
    DECLARE_SYSTEM_ABILITY(ConcurrentTaskServiceAbility);

public:
    ConcurrentTaskServiceAbility(int32_t sysAbilityId, bool runOnCreate) : SystemAbility(sysAbilityId, runOnCreate) {}
    ~ConcurrentTaskServiceAbility() override = default;

private:
    void OnStart() override;

    void OnStop() override;

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    sptr<ConcurrentTaskService> service_;

    DISALLOW_COPY_AND_MOVE(ConcurrentTaskServiceAbility);
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SEVICES_INCLUDE_CONCURRENT_TASK_SERVICE_ABILITY_H
