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

#ifndef CONCURRENT_TASK_SERVICE_INTERFACES_INNERAPI_CONCURRENT_TASK_CLIENT_INCLUDE_CONCURRENT_TASK_CLIENT_H
#define CONCURRENT_TASK_SERVICE_INTERFACES_INNERAPI_CONCURRENT_TASK_CLIENT_INCLUDE_CONCURRENT_TASK_CLIENT_H

#include <unordered_map>
#include "iremote_object.h"
#include "iconcurrent_task_service.h"

namespace OHOS {
namespace ConcurrentTask {
/*
 * this class wraped the functions of IConcurrentTaskService,effect is the same.
 * but through ConcurrentTaskClient, you don't need to get IConcurrentTaskService from samgr,
 * just use the functions is ok.
 */

class ConcurrentTaskClient {
public:
    /**
     * Only need one client connect to ConcurrentTaskService, singleton pattern.
     *
     * @return Returns the only one implement of ConcurrentTaskClient.
     */
    static ConcurrentTaskClient& GetInstance();

    void ReportData(uint32_t resType, int64_t value, const std::unordered_map<std::string, std::string>& mapPayload);
    void QueryInterval(int queryItem, IntervalReply& queryRs);

    void StopRemoteObject();

protected:
    ConcurrentTaskClient() = default;
    virtual ~ConcurrentTaskClient() = default;

private:
    class ConcurrentTaskDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit ConcurrentTaskDeathRecipient(ConcurrentTaskClient& concurrentTaskClient);

        ~ConcurrentTaskDeathRecipient() override;

        void OnRemoteDied(const wptr<IRemoteObject>& object) override;

    private:
        ConcurrentTaskClient& concurrentTaskClient_;
    };
    ErrCode TryConnect();

    std::mutex mutex_;
    sptr<ConcurrentTaskDeathRecipient> recipient_;
    sptr<IRemoteObject> remoteObject_;
    sptr<IConcurrentTaskService> clientService_;
    DISALLOW_COPY_AND_MOVE(ConcurrentTaskClient);
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SERVICE_INTERFACES_INNERAPI_ConcurrentTask_CLIENT_INCLUDE_CONCURRENT_TASK_CLIENT_H
