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

#ifndef QOS_MANAGER_INTERFACES_INNER_API_QOS_H
#define QOS_MANAGER_INTERFACES_INNER_API_QOS_H

namespace OHOS {
namespace QOS {
enum class QosLevel {
    QOS_BACKGROUND,
    QOS_UTILITY,
    QOS_DEFAULT,
    QOS_USER_INITIATED,
    QOS_DEADLINE_REQUEST,
    QOS_USER_INTERACTIVE,
    QOS_KEY_BACKGROUND,
    QOS_MAX,
};

class QosController {
public:
    static QosController& GetInstance();

    int SetThreadQosForOtherThread(enum QosLevel level, int tid);
    int ResetThreadQosForOtherThread(int tid);
    int GetThreadQosForOtherThread(enum QosLevel &level, int tid);

private:
    QosController() = default;
    ~QosController() = default;

    QosController(const QosController&) = delete;
    QosController& operator=(const QosController&) = delete;
    QosController(QosController&&) = delete;
    QosController& operator=(const QosController&&) = delete;
};

int SetThreadQos(enum QosLevel level);
int SetQosForOtherThread(enum QosLevel level, int tid);
int ResetThreadQos();
int ResetQosForOtherThread(int tid);
int GetThreadQos(enum QosLevel &level);
} // namespace QOS
} // namespace OHOS

#endif // QOS_MANAGER_INTERFACES_INNER_API_QOS_H
