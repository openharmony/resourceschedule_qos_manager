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

#include <cstdlib>
#include <unistd.h>
#include "concurrent_task_log.h"
#include "parameters.h"
#include "qos_interface.h"
#include "qos.h"
using namespace OHOS::ConcurrentTask;

static constexpr int ERROR_NUM = -1;

namespace OHOS {
namespace QOS {
QosController& QosController::GetInstance()
{
    static QosController instance;
    return instance;
}

int QosController::SetThreadQosForOtherThread(enum QosLevel level, int tid)
{
    bool qosEnable = OHOS::system::GetBoolParameter("persist.all.setQos.on", true);
    int qos = static_cast<int>(level);
    if (!qosEnable) {
        CONCUR_LOGD("[Qos] qoslevel %{public}d apply for tid %{public}d disable", qos, tid);
        return 0;
    }
    if (level < QosLevel::QOS_BACKGROUND || level >= QosLevel::QOS_MAX) {
        CONCUR_LOGE("[Qos] invalid qos level %{public}d", qos);
        return ERROR_NUM;
    }
    int ret = QosApplyForOther(qos, tid);
    if (ret == 0) {
        CONCUR_LOGD("[Qos] qoslevel %{public}d apply for tid %{public}d success", qos, tid);
    } else {
        CONCUR_LOGE("[Qos] qoslevel %{public}d apply for tid %{public}d failure", qos, tid);
    }

    return ret;
}

int QosController::ResetThreadQosForOtherThread(int tid)
{
    bool qosEnable = OHOS::system::GetBoolParameter("persist.all.setQos.on", true);
    if (!qosEnable) {
        CONCUR_LOGD("[Qos] qoslevel reset disable for tid %{public}d.", tid);
        return 0;
    }
    int ret = QosLeaveForOther(tid);
    if (ret == 0) {
        CONCUR_LOGD("[Qos] qoslevel reset for tid %{public}d success", tid);
    } else {
        CONCUR_LOGE("[Qos] qoslevel reset for tid %{public}d failure", tid);
    }

    return ret;
}

int QosController::GetThreadQosForOtherThread(enum QosLevel &level, int tid)
{
    int qos;
    int ret = QosGetForOther(tid, qos);
    if (ret == 0) {
        CONCUR_LOGD("[Qos] qoslevel get for tid %{public}d success", tid);
    } else {
        CONCUR_LOGE("[Qos] qoslevel get for tid %{public}d failure", tid);
    }
    if (qos < static_cast<int>(QosLevel::QOS_BACKGROUND) || qos >= static_cast<int>(QosLevel::QOS_MAX)) {
        return ERROR_NUM;
    }
    level = static_cast<QosLevel>(qos);

    return ret;
}

int SetThreadQos(enum QosLevel level)
{
    int tid = gettid();
    return QosController::GetInstance().SetThreadQosForOtherThread(level, tid);
}

int SetQosForOtherThread(enum QosLevel level, int tid)
{
    return QosController::GetInstance().SetThreadQosForOtherThread(level, tid);
}

int ResetThreadQos()
{
    int tid = gettid();
    return QosController::GetInstance().ResetThreadQosForOtherThread(tid);
}

int ResetQosForOtherThread(int tid)
{
    return QosController::GetInstance().ResetThreadQosForOtherThread(tid);
}

int GetThreadQos(enum QosLevel &level)
{
    return QosController::GetInstance().GetThreadQosForOtherThread(level, gettid());
}
} // namespace QOS
} // namespace OHOS
