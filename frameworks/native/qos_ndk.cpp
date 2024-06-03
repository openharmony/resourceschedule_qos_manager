
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
#include "qos.h"
#include "inner_api/qos.h"
#include <unistd.h>
#include <string>
#include <unordered_map>

static constexpr int ERROR_NUM = -1;

using namespace OHOS::QOS;
using namespace std;

int OH_QoS_SetThreadQoS(QoS_Level level)
{
    if (level < QOS_BACKGROUND || level > QOS_USER_INTERACTIVE) {
        return ERROR_NUM;
    }
    return SetThreadQos(static_cast<QosLevel>(level));
}

int OH_QoS_ResetThreadQoS(void)
{
    return ResetThreadQos();
}

int OH_QoS_GetThreadQoS(QoS_Level *level)
{
    if (level == nullptr) {
        return ERROR_NUM;
    }
    QosLevel qosLevel;
    int ret = GetThreadQos(qosLevel);
    if (ret < 0) {
        return ERROR_NUM;
    }
    if (static_cast<int>(qosLevel) < QoS_Level::QOS_BACKGROUND ||
        static_cast<int>(qosLevel) > QoS_Level::QOS_USER_INTERACTIVE) {
        return ERROR_NUM;
    }
    *level = static_cast<QoS_Level>(qosLevel);
    return 0;
}