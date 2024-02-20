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

const unordered_map<QoS_Level, QosLevel> qos_map = {
    {QoS_Level::QOS_BACKGROUND, QosLevel::QOS_BACKGROUND},
    {QoS_Level::QOS_UTILITY, QosLevel::QOS_UTILITY},
    {QoS_Level::QOS_DEFAULT, QosLevel::QOS_DEFAULT},
    {QoS_Level::QOS_USER_INITIATED, QosLevel::QOS_USER_INITIATED},
    {QoS_Level::QOS_DEADLINE_REQUEST, QosLevel::QOS_DEADLINE_REQUEST},
    {QoS_Level::QOS_USER_INTERACTIVE, QosLevel::QOS_USER_INTERACTIVE}
};

const unordered_map<QosLevel, QoS_Level> qos_reverse_map = {
    {QosLevel::QOS_BACKGROUND, QoS_Level::QOS_BACKGROUND},
    {QosLevel::QOS_UTILITY, QoS_Level::QOS_UTILITY},
    {QosLevel::QOS_DEFAULT, QoS_Level::QOS_DEFAULT},
    {QosLevel::QOS_USER_INITIATED, QoS_Level::QOS_USER_INITIATED},
    {QosLevel::QOS_DEADLINE_REQUEST, QoS_Level::QOS_DEADLINE_REQUEST},
    {QosLevel::QOS_USER_INTERACTIVE, QoS_Level::QOS_USER_INTERACTIVE}
};


int OH_QoS_SetThreadQoS(QoS_Level level)
{
    auto iter = qos_map.find(level);
    if (iter == qos_map.end()) {
        return ERROR_NUM;
    }
    return QosController::GetInstance().SetThreadQosForOtherThread(iter->second, gettid());
}

int OH_QoS_ResetThreadQoS(void)
{
    return QosController::GetInstance().ResetThreadQosForOtherThread(gettid());
}

int OH_QoS_GetThreadQoS(QoS_Level *level)
{
    if (level == nullptr) {
        return ERROR_NUM;
    }
    enum QosLevel qosLevel;
    int ret = QosController::GetInstance().GetThreadQosForOtherThread(qosLevel, gettid());
    if (ret < 0) {
        return ERROR_NUM;
    }
    auto iter = qos_reverse_map.find(qosLevel);
    if (iter == qos_reverse_map.end()) {
        return ERROR_NUM;
    }
    *level = iter->second;
    return 0;
}