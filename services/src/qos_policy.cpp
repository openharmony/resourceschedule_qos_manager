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

#include "qos_policy.h"
#include <unistd.h>
#include "concurrent_task_log.h"

static struct QosPolicyDatas g_defaultQosPolicy = {
    .policyType = QOS_POLICY_DEFAULT,
    .policyFlag = QOS_FLAG_ALL,
    .policys = {
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
    }
};

static struct QosPolicyDatas g_foregroundQosPolicy = {
    .policyType = QOS_POLICY_FRONT,
    .policyFlag = QOS_FLAG_ALL,
    .policys = {
        {10, 10, 0, 200, 0, SCHED_POLICY_OTHER},
        {5, 5, 0, 250, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
#ifdef QOS_EXT_ENABLE
        {-10, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {-10, -10, 0, 1024, 0, SCHED_POLICY_OTHER},
        {-10, -10, 0, 1024, 0, SCHED_POLICY_OTHER},
#else
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
#endif
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
    }
};

static struct QosPolicyDatas g_backgroundQosPolicy = {
    .policyType = QOS_POLICY_BACK,
    .policyFlag = QOS_FLAG_ALL & ~QOS_FLAG_RT,
    .policys = {
        {15, 15, 0, 150, 0, SCHED_POLICY_OTHER},
        {10, 10, 0, 200, 0, SCHED_POLICY_OTHER},
        {5, 5, 0, 250, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 300, 0, SCHED_POLICY_OTHER},
#ifdef QOS_EXT_ENABLE
        {-5, -5, 0, 350, 0, SCHED_POLICY_OTHER},
        {-5, -5, 0, 350, 0, SCHED_POLICY_OTHER},
#else
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
#endif
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
    }
};

static struct QosPolicyDatas g_systemServerQosPolicy = {
    .policyType = QOS_POLICY_SYSTEM_SERVER,
    .policyFlag = QOS_FLAG_ALL,
    .policys = {
        {10, 10, 0, 200, 0, SCHED_POLICY_OTHER},
        {5, 5, 0, 250, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
#ifdef QOS_EXT_ENABLE
        {-10, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {-10, -10, 0, 1024, 0, SCHED_POLICY_OTHER},
        {-10, -10, 0, 1024, 1, SCHED_POLICY_FIFO | SCHED_RESET_ON_FORK},
#else
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
#endif
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
    }
};

static struct QosPolicyDatas g_focusQosPolicy = {
    .policyType = QOS_POLICY_FOCUS,
    .policyFlag = QOS_FLAG_ALL,
    .policys = {
        {10, 10, 0, 200, 0, SCHED_POLICY_OTHER},
        {5, 5, 0, 250, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
#ifdef QOS_EXT_ENABLE
        {-10, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {-10, -10, 0, 1024, 0, SCHED_POLICY_OTHER},
        {-10, -10, 0, 1024, 1, SCHED_POLICY_RT_EX | SCHED_RESET_ON_FORK},
#else
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
#endif
        {0, 0, 0, 1024, 0, SCHED_POLICY_OTHER},
    }
};

namespace OHOS {
namespace ConcurrentTask {
int QosPolicy::SetQosPolicy(struct QosPolicyDatas *policyDatas)
{
    return QosPolicySet(policyDatas);
}

void QosPolicy::Init()
{
    int ret;

    ret = SetQosPolicy(&g_defaultQosPolicy);
    if (ret) {
        CONCUR_LOGE("%{public}d set g_defaultQosPolicy failed", getuid());
    }

    ret = SetQosPolicy(&g_foregroundQosPolicy);
    if (ret) {
        CONCUR_LOGE("%{public}d set g_foregroundQosPolicy failed", getuid());
    }

    ret = SetQosPolicy(&g_backgroundQosPolicy);
    if (ret) {
        CONCUR_LOGE("%{public}d set g_backgroundQosPolicy failed", getuid());
    }

    ret = SetQosPolicy(&g_systemServerQosPolicy);
    if (ret) {
        CONCUR_LOGE("%{public}d set g_systemServerQosPolicy failed", getuid());
    }

    ret = SetQosPolicy(&g_focusQosPolicy);
    if (ret) {
        CONCUR_LOGE("%{public}d set g_focusQosPolicy failed", getuid());
    }

    CONCUR_LOGI("set qos policy finish");
}
}
}
