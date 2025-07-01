
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
#include "concurrent_task_log.h"
#include <unistd.h>
#include <string>
#include <mutex>
#include <unordered_map>
#include <dlfcn.h>

static constexpr int ERROR_NUM = -1;

const char* GEWU_CLIENT_LIB = "libgewu_client.z.so";

const char* GEWU_CREATE_SESSION_FUNC = "GewuCreateSession";
const char* GEWU_DESTROY_SESSION_FUNC = "GewuDestroySession";
const char* GEWU_SUBMIT_REQUEST_FUNC = "GewuSubmitRequest";
const char* GEWU_ABORT_REQUEST_FUNC = "GewuAbortRequest";

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

using GewuCreateSessionFunc = OH_QoS_GewuCreateSessionResult(*)(const char* attributes);
using GewuDestroySessionFunc = OH_QoS_GewuErrorCode(*)(OH_QoS_GewuSession session);
using GewuAbortRequestFunc = OH_QoS_GewuErrorCode(*)(OH_QoS_GewuSession session, OH_QoS_GewuRequest request);
using GewuSubmitRequestFunc = OH_QoS_GewuSubmitRequestResult(*)(OH_QoS_GewuSession session, const char* request,
    OH_QoS_GewuOnResponse callback, void *context);

std::once_flag g_gewuInitFlag;
bool g_gewuInitialized = false;

void* g_gewuNdkLibHandler = nullptr;

GewuCreateSessionFunc g_CreateSession = nullptr;
GewuDestroySessionFunc g_DestroySession = nullptr;
GewuSubmitRequestFunc g_SubmitRequest = nullptr;
GewuAbortRequestFunc g_AbortRequest = nullptr;

static inline void *LoadSymbol(const char* symbolName)
{
    void* funcPtr = dlsym(g_gewuNdkLibHandler, symbolName);
    if (funcPtr == nullptr) {
        CONCUR_LOGE("[Gewu] failed to load symbol: %{public}s, error: %{public}s", symbolName, dlerror());
    }
    return funcPtr;
}

static int LoadSymbols(void)
{
    g_CreateSession = reinterpret_cast<GewuCreateSessionFunc>(LoadSymbol(GEWU_CREATE_SESSION_FUNC));
    if (g_CreateSession == nullptr) {
        return -1;
    }

    g_DestroySession = reinterpret_cast<GewuDestroySessionFunc>(LoadSymbol(GEWU_DESTROY_SESSION_FUNC));
    if (g_DestroySession == nullptr) {
        return -1;
    }

    g_SubmitRequest = reinterpret_cast<GewuSubmitRequestFunc>(LoadSymbol(GEWU_SUBMIT_REQUEST_FUNC));
    if (g_SubmitRequest == nullptr) {
        return -1;
    }

    g_AbortRequest = reinterpret_cast<GewuAbortRequestFunc>(LoadSymbol(GEWU_ABORT_REQUEST_FUNC));
    if (g_AbortRequest == nullptr) {
        return -1;
    }

    return 0;
}

__attribute__((noinline)) static void InitializeGewu(void)
{
    g_gewuNdkLibHandler = dlopen(GEWU_CLIENT_LIB, RTLD_LAZY | RTLD_LOCAL);
    if (g_gewuNdkLibHandler == nullptr) {
        CONCUR_LOGE("[Gewu] failed to load library: %{public}s, error: %{public}s", GEWU_CLIENT_LIB, dlerror());
        return;
    }
    int err = LoadSymbols();
    if (err != 0) {
        dlclose(g_gewuNdkLibHandler);
        g_gewuNdkLibHandler = nullptr;
        return;
    }
    g_gewuInitialized = true;
}

static inline bool EnsureGewuInitialized(void)
{
    std::call_once(g_gewuInitFlag, InitializeGewu);
    return g_gewuInitialized;
}

extern "C" OH_QoS_GewuCreateSessionResult OH_QoS_GewuCreateSession(const char* attributes)
{
    if (!EnsureGewuInitialized()) {
        return {OH_QOS_GEWU_INVALID_SESSION_ID, OH_QOS_GEWU_NOSYS};
    }
    return g_CreateSession(attributes);
}

extern "C" OH_QoS_GewuErrorCode OH_QoS_GewuDestroySession(OH_QoS_GewuSession session)
{
    if (!EnsureGewuInitialized()) {
        return OH_QOS_GEWU_NOSYS;
    }
    return g_DestroySession(session);
}

extern "C" OH_QoS_GewuSubmitRequestResult OH_QoS_GewuSubmitRequest(OH_QoS_GewuSession session, const char* request,
                                                                   OH_QoS_GewuOnResponse callback, void* context)
{
    if (!EnsureGewuInitialized()) {
        return {OH_QOS_GEWU_INVALID_REQUEST_ID, OH_QOS_GEWU_NOSYS};
    }
    return g_SubmitRequest(session, request, callback, context);
}

extern "C" OH_QoS_GewuErrorCode OH_QoS_GewuAbortRequest(OH_QoS_GewuSession session, OH_QoS_GewuRequest request)
{
    if (!EnsureGewuInitialized()) {
        return OH_QOS_GEWU_NOSYS;
    }
    return g_AbortRequest(session, request);
}
