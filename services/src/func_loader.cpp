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

#include "func_loader.h"

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>

#include "concurrent_task_log.h"

namespace OHOS {
namespace ConcurrentTask {
FuncLoader::FuncLoader(const std::string& funcImplPath) : funcImplPath_(funcImplPath)
{
    LoadFile(funcImplPath_.c_str());
}

FuncLoader::~FuncLoader()
{
    if (fileHandle_ != nullptr) {
        dlclose(fileHandle_);
    }
    fileHandle_ = nullptr;
}

void FuncLoader::LoadFile(const char* fileName)
{
    if (!fileName || strlen(fileName) == 0 || strlen(fileName) > PATH_MAX) {
        CONCUR_LOGE("%{public}s, load %{pulibc}s file fail", __func__, fileName);
        return;
    }
    const char* preFix = "lib";
    if (strncmp(fileName, preFix, strlen(preFix)) != 0) {
        CONCUR_LOGE("invailed fileName!");
        return;
    }
    fileHandle_ = dlopen(fileName, RTLD_LAZY);
    if (fileHandle_ == nullptr) {
        enable_ = false;
        CONCUR_LOGE("dlopen %{public}s ffail", fileName);
        return;
    }
    CONCUR_LOGD("%{public}s, load %{pulibc}s file success", __func__, fileName);
    enable_ = true;
}

void* FuncLoader::LoadSymbol(const char* sysName)
{
    if (!enable_) {
        return nullptr;
    }
    void* funcSym = dlsym(fileHandle_, sysName);
    if (funcSym == nullptr) {
        CONCUR_LOGE("dlsym func %{public}s fail", sysName);
        enable_ = false;
        return nullptr;
    }
    CONCUR_LOGD("dlsym func %{public}s success", sysName);
    return funcSym;
}

bool FuncLoader::GetLoadSuccess()
{
    return enable_;
}

} // namespace ConcurrentTask
} // namespace OHOS