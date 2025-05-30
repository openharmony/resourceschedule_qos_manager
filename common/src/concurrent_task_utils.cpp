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

#include <fcntl.h>
#include <sys/eventfd.h>
#include "concurrent_task_utils.h"


uint64_t GetAddrTag(void* addr)
{
    uint64_t tag = 0;
#if !defined(CROSS_PLATFORM)
    if (addr != nullptr) {
        tag = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, (uint64_t)addr);
    }
#endif
    return tag;
}