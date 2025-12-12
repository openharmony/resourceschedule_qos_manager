/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef QOS_MANAGER_PI_MUETX_H
#define QOS_MANAGER_PI_MUETX_H

#include <pthread.h>
#include <type_traits>

namespace OHOS {
namespace PiMutex {
template<class, class = std::void_t<>>
struct HasType : std::false_type {};

template<class T>
struct HasType<T, std::void_t<typename T::native_handle_type>> : std::true_type {};

template<class Mutex>
class PiMutex : public Mutex {
public:
    PiMutex()
    {
        if constexpr (HasType<Mutex> && std::is_same_v<Mutex::native_handle_type, pthread_mutex_t*>) {
            typename Mutex::native_handle_type handle = Mutex::native_handle();
            pthread_mutexattr_t attr;
            pthread_mutexattr_init(&attr);
            pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);
            pthread_mutex_init(handle, &attr);
        }
    }

    ~PiMutex() = default;

    PiMutex(const PiMutex&) = delete;
    PiMutex& operator=(const PiMutex&) = delete;
};
} // namespace QOS
} // namespace OHOS

#endif // QOS_MANAGER_PI_MUETX_H
