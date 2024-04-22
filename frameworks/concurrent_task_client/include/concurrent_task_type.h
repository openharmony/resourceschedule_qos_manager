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

#ifndef CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_TYPE_H
#define CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_TYPE_H
namespace OHOS {
namespace ConcurrentTask {
constexpr int MAX_KEY_THREADS = 5;

enum MsgType {
    MSG_FOREGROUND = 0,
    MSG_BACKGROUND,
    MSG_APP_START,
    MSG_APP_KILLED,
    MSG_CONTINUOUS_TASK_START,
    MSG_CONTINUOUS_TASK_END,
    MSG_GET_FOCUS,
    MSG_LOSE_FOCUS,
    MSG_SYSTEM_MAX,
    MSG_APP_START_TYPE = 100,
    MSG_REG_RENDER = MSG_APP_START_TYPE,
    MSG_REG_UI,
    MSG_REG_KEY_THERAD,
    MSG_TYPE_MAX
};

enum PrioType {
    PRIO_RT = 0,
    RPIO_IN = 1,
    PRIO_NORMAL = 2,
};

enum QueryIntervalItem {
    QUERY_UI = 0,
    QUERY_RENDER = 1,
    QUERY_RENDER_SERVICE = 2,
    QUERY_COMPOSER = 3,
    QUERY_HARDWARE = 4,
    QUERY_EXECUTOR_START = 5,
    QUERY_RENDER_SERVICE_MAIN = 6,
    QUERY_RENDER_SERVICE_RENDER = 7,
    QURRY_TYPE_MAX,
};

enum DeadlineType {
    DDL_RATE = 0,
    MSG_GAME = 1,
};

struct IntervalReply {
    int rtgId;
    int tid;
    int paramA;
    int paramB;
    std::string bundleName;
};

struct DeadlineReply {
    bool setStatus;
};

enum GameStatus {
    GAME_ENTRY_MSG = 0,
    GAME_EXIT_MSG,
    GAME_GTX_MSG,
    CAMERA_ENTRY_MSG,
    CAMERA_EXIT_MSG,
    STATUS_MSG_MAX
};
}
}
#endif // CONCURRENT_TASK_SERVICES_CONCURRENTSEVICE_INCLUDE_CONCURRENT_TASK_TYPE_H
