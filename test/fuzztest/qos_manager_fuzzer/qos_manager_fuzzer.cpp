/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "qos_manager_fuzzer.h"

#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <thread>
#include <climits>
#include "concurrent_task_service.h"
#include "securec.h"
#include "qos.h"
#include "qos_interface.h"
#include "qos_policy.h"
#include "system_ability_definition.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::ConcurrentTask;
using namespace OHOS::QOS;

namespace OHOS {
static std::mutex onStopMutex_;

namespace {
    // 所有有效的 QoS 级别（基于 qos.h 的枚举）
    constexpr QosLevel VALID_QOS_LEVELS[] = {
        QosLevel::QOS_BACKGROUND,
        QosLevel::QOS_UTILITY,
        QosLevel::QOS_DEFAULT,
        QosLevel::QOS_USER_INITIATED,
        QosLevel::QOS_DEADLINE_REQUEST,
        QosLevel::QOS_USER_INTERACTIVE
    };
    constexpr size_t VALID_QOS_COUNT = sizeof(VALID_QOS_LEVELS) / sizeof(VALID_QOS_LEVELS[0]);
    
    // 边界值测试用的非法 QoS 级别
    constexpr int INVALID_QOS_LEVELS[] = {
        -1, -100, 6, 7, 100, 255, INT_MIN, INT_MAX
    };
    constexpr size_t INVALID_QOS_COUNT = sizeof(INVALID_QOS_LEVELS) / sizeof(INVALID_QOS_LEVELS[0]);
}

// 辅助函数：获取有效的 QoS 级别
static QosLevel GetValidQosLevel(FuzzedDataProvider &fdp)
{
    size_t index = fdp.ConsumeIntegralInRange<size_t>(0, VALID_QOS_COUNT - 1);
    return VALID_QOS_LEVELS[index];
}

// 辅助函数：获取可能无效的 QoS 级别（用于边界测试）
static int GetPossiblyInvalidQosLevel(FuzzedDataProvider &fdp)
{
    if (fdp.ConsumeBool()) {
        // 返回有效值
        return static_cast<int>(GetValidQosLevel(fdp));
    } else {
        // 返回无效值
        size_t index = fdp.ConsumeIntegralInRange<size_t>(0, INVALID_QOS_COUNT - 1);
        return INVALID_QOS_LEVELS[index];
    }
}

// 辅助函数：获取各种可能的线程 ID
static int GetThreadId(FuzzedDataProvider &fdp)
{
    // 定义特殊线程ID常量
    constexpr int invalidTid1 = -1;         // 无效 tid
    constexpr int invalidTid2 = 0;          // 无效 tid
    constexpr int initProcessTid = 1;       // init 进程
    constexpr int threadTidMax = INT_MAX;   // 边界值
    constexpr int threadTidMin = INT_MIN;   // 边界值
    constexpr int threadTidMaxValid = 65535;

    // 随机选择策略
    enum ThreadIdChoice : uint8_t {
        CURRENT_THREAD = 0,
        INIT_PROCESS,
        INVALID_TID_NEG1,
        INVALID_TID_ZERO,
        MAX_TID,
        MIN_TID,
        RANDOM_VALID
    };

    uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);

    switch (choice) {
        case CURRENT_THREAD:
            return gettid();          // 当前线程
        case INIT_PROCESS:
            return initProcessTid;  // init 进程
        case INVALID_TID_NEG1:
            return invalidTid1;     // 无效 tid
        case INVALID_TID_ZERO:
            return invalidTid2;     // 无效 tid
        case MAX_TID:
            return threadTidMax;    // 边界值
        case MIN_TID:
            return threadTidMin;    // 边界值
        default:
            // 随机但可能有效的 tid
            return fdp.ConsumeIntegralInRange<int>(1, threadTidMaxValid);
    }
}


// 测试1: 边界值测试 - 无效 QoS 级别
bool FuzzInvalidQosLevels(FuzzedDataProvider &fdp)
{
    int invalidLevel = GetPossiblyInvalidQosLevel(fdp);
    int tid = GetThreadId(fdp);
    
    // 尝试设置无效的 QoS 级别（应该返回错误）
    QOS::SetQosForOtherThread(static_cast<QosLevel>(invalidLevel), tid);
    
    return true;
}

// 测试2: 边界值测试 - 无效线程 ID
bool FuzzInvalidThreadIds(FuzzedDataProvider &fdp)
{
    QosLevel level = GetValidQosLevel(fdp);
    
    // 测试各种无效的线程 ID
    int invalidTids[] = {-1, 0, -100, INT_MIN, INT_MAX, 999999};
    for (int tid : invalidTids) {
        QOS::SetQosForOtherThread(level, tid);
        
        enum QosLevel outLevel;
        QosController::GetInstance().GetThreadQosForOtherThread(outLevel, tid);
    }
    
    return true;
}

// 测试3: 状态转换测试 - 测试所有可能的 QoS 级别转换
bool FuzzQosStateTransitions(FuzzedDataProvider &fdp)
{
    // 设置一个初始级别
    QosLevel initialLevel = GetValidQosLevel(fdp);
    QOS::SetThreadQos(initialLevel);
    
    // 快速切换到其他所有级别
    for (size_t i = 0; i < VALID_QOS_COUNT && fdp.remaining_bytes() > 0; i++) {
        QosLevel newLevel = GetValidQosLevel(fdp);
        QOS::SetThreadQos(newLevel);
        
        // 验证设置是否生效
        enum QosLevel currentLevel;
        QOS::GetThreadQos(currentLevel);
    }
    
    // 最后重置
    QOS::ResetThreadQos();
    
    return true;
}

// 测试4: 双重操作测试 - 测试重复操作
bool FuzzDoubleOperations(FuzzedDataProvider &fdp)
{
    QosLevel level = GetValidQosLevel(fdp);
    
    // 连续两次设置相同的 QoS
    QOS::SetThreadQos(level);
    QOS::SetThreadQos(level);
    
    // 连续两次重置
    QOS::ResetThreadQos();
    QOS::ResetThreadQos();
    
    // 连续两次 Leave
    QOS::SetThreadQos(level);
    QosLeave();
    QosLeave(); // 在未设置的情况下 Leave
    
    return true;
}

// 测试5: 未初始化状态测试
bool FuzzUninitializedState(FuzzedDataProvider &fdp)
{
    // 在没有设置 QoS 的情况下尝试各种操作
    
    // 尝试 Get（应该失败或返回默认值）
    enum QosLevel level;
    QOS::GetThreadQos(level);
    
    // 尝试 Reset（未设置就重置）
    QOS::ResetThreadQos();
    
    // 尝试 Leave（未设置就 Leave）
    QosLeave();
    
    return true;
}

// 测试6: 资源泄漏测试 - 大量快速调用
bool FuzzResourceLeak(FuzzedDataProvider &fdp)
{
    // 快速大量调用，测试文件描述符泄漏
    size_t iterations = fdp.ConsumeIntegralInRange<size_t>(100, 500);
    
    for (size_t i = 0; i < iterations && fdp.remaining_bytes() > 0; i++) {
        QosLevel level = GetValidQosLevel(fdp);
        int tid = GetThreadId(fdp);
        
        // 这些操作都会打开/关闭文件描述符
        QOS::SetQosForOtherThread(level, tid);
        
        enum QosLevel outLevel;
        QosController::GetInstance().GetThreadQosForOtherThread(outLevel, tid);
    }
    
    return true;
}

// 测试7: 竞态条件测试 - 多线程同时操作
bool FuzzRaceCondition(FuzzedDataProvider &fdp)
{
    int targetTid = gettid();
    size_t threadCount = fdp.ConsumeIntegralInRange<size_t>(2, 5);
    std::vector<std::thread> threads;
    
    constexpr size_t minBytesForThread = 4;
    constexpr int qosSetRepeat = 10;

    // 创建多个线程同时操作同一个线程的 QoS
    for (size_t i = 0; i < threadCount && fdp.remaining_bytes() > minBytesForThread; i++) {
        QosLevel level = GetValidQosLevel(fdp);
        threads.emplace_back([level, targetTid]() {
            for (int j = 0; j < qosSetRepeat; j++) {
                QOS::SetQosForOtherThread(level, targetTid);
                
                enum QosLevel outLevel;
                QosController::GetInstance().GetThreadQosForOtherThread(outLevel, targetTid);
            }
        });
    }
    
    // 等待所有线程完成
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    return true;
}

// 测试8: 操作序列测试 - 测试 Set->Get->Reset 完整流程
bool FuzzOperationSequence(FuzzedDataProvider &fdp)
{
    QosLevel level = GetValidQosLevel(fdp);
    int tid = GetThreadId(fdp);
    
    // 完整的操作序列
    // 1. Set
    (void)QOS::SetQosForOtherThread(level, tid);
    
    // 2. Get（验证设置）
    enum QosLevel getLevel;
    (void)QosController::GetInstance().GetThreadQosForOtherThread(getLevel, tid);
    
    // 3. 修改为另一个级别
    if (fdp.ConsumeBool()) {
        QosLevel newLevel = GetValidQosLevel(fdp);
        QOS::SetQosForOtherThread(newLevel, tid);
    }
    
    // 4. Reset
    (void)QosController::GetInstance().ResetThreadQosForOtherThread(tid);
    
    // 5. 再次 Get（应该失败或返回默认）
    (void)QosController::GetInstance().GetThreadQosForOtherThread(getLevel, tid);
    
    return true;
}


// 测试9: QosLeave vs ResetThreadQos 差异测试
bool FuzzLeaveVsReset(FuzzedDataProvider &fdp)
{
    QosLevel level = GetValidQosLevel(fdp);
    
    // 测试 QosLeave
    QOS::SetThreadQos(level);
    QosLeave();
    
    // 测试 ResetThreadQos
    QOS::SetThreadQos(level);
    QOS::ResetThreadQos();
    
    // 测试混合使用
    QOS::SetThreadQos(level);
    if (fdp.ConsumeBool()) {
        QosLeave();
    } else {
        QOS::ResetThreadQos();
    }
    
    return true;
}

enum FuzzStrategy : uint8_t {
    INVALID_QOS_LEVELS = 0,
    INVALID_THREAD_IDS,
    QOS_STATE_TRANSITIONS,
    DOUBLE_OPERATIONS,
    UNINITIALIZED_STATE,
    RESOURCE_LEAK,
    RACE_CONDITION,
    OPERATION_SEQUENCE,
    CROSS_THREAD_OPERATIONS,
    LEAVE_VS_RESET,
    QOS_CONTROLLER_GET_THREAD_QOS_FOR_OTHER_THREAD,
    QOS_INTERFACE_QOS_LEAVE,
    QOS_RESET_THREAD_QOS,
    QOS_SET_QOS_FOR_OTHER_THREAD,
    QOS_SET_THREAD_QOS,
    MAX_STRATEGY
};

static void DispatchFuzzStrategy(FuzzedDataProvider &fdp, uint8_t strategy)
{
    using FuzzFunc = bool(*)(FuzzedDataProvider &);

    static constexpr FuzzFunc kTable[] = {
        FuzzInvalidQosLevels,
        FuzzInvalidThreadIds,
        FuzzQosStateTransitions,
        FuzzDoubleOperations,
        FuzzUninitializedState,
        FuzzResourceLeak,
        FuzzRaceCondition,
        FuzzOperationSequence,
        FuzzLeaveVsReset
    };

    constexpr size_t count = sizeof(kTable) / sizeof(kTable[0]);
    size_t idx = strategy % count;

    FuzzFunc fn = kTable[idx];
    if (fn != nullptr) {
        fn(fdp);
    }
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    constexpr size_t kMinInputSize = 4;
    if (size < kMinInputSize) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    uint8_t strategy = fdp.ConsumeIntegral<uint8_t>();

    OHOS::DispatchFuzzStrategy(fdp, strategy);
    return 0;
}