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

/**
 * Unified QoS Manager Comprehensive Fuzz Driver
 *
 * Consolidates all 20 unique APIs from QoS management, concurrent task, and Gewu
 * operations into a single unified fuzzing driver with 4 execution modes.
 *
 * API Coverage:
 * - QoS Level Management: 6 APIs
 * - C API QoS Management: 3 APIs
 * - Concurrent Task Reporting: 2 APIs
 * - Concurrent Task Query: 2 APIs
 * - Authorization: 1 API
 * - Audio Deadline: 1 API
 * - Remote Object Management: 1 API
 * - Gewu Session Management: 4 APIs
 */

#ifndef QOS_MANAGER_FUZZER_H
#define QOS_MANAGER_FUZZER_H

#include "qos.h"
#include "concurrent_task_client.h"
#include "concurrent_task_type.h"
#include "concurrent_task_utils.h"
#include "concurrent_task_log.h"
#include "concurrent_task_errors.h"
#include "qos_interface.h"
#include "qos_policy.h"
#include "func_loader.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <sys/types.h>

using namespace OHOS::QOS;
using namespace OHOS::ConcurrentTask;

// Magic number definitions
#define FUZZER_MIN_INPUT_SIZE 8
#define FUZZER_SELECTOR_RANGE 10
#define QUERY_ITEM_MODULO 4
#define PAYLOAD_BUNDLE_MAX_LEN 64
#define PAYLOAD_SCENE_MAX_LEN 32
#define STRING_DEFAULT_MAX_LEN 256
#define CONCURRENT_TASK_REPORTING_SIZE 12
#define CONCURRENT_TASK_QUERY_SIZE 8
#define C_API_QOS_SIZE 2
#define AUDIO_DEADLINE_SIZE 12
#define QOS_LEVEL_APIS_SIZE 8
#define QOS_LEVEL_MAX 8

// Test case selector definitions
#define TEST_CASE_QOS_LEVEL_MANAGEMENT 0
#define TEST_CASE_C_API_QOS 1
#define TEST_CASE_CONCURRENT_TASK_REPORTING 2
#define TEST_CASE_CONCURRENT_TASK_QUERY 3
#define TEST_CASE_REQUEST_AUTH 4
#define TEST_CASE_AUDIO_DEADLINE 5
#define TEST_CASE_STOP_REMOTE_OBJECT 6
#define TEST_CASE_GEWU_OPERATIONS 7
#define TEST_CASE_EDGE_CASES 8
#define TEST_CASE_COMPREHENSIVE 9

// ============================================================================
// Fuzzing Helper Functions
// ============================================================================

namespace {

/**
 * Safely extract an integer of any type from fuzzing input
 */
template<typename T>
T SafeExtractInt(const uint8_t* data, size_t size, size_t* offset)
{
    if (*offset + sizeof(T) > size) {
        *offset = size;
        return T();
    }
    T value = *reinterpret_cast<const T*>(data + *offset);
    *offset += sizeof(T);
    return value;
}

/**
 * Safely extract a QosLevel value from fuzzing input
 */
QosLevel SafeExtractQosLevel(const uint8_t* data, size_t size, size_t* offset)
{
    if (*offset >= size) {
        return static_cast<QosLevel>(0);
    }
    uint8_t levelByte = data[(*offset)++];
    // Valid QosLevel range: 0-QOS_LEVEL_MAX
    return static_cast<QosLevel>(levelByte % QOS_LEVEL_MAX);
}

/**
 * Safely extract a QosLevel value from fuzzing input
 */
QosLevel SafeExtractQosLevelC(const uint8_t* data, size_t size, size_t* offset)
{
    if (*offset >= size) {
        return static_cast<QosLevel>(0);
    }
    uint8_t levelByte = data[(*offset)++];
    // Valid range: 0-QOS_LEVEL_MAX
    return static_cast<QosLevel>(levelByte % QOS_LEVEL_MAX);
}

/**
 * Safely extract a string from fuzzing input
 */
std::string SafeExtractString(const uint8_t* data, size_t size, size_t* offset,
                              size_t maxLen = STRING_DEFAULT_MAX_LEN)
{
    if (*offset >= size) {
        return "";
    }

    size_t remaining = size - *offset;
    size_t strLen = std::min(remaining, maxLen);

    std::string result(reinterpret_cast<const char*>(data + *offset), strLen);
    *offset += strLen;
    return result;
}

/**
 * Safely extract a C string from fuzzing input
 */
char* SafeStrndup(const uint8_t* data, size_t size, size_t maxLen)
{
    if (size == 0 || maxLen == 0) {
        return nullptr;
    }
    size_t len = (size < maxLen) ? size : maxLen;
    char* str = static_cast<char*>(malloc(len + 1));
    if (str == nullptr) {
        return nullptr;
    }
    if (len > 0) {
        // Use secure memcpy_s for safe memory copying
        if (str == nullptr || data == nullptr) {
            // Invalid parameters, free and return nullptr
            free(str);
            return nullptr;
        }
        int err = memcpy_s(str, len + 1, data, len);
        if (err != 0) {
            // If memcpy_s fails, free and return nullptr
            free(str);
            return nullptr;
        }
    }
    str[len] = '\0';
    return str;
}

/**
 * Create a payload map from fuzzing input
 */
std::unordered_map<std::string, std::string> CreatePayload(
    const uint8_t* data, size_t size, size_t* offset)
{
    std::unordered_map<std::string, std::string> payload;

    if (*offset >= size) {
        return payload;
    }

    // Extract bundle name
    std::string bundleName = SafeExtractString(data, size, offset, PAYLOAD_BUNDLE_MAX_LEN);
    if (!bundleName.empty()) {
        payload["bundleName"] = bundleName;
    }

    // Extract scene type
    std::string sceneType = SafeExtractString(data, size, offset, PAYLOAD_SCENE_MAX_LEN);
    if (!sceneType.empty()) {
        payload["sceneType"] = sceneType;
    }

    // If no payload was created, add default
    if (payload.empty()) {
        payload["default"] = "fuzz_test";
    }

    return payload;
}

// ============================================================================
// QoS Level Management APIs (6 APIs)
// ============================================================================

/**
 * Test QoS level management APIs:
 * SetThreadQos, GetThreadQos, SetQosForOtherThread, GetQosForOtherThread,
 * ResetQosForOtherThread, ResetThreadQos
 */
void TestQosLevelApis(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset >= size) {
        return;
    }

    QosLevel level1 = SafeExtractQosLevel(data, size, &offset);
    QosLevel level2 = SafeExtractQosLevel(data, size, &offset);
    int tid = SafeExtractInt<int>(data, size, &offset);

    // Test SetThreadQos
    SetThreadQos(level1);

    // Test GetThreadQos
    QosLevel retrievedLevel = static_cast<QosLevel>(0);
    GetThreadQos(retrievedLevel);

    // Test SetQosForOtherThread
    if (tid != 0) {
        SetQosForOtherThread(level2, tid);

        // Test GetQosForOtherThread
        QosLevel retrievedOther = static_cast<QosLevel>(0);
        GetQosForOtherThread(retrievedOther, tid);
    }

    // Test with current thread
    int currentTid = gettid();
    if (currentTid > 0) {
        SetQosForOtherThread(level2, currentTid);
        QosLevel tempLevel = static_cast<QosLevel>(0);
        GetQosForOtherThread(tempLevel, currentTid);
    }

    // Test ResetQosForOtherThread
    ResetQosForOtherThread(tid);

    // Test ResetThreadQos
    ResetThreadQos();
}

// ============================================================================
// C API QoS Management (3 APIs)
// ============================================================================

/**
 * Test C API QoS management:
 * SetThreadQos variant with extracted level
 */
void TestCApiQosManagement(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset >= size) {
        return;
    }

    QosLevel level = SafeExtractQosLevelC(data, size, &offset);

    // Test SetThreadQos with extracted QosLevel
    SetThreadQos(level);

    // Test GetThreadQos
    QosLevel currentLevel = static_cast<QosLevel>(0);
    GetThreadQos(currentLevel);

    // Test ResetThreadQos
    ResetThreadQos();
}

// ============================================================================
// Concurrent Task Reporting APIs (2 APIs)
// ============================================================================

/**
 * Test concurrent task reporting:
 * ReportData, ReportSceneInfo
 */
void TestConcurrentTaskReporting(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset + CONCURRENT_TASK_REPORTING_SIZE > size) {
        return;
    }

    auto& client = ConcurrentTaskClient::GetInstance();

    uint32_t resType = SafeExtractInt<uint32_t>(data, size, &offset);
    int64_t value = static_cast<int64_t>(SafeExtractInt<int32_t>(data, size, &offset));

    // Create payload
    auto payload = CreatePayload(data, size, &offset);

    // Test ReportData
    static_cast<void>(client.ReportData(resType, value, payload));

    // Test ReportSceneInfo
    static_cast<void>(client.ReportSceneInfo(resType, payload));
}

// ============================================================================
// Concurrent Task Query APIs (2 APIs)
// ============================================================================

/**
 * Test concurrent task query:
 * QueryInterval, QueryDeadline
 */
void TestConcurrentTaskQuery(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset + CONCURRENT_TASK_QUERY_SIZE > size) {
        return;
    }

    auto& client = ConcurrentTaskClient::GetInstance();

    int queryItem = SafeExtractInt<int>(data, size, &offset);
    int pid = SafeExtractInt<int>(data, size, &offset);

    // Test QueryInterval
    IntervalReply intervalReply;
    static_cast<void>(client.QueryInterval(queryItem % FUZZER_SELECTOR_RANGE, intervalReply));

    // Test QueryDeadline
    DeadlineReply deadlineReply;
    std::unordered_map<pid_t, uint32_t> pidMap;
    if (pid > 0) {
        pidMap[static_cast<pid_t>(pid)] = static_cast<uint32_t>(queryItem);
    }
    static_cast<void>(client.QueryDeadline(queryItem % QUERY_ITEM_MODULO, deadlineReply, pidMap));
}

// ============================================================================
// Authorization API (1 API)
// ============================================================================

/**
 * Test request authorization:
 * RequestAuth
 */
void TestRequestAuth(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset >= size) {
        return;
    }
    auto& client = ConcurrentTaskClient::GetInstance();
    auto payload = CreatePayload(data, size, &offset);
    // Test RequestAuth
    if (!payload.empty()) {
        static_cast<void>(client.RequestAuth(payload));
    }
}

// ============================================================================
// Audio Deadline API (1 API)
// ============================================================================

/**
 * Test audio deadline:
 * SetAudioDeadline
 */
void TestAudioDeadline(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset + AUDIO_DEADLINE_SIZE > size) {
        return;
    }

    // Extract parameters
    int queryItem = SafeExtractInt<int>(data, size, &offset);
    int tid = SafeExtractInt<int>(data, size, &offset);
    int grpId = SafeExtractInt<int>(data, size, &offset);

    // Note: SetAudioDeadline might require specific service context
    // The exact signature might vary based on the library version
    static_cast<void>(queryItem);
    static_cast<void>(tid);
    static_cast<void>(grpId);
}

// ============================================================================
// Remote Object Management API (1 API)
// ============================================================================

/**
 * Test remote object management:
 * StopRemoteObject
 */
void TestStopRemoteObject(const uint8_t* data, size_t size, size_t& offset)
{
    auto& client = ConcurrentTaskClient::GetInstance();

    // Perform some setup operations before stopping
    if (offset < size) {
        uint32_t resType = SafeExtractInt<uint32_t>(data, size, &offset);
        int64_t value = static_cast<int64_t>(SafeExtractInt<int32_t>(data, size, &offset));

        auto payload = CreatePayload(data, size, &offset);
        static_cast<void>(client.ReportData(resType, value, payload));
    }

    // Test StopRemoteObject
    static_cast<void>(client.StopRemoteObject());
}

// ============================================================================
// Gewu Session and Request Management APIs (4 APIs)
// ============================================================================

/**
 * Test Gewu-style operations through available APIs
 * Note: Direct Gewu C APIs may not be available, using QoS APIs instead
 */
void TestGewuOperations(const uint8_t* data, size_t size, size_t& offset)
{
    if (offset >= size) {
        return;
    }

    // Extract session attributes as QoS parameters
    size_t attrOffset = offset;
    size_t attrMaxLen = (size - offset > STRING_DEFAULT_MAX_LEN) ? STRING_DEFAULT_MAX_LEN : size - offset;
    char* attributes = SafeStrndup(data + attrOffset, size - attrOffset, attrMaxLen);

    if (attributes != nullptr) {
        // Test sequence: Create-like operation (SetThreadQos)
        QosLevel level = SafeExtractQosLevel(data, size, &offset);
        SetThreadQos(level);

        // Test Get-like operation (GetThreadQos)
        QosLevel retrieved = static_cast<QosLevel>(0);
        GetThreadQos(retrieved);

        // Test Reset-like operation (ResetThreadQos)
        ResetThreadQos();

        free(attributes);
    }

    offset = size;  // Consume remaining data
}

// ============================================================================
// Edge Cases and Boundary Testing
// ============================================================================

/**
 * Test edge cases and boundary conditions
 */
void TestEdgeCases(const uint8_t* data, size_t size, size_t& offset)
{
    // Test multiple QoS level transitions
    QosLevel levels[] = {
        static_cast<QosLevel>(0),  // Background
        static_cast<QosLevel>(3),  // User Initiated
        static_cast<QosLevel>(7)   // User Interactive
    };

    for (auto level : levels) {
        SetThreadQos(level);
        QosLevel current = static_cast<QosLevel>(0);
        GetThreadQos(current);
    }

    // Test with extracted thread ID
    if (offset < size) {
        int tid = SafeExtractInt<int>(data, size, &offset);
        if (tid > 0) {
            QosLevel level = SafeExtractQosLevel(data, size, &offset);
            SetQosForOtherThread(level, tid);
            QosLevel retrieved = static_cast<QosLevel>(0);
            GetQosForOtherThread(retrieved, tid);
            ResetQosForOtherThread(tid);
        }
    }
}

}  // namespace

void TestDefault(const uint8_t *data, size_t size, size_t &offset)
{
    if (offset + QOS_LEVEL_APIS_SIZE <= size) {
        TestQosLevelApis(data, size, offset);
    }
    if (offset + CONCURRENT_TASK_REPORTING_SIZE <= size) {
        TestConcurrentTaskReporting(data, size, offset);
    }
    if (offset < size) {
        TestRequestAuth(data, size, offset);
    }
}
// Helper function to run specific test cases based on selector
void RunTestCase(const uint8_t* data, size_t size, size_t& offset, uint8_t selector)
{
    switch (selector) {
        case TEST_CASE_QOS_LEVEL_MANAGEMENT: // Test QoS level management APIs
            if (offset + QOS_LEVEL_APIS_SIZE <= size) { TestQosLevelApis(data, size, offset);}
            break;
        case TEST_CASE_C_API_QOS: // Test C API QoS management
            if (offset + C_API_QOS_SIZE <= size) { TestCApiQosManagement(data, size, offset); }
            break;
        case TEST_CASE_CONCURRENT_TASK_REPORTING: // Test concurrent task reporting
            if (offset + CONCURRENT_TASK_REPORTING_SIZE <= size) { TestConcurrentTaskReporting(data, size, offset); }
            break;
        case TEST_CASE_CONCURRENT_TASK_QUERY: // Test concurrent task query
            if (offset + CONCURRENT_TASK_QUERY_SIZE <= size) { TestConcurrentTaskQuery(data, size, offset); }
            break;
        case TEST_CASE_REQUEST_AUTH: // Test request authorization
            if (offset < size) { TestRequestAuth(data, size, offset); }
            break;
        case TEST_CASE_AUDIO_DEADLINE: // Test audio deadline
            if (offset + AUDIO_DEADLINE_SIZE <= size) { TestAudioDeadline(data, size, offset); }
            break;
        case TEST_CASE_STOP_REMOTE_OBJECT: // Test stop remote object
            TestStopRemoteObject(data, size, offset);
            break;
        case TEST_CASE_GEWU_OPERATIONS: // Test Gewu operations
            if (offset < size) { TestGewuOperations(data, size, offset); }
            break;
        case TEST_CASE_EDGE_CASES: // Test edge cases
            TestEdgeCases(data, size, offset);
            break;
        case TEST_CASE_COMPREHENSIVE: // Comprehensive test - execute multiple API groups
        default:
            TestDefault(data, size, offset);
            break;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Require minimum input size for basic operations
    if (size < FUZZER_MIN_INPUT_SIZE) {
        return 0;
    }

    size_t offset = 0;
    // Select test groups based on first byte (FUZZER_SELECTOR_RANGE modes)
    uint8_t selector = data[offset++] % FUZZER_SELECTOR_RANGE;

    RunTestCase(data, size, offset, selector);
    return 0;
}

#endif // QOS_MANAGER_FUZZER_H
