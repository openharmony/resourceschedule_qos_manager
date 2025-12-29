/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <array>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <fuzzer/FuzzedDataProvider.h>

#include "concurrent_task_client.h"
#include "concurrent_task_controller_interface.h"
#include "concurrent_task_service.h"
#include "concurrent_task_service_ability.h"
#include "func_loader.h"
#include "message_option.h"
#include "message_parcel.h"
#include "qos.h"
#include "qos_interface.h"
#include "qos_policy.h"

using namespace OHOS::ConcurrentTask;
using namespace OHOS::QOS;

namespace OHOS {
namespace QOS {
int AddThreadsToProcRtg(int tid[], int size);
} // namespace QOS
} // namespace OHOS

namespace OHOS {
namespace {
constexpr size_t MIN_FUZZ_BYTES = 4;
constexpr int MAX_QOS_LEVEL = static_cast<int>(QosLevel::QOS_MAX);
constexpr int MAX_DISPATCH_INDEX = 8;
constexpr int MAX_TID_RANGE = 4096;
constexpr int RT_PRIORITY_LIMIT = 128;
constexpr int MAX_IPC_STRING = 32;
constexpr int MAX_PAYLOAD_STRING = 64;
constexpr int MIN_IPC_BYTES = 8;
constexpr int SA_TEST_ID = 5204; // arbitrary system ability id for fuzzing
constexpr size_t PROC_RTG_TID_COUNT = 5;
constexpr size_t MAX_FUZZ_SHORT_STRING_LENGTH = 8;

enum class QosOp : int {
    CONTROLLER = 0,
    RAW_INTERFACE,
    POLICY_SET,
    RTG_ENABLE,
    PROC_RTG,
    CLIENT_API,
    SERVICE_IPC,
    FUNC_LOADER,
    TASK_CONTROLLER,
};
} // namespace

static QosLevel ConsumeQosLevel(FuzzedDataProvider &fdp)
{
    int rawLevel = fdp.ConsumeIntegralInRange<int>(-1, MAX_QOS_LEVEL + 1);
    return static_cast<QosLevel>(rawLevel);
}

static int ConsumeTid(FuzzedDataProvider &fdp)
{
    return fdp.ConsumeIntegralInRange<int>(-MAX_TID_RANGE, MAX_TID_RANGE);
}

static void ExerciseQosController(FuzzedDataProvider &fdp)
{
    QosLevel level = ConsumeQosLevel(fdp);
    int tid = ConsumeTid(fdp);

    QosController::GetInstance().SetThreadQosForOtherThread(level, tid);
    QosController::GetInstance().GetThreadQosForOtherThread(level, tid);
    QosController::GetInstance().ResetThreadQosForOtherThread(tid);

    SetThreadQos(level);
    SetQosForOtherThread(level, tid);
    ResetThreadQos();
    ResetQosForOtherThread(tid);
    GetThreadQos(level);
    GetQosForOtherThread(level, tid);
}

static void ExerciseQosInterface(FuzzedDataProvider &fdp)
{
    unsigned int rawLevel = fdp.ConsumeIntegral<unsigned int>();
    int tid = ConsumeTid(fdp);
    bool enableRtg = fdp.ConsumeBool();

    EnableRtg(enableRtg);
    QosApply(rawLevel);
    QosApplyForOther(rawLevel, tid);
    QosLeave();
    QosLeaveForOther(tid);

    int queriedLevel = -1;
    QosGet(queriedLevel);
    QosGetForOther(tid, queriedLevel);
}

static void PopulatePolicyEntry(QosPolicyData &entry, FuzzedDataProvider &fdp)
{
    entry.nice = fdp.ConsumeIntegral<int>();
    entry.latencyNice = fdp.ConsumeIntegral<int>();
    entry.uclampMin = fdp.ConsumeIntegral<int>();
    entry.uclampMax = fdp.ConsumeIntegral<int>();
    entry.rtSchedPriority = fdp.ConsumeIntegralInRange<int>(-RT_PRIORITY_LIMIT, RT_PRIORITY_LIMIT);
    entry.policy = fdp.PickValueInArray({
        SchedPolicy::SCHED_POLICY_OTHER,
        SchedPolicy::SCHED_POLICY_FIFO,
        SchedPolicy::SCHED_POLICY_RR,
        SchedPolicy::SCHED_POLICY_RT_EX,
    });
}

static void ExerciseQosPolicy(FuzzedDataProvider &fdp)
{
    QosPolicyDatas policyDatas {};
    policyDatas.policyType = fdp.ConsumeIntegral<int>();
    policyDatas.policyFlag = fdp.ConsumeIntegral<unsigned int>();

    for (int i = 0; i < NR_QOS; i++) {
        PopulatePolicyEntry(policyDatas.policys[i], fdp);
    }

    QosPolicy policyClient;
    policyClient.SetQosPolicy(&policyDatas);
}

static void ExerciseProcRtg(FuzzedDataProvider &fdp)
{
    int tid = ConsumeTid(fdp);
    std::array<int, PROC_RTG_TID_COUNT> tids {};
    for (auto &item : tids) {
        item = ConsumeTid(fdp);
    }

    AddThreadToProcRtg(tid);
    AddThreadsToProcRtg(tids.data(), static_cast<int>(tids.size()));
    RemoveThreadFromProcRtg(tid);
    RemoveThreadsFromProcRtg(tids.data(), static_cast<int>(tids.size()));
}

static std::unordered_map<std::string, std::string> BuildStringPayload(FuzzedDataProvider &fdp)
{
    std::unordered_map<std::string, std::string> payload;
    payload["k"] = fdp.ConsumeRandomLengthString(MAX_PAYLOAD_STRING);
    payload[fdp.ConsumeRandomLengthString(MAX_FUZZ_SHORT_STRING_LENGTH)] =
        fdp.ConsumeRandomLengthString(MAX_PAYLOAD_STRING);
    return payload;
}

static std::unordered_map<pid_t, uint32_t> BuildPidPayload(FuzzedDataProvider &fdp)
{
    std::unordered_map<pid_t, uint32_t> payload;
    payload[fdp.ConsumeIntegral<pid_t>()] = fdp.ConsumeIntegral<uint32_t>();
    return payload;
}

static void ExerciseClientApi(FuzzedDataProvider &fdp)
{
    ConcurrentTaskClient &client = ConcurrentTaskClient::GetInstance();
    auto payload = BuildStringPayload(fdp);
    IntervalReply intervalReply;
    DeadlineReply deadlineReply;

    client.ReportData(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<int64_t>(), payload);
    client.ReportSceneInfo(fdp.ConsumeIntegral<uint32_t>(), payload);
    client.QueryInterval(fdp.ConsumeIntegral<int>(), intervalReply);
    client.QueryDeadline(fdp.ConsumeIntegral<int>(), deadlineReply, BuildPidPayload(fdp));
    client.QueryDeadline(fdp.ConsumeIntegral<int>(), deadlineReply, BuildStringPayload(fdp));
    client.SetAudioDeadline(fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>(),
        intervalReply);
    client.RequestAuth(payload);
    client.SetSystemQoS(fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>());
    client.StopRemoteObject();
    client.ReportSceneInfo(fdp.ConsumeIntegral<uint32_t>(), payload); // trigger post-stop path
}

static void ExerciseServiceIpc(FuzzedDataProvider &fdp)
{
    if (fdp.remaining_bytes() < MIN_IPC_BYTES) {
        return;
    }
    static const uint32_t kCodes[] = {
        0, 1, 2, 3, 4, 5
    };

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    data.WriteString(fdp.ConsumeRandomLengthString(MAX_IPC_STRING));

    uint32_t code = fdp.PickValueInArray(kCodes);
    ConcurrentTaskService service;
    service.OnRemoteRequest(code, data, reply, option);
}

static void ExerciseFuncLoader(FuzzedDataProvider &fdp)
{
    std::string path = fdp.ConsumeRandomLengthString(MAX_IPC_STRING);
    FuncLoader loader(path);
    loader.LoadSymbol(fdp.ConsumeRandomLengthString(MAX_FUZZ_SHORT_STRING_LENGTH).c_str());
    loader.LoadSymbol("");
    loader.LoadSymbol("nonexistent_symbol");
    loader.GetLoadSuccess();
}

static void ExerciseServiceDirect(FuzzedDataProvider &fdp)
{
    ConcurrentTaskService svc;
    auto payload = BuildStringPayload(fdp);
    IpcIntervalReply ipcInterval {};
    IpcDeadlineReply ipcDdl {};

    svc.ReportData(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<int64_t>(), payload);
    svc.ReportSceneInfo(fdp.ConsumeIntegral<uint32_t>(), payload);
    svc.QueryInterval(fdp.ConsumeIntegral<int>(), ipcInterval);
    svc.QueryDeadline(fdp.ConsumeIntegral<int>(), ipcDdl, payload);
    svc.SetAudioDeadline(
        fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>(), ipcInterval);
    svc.RequestAuth(payload);
}

static void ExerciseServiceAbility(FuzzedDataProvider &fdp)
{
    ConcurrentTaskServiceAbility ability(SA_TEST_ID, fdp.ConsumeBool());
    ability.FuzzOnStart();
    ability.FuzzOnAddSystemAbility(
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeRandomLengthString(MAX_FUZZ_SHORT_STRING_LENGTH));
    ability.FuzzOnRemoveSystemAbility(
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeRandomLengthString(MAX_FUZZ_SHORT_STRING_LENGTH));
    ability.GetClassName();
    if (fdp.ConsumeBool()) {
        ability.FuzzOnStart(); // repeat to trigger duplicate start branch
    }
    ability.FuzzOnStop();
}

static void ExerciseTaskController(FuzzedDataProvider &fdp)
{
    TaskControllerInterface &controller = TaskControllerInterface::GetInstance();
    controller.Init();

    auto payload = BuildStringPayload(fdp);
    IntervalReply intervalReply;
    DeadlineReply ddlReply;

    controller.ReportData(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<int64_t>(), payload);
    controller.ReportSceneInfo(fdp.ConsumeIntegral<uint32_t>(), payload);
    controller.QueryInterval(fdp.ConsumeIntegral<int>(), intervalReply);
    controller.QueryDeadline(fdp.ConsumeIntegral<int>(), ddlReply, payload);
    controller.SetAudioDeadline(
        fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>(), intervalReply);
    controller.RequestAuth(payload);
    controller.Release();
    controller.ReportData(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<int64_t>(), payload);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_FUZZ_BYTES) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    QosPolicy policyInitializer;
    policyInitializer.Init();

    while (fdp.remaining_bytes() > 0) {
        int op = fdp.ConsumeIntegralInRange<int>(0, MAX_DISPATCH_INDEX);
        switch (static_cast<QosOp>(op)) {
            case QosOp::CONTROLLER:
                ExerciseQosController(fdp);
                break;
            case QosOp::RAW_INTERFACE:
                ExerciseQosInterface(fdp);
                break;
            case QosOp::POLICY_SET:
                ExerciseQosPolicy(fdp);
                break;
            case QosOp::RTG_ENABLE:
                EnableRtg(fdp.ConsumeBool());
                break;
            case QosOp::PROC_RTG:
                ExerciseProcRtg(fdp);
                break;
            case QosOp::CLIENT_API:
                ExerciseClientApi(fdp);
                break;
            case QosOp::SERVICE_IPC:
                ExerciseServiceIpc(fdp);
                break;
            case QosOp::FUNC_LOADER:
                ExerciseFuncLoader(fdp);
                break;
            case QosOp::TASK_CONTROLLER:
                ExerciseTaskController(fdp);
                ExerciseServiceDirect(fdp);
                ExerciseServiceAbility(fdp);
                break;
            default:
                break;
        }
    }
    return 0;
}
} // namespace OHOS
