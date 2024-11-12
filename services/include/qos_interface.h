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

#ifndef QOS_INTERFACE_H
#define QOS_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * generic
 */
constexpr int SYSTEM_UID = 1000;
constexpr int ROOT_UID = 0;
constexpr int NR_QOS = 7;
constexpr unsigned int SET_RTG_ENABLE = 1;
constexpr unsigned int QOS_CTRL_IPC_MAGIC = 0xCC;
constexpr unsigned int RTG_SCHED_IPC_MAGIC = 0xAB;

constexpr unsigned int AF_QOS_ALL = 0x0003;
constexpr unsigned int AF_QOS_DELEGATED = 0x0001;

/*
 * qos ctrl
 */
enum class QosManipulateType {
    QOS_APPLY = 1,
    QOS_LEAVE,
    QOS_GET,
    QOS_MAX_NR,
};

struct QosCtrlData {
    int pid;
    unsigned int type;
    unsigned int level;
    int qos;
#ifdef QOS_EXT_ENABLE
    int staticQos;
    int dynamicQos;
    bool tagSchedEnable = false;
#endif
};

struct QosPolicyData {
    int nice;
    int latencyNice;
    int uclampMin;
    int uclampMax;
    int rtSchedPriority;
    int policy;
};

enum SchedPolicy {
    SCHED_POLICY_OTHER = 0,
    SCHED_POLICY_FIFO = 1,
    SCHED_POLICY_RR = 2,
    SCHED_POLICY_RT_EX = 0xFF,
};

enum QosPolicyType {
    QOS_POLICY_DEFAULT = 1,
    QOS_POLICY_SYSTEM_SERVER = 2,
    QOS_POLICY_FRONT = 3,
    QOS_POLICY_BACK = 4,
    QOS_POLICY_FOCUS = 5,
    QOS_POLICY_MAX_NR,
};

#define QOS_FLAG_NICE               0X01
#define QOS_FLAG_LATENCY_NICE       0X02
#define QOS_FLAG_UCLAMP             0x04
#define QOS_FLAG_RT                 0x08

#define QOS_FLAG_ALL    (QOS_FLAG_NICE          | \
            QOS_FLAG_LATENCY_NICE       | \
            QOS_FLAG_UCLAMP     | \
            QOS_FLAG_RT)

#define SCHED_RESET_ON_FORK         0x40000000

struct QosPolicyDatas {
    int policyType;
    unsigned int policyFlag;
    struct QosPolicyData policys[NR_QOS];
};

enum QosCtrlCmdid {
    QOS_CTRL = 1,
    QOS_POLICY = 2,
    QOS_CTRL_MAX_NR
};

#define QOS_CTRL_BASIC_OPERATION \
    _IOWR(QOS_CTRL_IPC_MAGIC, QOS_CTRL, struct QosCtrlData)
#define QOS_CTRL_POLICY_OPERATION \
    _IOWR(QOS_CTRL_IPC_MAGIC, QOS_POLICY, struct QosPolicyDatas)

struct RtgEnableData {
    int enable;
    int len;
    char *data;
};

#define CMD_ID_SET_ENABLE \
    _IOWR(RTG_SCHED_IPC_MAGIC, SET_RTG_ENABLE, struct RtgEnableData)

/*
 * interface
 */
int EnableRtg(bool flag);
int QosApply(unsigned int level);
int QosApplyForOther(unsigned int level, int tid);
int QosLeave(void);
int QosLeaveForOther(int tid);
int QosPolicySet(const struct QosPolicyDatas *policyDatas);
int QosGet(int &level);
int QosGetForOther(int tid, int &level);

#ifdef __cplusplus
}
#endif
#endif /* OQS_INTERFACE_H */
