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
#define SYSTEM_UID 1000
#define ROOT_UID 0

/*
 * auth_ctrl
 */
struct AuthCtrlData {
    unsigned int uid;
    unsigned int type;
    unsigned int rtgUaFlag;
    unsigned int qosUaFlag;
    unsigned int status;
};

enum class AuthManipulateType {
    AUTH_ENABLE = 1,
    AUTH_DELETE,
    AUTH_GET,
    AUTH_SWITCH,
    AUTH_MAX_NR,
};

enum class AuthStatus {
    AUTH_STATUS_DISABLED = 1,
    AUTH_STATUS_SYSTEM_SERVER = 2,
    AUTH_STATUS_FOREGROUND = 3,
    AUTH_STATUS_BACKGROUND = 4,
    AUTH_STATUS_DEAD,
};

enum class QosClassLevel {
    QOS_UNSPECIFIED = 0,
    QOS_BACKGROUND = 1,
    QOS_UTILITY = 2,
    QOS_DEFAULT = 3,
    QOS_USER_INITIATED = 4,
    QOS_DEADLINE_REQUEST = 5,
    QOS_USER_INTERACTIVE = 6,
    QOS_MAX,
};

#define BASIC_AUTH_CTRL_OPERATION \
    _IOWR(0xCD, 1, struct AuthCtrlData)

/*
 * qos ctrl
 */
enum class QosManipulateType {
    QOS_APPLY = 1,
    QOS_LEAVE,
    QOS_MAX_NR,
};

struct QosCtrlData {
    int pid;
    unsigned int type;
    unsigned int level;
};

struct QosPolicyData {
    int nice;
    int latencyNice;
    int uclampMin;
    int uclampMax;
    int rtSchedPriority;
};

enum class QosPolicyType {
    QOS_POLICY_DEFAULT = 1,
    QOS_POLICY_SYSTEM_SERVER = 2,
    QOS_POLICY_FRONT = 3,
    QOS_POLICY_BACK = 4,
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

struct QosPolicyDatas {
    int policyType;
    unsigned int policyFlag;
    struct QosPolicyData policys[static_cast<int>(QosClassLevel::QOS_MAX)];
};

#define QOS_CTRL_BASIC_OPERATION \
    _IOWR(0xCC, 1, struct QosCtrlData)
#define QOS_CTRL_POLICY_OPERATION \
    _IOWR(0xCC, 2, struct QosPolicyDatas)

/*
 * RTG
 */
#define AF_RTG_ALL          0x1fff
#define AF_RTG_DELEGATED    0x1fff

struct RtgEnableData {
    int enable;
    int len;
    char *data;
};

#define CMD_ID_SET_ENABLE \
    _IOWR(0xAB, 1, struct RtgEnableData)

/*
 * interface
 */
int EnableRtg(bool flag);
int AuthEnable(unsigned int uid, unsigned int uaFlag, unsigned int status);
int AuthPause(unsigned int uid);
int AuthDelete(unsigned int uid);
int AuthGet(unsigned int uid, unsigned int *uaFlag, unsigned int *status);
int AuthSwitch(unsigned int uid, unsigned int rtgFlag, unsigned int qosFlag, unsigned int status);
int QosApply(unsigned int level);
int QosApplyForOther(unsigned int level, int tid);
int QosLeave(void);
int QosLeaveForOther(int tid);
int QosPolicy(struct QosPolicyDatas *policyDatas);

#ifdef __cplusplus
}
#endif
#endif /* OQS_INTERFACE_H */