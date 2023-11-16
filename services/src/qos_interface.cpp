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

#ifndef GNU_SOURCE
#define GNU_SOURCE
#endif
#include <cstdio>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "../include/qos_interface.h"

static int TrivalOpenRtgNode(void)
{
    char fileName[] = "/proc/self/sched_rtg_ctrl";
    int fd = open(fileName, O_RDWR);
#ifdef QOS_DEBUG
    if (fd < 0) {
        printf("task %d belong to user %d open rtg node failed\n", getpid(), getuid());
    }
#endif
    return fd;
}

static int TrivalOpenAuthCtrlNode(void)
{
    char fileName[] = "/dev/auth_ctrl";
    int fd = open(fileName, O_RDWR);
#ifdef QOS_DEBUG
    if (fd < 0) {
        printf("task %d belong to user %d open auth node failed\n", getpid(), getuid());
    }
#endif
    return fd;
}

static int TrivalOpenQosCtrlNode(void)
{
    char fileName[] = "/proc/thread-self/sched_qos_ctrl";
    int fd = open(fileName, O_RDWR);
#ifdef QOS_DEBUG
    if (fd < 0) {
        printf("task %d belong to user %d open qos node failed\n", getpid(), getuid());
    }
#endif
    return fd;
}

int EnableRtg(bool flag)
{
    struct RtgEnableData enableData;
    char configStr[] = "load_freq_switch:1;sched_cycle:1;frame_max_util:1024";
    int ret;

    enableData.enable = flag;
    enableData.len = sizeof(configStr);
    enableData.data = configStr;
    int fd = TrivalOpenRtgNode();
    if (fd < 0) {
        return fd;
    }

    ret = ioctl(fd, CMD_ID_SET_ENABLE, &enableData);
    if (ret < 0) {
        printf("set rtg config enable failed.\n");
    }

    close(fd);

    return 0;
};

int AuthEnable(unsigned int pid, unsigned int uaFlag, unsigned int status)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.pid = pid;
    data.rtgUaFlag = uaFlag;
    data.qosUaFlag = AF_QOS_ALL;
    data.status = status;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_ENABLE);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth enable failed for pid %u with status %u\n", pid, status);
    }
#endif
    close(fd);
    return ret;
}

int AuthSwitch(unsigned int pid, unsigned int rtgFlag, unsigned int qosFlag, unsigned int status)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.pid = pid;
    data.rtgUaFlag = rtgFlag;
    data.qosUaFlag = qosFlag;
    data.status = status;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_SWITCH);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth switch failed for pid %u with status %u\n", pid, status);
    }
#endif
    close(fd);
    return ret;
}

int AuthDelete(unsigned int pid)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.pid = pid;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_DELETE);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth delete failed for pid %u\n", pid);
    }
#endif
    close(fd);
    return ret;
}

int AuthPause(unsigned int pid)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.pid = pid;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_SWITCH);
    data.rtgUaFlag = 0;
    data.qosUaFlag = AF_QOS_DELEGATED;
    data.status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_BACKGROUND);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth pause failed for pid %u\n", pid);
    }
#endif
    close(fd);
    return ret;
}

int AuthGet(unsigned int pid)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.pid = pid;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_GET);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
    if (ret < 0) {
        return ret;
    }
    close(fd);

    return static_cast<int>(data.status);
}

int AuthEnhance(unsigned int pid, bool enhanceStatus)
{
    int ret = 0;
#ifdef QOS_EXT_ENABLE
    struct AuthCtrlData data;
    int fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.pid = pid;
    data.enhanceStatus = enhanceStatus;
    ret = ioctl(fd, ENHANCE_AUTH_CTRL_OPERATION, &data);
    close(fd);
#endif
    return ret;
}

int QosApply(unsigned int level)
{
    int tid = gettid();
    int ret;

    ret = QosApplyForOther(level, tid);
    return ret;
}

int QosApplyForOther(unsigned int level, int tid)
{
    struct QosCtrlData data;
    int fd;

    int ret;

    fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.level = level;
    data.type = static_cast<unsigned int>(QosManipulateType::QOS_APPLY);
    data.pid = tid;

    ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("qos apply failed for task %d\n", tid);
    }
#endif
    close(fd);
    return ret;
}

int QosLeave(void)
{
    struct QosCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.type = static_cast<unsigned int>(QosManipulateType::QOS_LEAVE);
    data.pid = gettid();

    ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("qos leave failed for task %d\n", getpid());
    }
#endif
    close(fd);
    return ret;
}

int QosLeaveForOther(int tid)
{
    struct QosCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.type = static_cast<unsigned int>(QosManipulateType::QOS_LEAVE);
    data.pid = tid;

    ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("qos leave failed for task %d\n", tid);
    }
#endif
    close(fd);
    return ret;
}

int QosPolicySet(const struct QosPolicyDatas *policyDatas)
{
    int fd;
    int ret;

    fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }

    ret = ioctl(fd, QOS_CTRL_POLICY_OPERATION, policyDatas);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("set qos policy failed for task %d\n", getpid());
    }
#endif
    close(fd);
    return ret;
}
