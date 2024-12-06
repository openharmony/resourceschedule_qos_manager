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

#include "qos_interface.h"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include "concurrent_task_log.h"
#include "concurrent_task_utils.h"

static int TrivalOpenRtgNode(void)
{
    char fileName[] = "/proc/self/sched_rtg_ctrl";
    int fd = open(fileName, O_RDWR);
    if (fd < 0) {
        CONCUR_LOGE("[Interface] task %{public}d belong to user %{public}d open rtg node failed, errno = %{public}d",
                    getpid(), getuid(), errno);
    }
    return fd;
}

static int TrivalOpenQosCtrlNode(void)
{
    char fileName[] = "/proc/thread-self/sched_qos_ctrl";
    int fd = open(fileName, O_RDWR);
    if (fd < 0) {
        CONCUR_LOGE("[Interface] task %{public}d belong to user %{public}d open qos node failed, errno = %{public}d",
                    getpid(), getuid(), errno);
    }
    return fd;
}

int EnableRtg(bool flag)
{
    char configStr[] = "load_freq_switch:1;sched_cycle:1;frame_max_util:1024";
    struct RtgEnableData enableData;
    enableData.enable = flag;
    enableData.len = sizeof(configStr);
    enableData.data = configStr;
    int fd = TrivalOpenRtgNode();
    if (fd < 0) {
        return fd;
    }
    fdsan_exchange_owner_tag(fd, 0, GetAddrTag(static_cast<void*>(&fd)));

    int ret = ioctl(fd, CMD_ID_SET_ENABLE, &enableData);
    if (ret < 0) {
        CONCUR_LOGE("set rtg config enable failed.");
    }

    fdsan_close_with_tag(fd, GetAddrTag(static_cast<void*>(&fd)));

    return 0;
};

int QosApply(unsigned int level)
{
    int tid = gettid();
    int ret = QosApplyForOther(level, tid);
    return ret;
}

int QosApplyForOther(unsigned int level, int tid)
{
    int fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }
    fdsan_exchange_owner_tag(fd, 0, GetAddrTag(static_cast<void*>(&fd)));

    struct QosCtrlData data;
    data.level = level;
    data.type = static_cast<unsigned int>(QosManipulateType::QOS_APPLY);
    data.pid = tid;

    int ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
    if (ret < 0) {
        CONCUR_LOGE("[Interface] task %{public}d apply qos failed, errno = %{public}d", tid, errno);
    }
    fdsan_close_with_tag(fd, GetAddrTag(static_cast<void*>(&fd)));
    return ret;
}

int QosLeave(void)
{
    int fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }
    fdsan_exchange_owner_tag(fd, 0, GetAddrTag(static_cast<void*>(&fd)));

    struct QosCtrlData data;
    data.type = static_cast<unsigned int>(QosManipulateType::QOS_LEAVE);
    data.pid = gettid();

    int ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
    if (ret < 0) {
        CONCUR_LOGE("[Interface] task %{public}d leave qos failed, errno = %{public}d", gettid(), errno);
    }
    fdsan_close_with_tag(fd, GetAddrTag(static_cast<void*>(&fd)));
    return ret;
}

int QosLeaveForOther(int tid)
{
    int fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }
    fdsan_exchange_owner_tag(fd, 0, GetAddrTag(static_cast<void*>(&fd)));

    struct QosCtrlData data;
    data.type = static_cast<unsigned int>(QosManipulateType::QOS_LEAVE);
    data.pid = tid;

    int ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
    if (ret < 0) {
        CONCUR_LOGE("[Interface] task %{public}d leave qos failed, errno = %{public}d", tid, errno);
    }
    fdsan_close_with_tag(fd, GetAddrTag(static_cast<void*>(&fd)));
    return ret;
}

int QosPolicySet(const struct QosPolicyDatas* policyDatas)
{
    int fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }
    fdsan_exchange_owner_tag(fd, 0, GetAddrTag(static_cast<void*>(&fd)));

    int ret = ioctl(fd, QOS_CTRL_POLICY_OPERATION, policyDatas);
    if (ret < 0) {
        CONCUR_LOGE("[Interface] set qos policy failed, errno = %{public}d", errno);
    }
    fdsan_close_with_tag(fd, GetAddrTag(static_cast<void*>(&fd)));
    return ret;
}

int QosGet(int& level)
{
    int tid = gettid();
    return QosGetForOther(tid, level);
}

int QosGetForOther(int tid, int& level)
{
    int fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }
    fdsan_exchange_owner_tag(fd, 0, GetAddrTag(static_cast<void*>(&fd)));

    struct QosCtrlData data;
    data.type = static_cast<unsigned int>(QosManipulateType::QOS_GET);
    data.pid = tid;
    data.qos = -1;

    int ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
    if (ret < 0) {
        CONCUR_LOGE("[Interface] task %{public}d get qos failed, errno = %{public}d", tid, errno);
    }
    level = data.qos;

    fdsan_close_with_tag(fd, GetAddrTag(static_cast<void*>(&fd)));
    return ret;
}