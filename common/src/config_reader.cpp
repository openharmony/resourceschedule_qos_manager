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
#include <cstdlib>
#include <string>
#include <climits>

#include "config_reader.h"
#include "config_policy_utils.h"
#include "concurrent_task_log.h"
#include "parameters.h"

using namespace std;

namespace OHOS {
namespace ConcurrentTask {
namespace {
    const std::string XML_TAG_QOS_CONFIG = "qosconfig";
    const std::string XML_TAG_QOS_AUTH = "auth";
    const std::string XML_TAG_UIDLIST = "uidlist";
    const std::string XML_TAG_UID = "uid";
    const std::string XML_TAG_BUNDLENAMELIST = "bundlenamelist";
    const std::string XML_TAG_BUNDLENAME = "bundlename";
    const std::string XML_TAG_POWER_MODE = "powermode";
    const std::string XML_TAG_SWITCH = "switch";
    const std::string XML_TAG_FPS = "fps";
    const std::string XML_TAG_DEGRADATION_FPS = "degradationfps";
    const std::string XML_TAG_FPS_HIGH = "120";
    const std::string XML_TAG_FPS_MEDIUM = "90";
    const std::string XML_TAG_FPS_STANDARD = "60";
    constexpr int FPS_OFFSET = 10000;
}

bool ConfigReader::IsValidNode(const xmlNode* currNode)
{
    if (!currNode) {
        return false;
    }
    if (!currNode->name || currNode->type == XML_COMMENT_NODE) {
        return false;
    }
    return true;
}

bool ConfigReader::FillinUidInfo(const xmlNode* currNode)
{
    if (!IsValidNode(currNode)) {
        CONCUR_LOGE("FillinUidInfo:: currNode is nullptr!");
        return false;
    }
    xmlNodePtr currNodePtr = currNode->xmlChildrenNode;
    for (; currNodePtr; currNodePtr = currNodePtr->next) {
        if (xmlStrcmp(currNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_UID.c_str())) == 0) {
            xmlChar *attrValue = xmlGetProp(currNodePtr, reinterpret_cast<const xmlChar*>(XML_TAG_UID.c_str()));
            if (!attrValue) {
                CONCUR_LOGE("FillinUidInfo:: uid null!");
                return false;
            }
            int64_t uid = atoi(reinterpret_cast<const char*>(attrValue));
            authProcUidConfigs_.insert(uid);
            xmlFree(attrValue);
        }
    }
    return true;
}

bool ConfigReader::FillinBundleNameInfo(const xmlNode* currNode)
{
    if (!IsValidNode(currNode)) {
        CONCUR_LOGE("FillinBundleNameInfo:: currNode is nullptr!");
        return false;
    }
    xmlNodePtr currNodePtr = currNode->xmlChildrenNode;
    for (; currNodePtr; currNodePtr = currNodePtr->next) {
        if (xmlStrcmp(currNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_BUNDLENAME.c_str())) == 0) {
            xmlChar *attrValue = xmlGetProp(currNodePtr, reinterpret_cast<const xmlChar*>(XML_TAG_BUNDLENAME.c_str()));
            if (!attrValue) {
                CONCUR_LOGE("FillinBundleNameInfo:: bundleName null!");
                return false;
            }
            std::string bundleName = reinterpret_cast<const char*>(attrValue);
            authProcBundleNameConfigs_.insert(bundleName);
            xmlFree(attrValue);
        }
    }
    return true;
}

void ConfigReader::ParseAuth(const xmlNode* currNode)
{
    xmlNodePtr currNodePtr = currNode->xmlChildrenNode;
    for (; currNodePtr; currNodePtr = currNodePtr->next) {
        if (xmlStrcmp(currNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_UIDLIST.c_str())) == 0) {
            if (!FillinUidInfo(currNodePtr)) {
                CONCUR_LOGE("ParseAuth:: uid fill in authProcUidConfigs_ error!");
                continue;
            }
        }

        if (xmlStrcmp(currNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_BUNDLENAMELIST.c_str())) == 0) {
            if (!FillinBundleNameInfo(currNodePtr)) {
                CONCUR_LOGE("ParseAuth:: bundleName fill in authProcBundleNameConfigs_ error!");
                continue;
            }
        }
    }
}

void ConfigReader::ParsePowerMode(const xmlNode* currNode)
{
    if (!IsValidNode(currNode)) {
        CONCUR_LOGE("ParsePowerMode:: currNode is nullptr!");
        return;
    }
    xmlNodePtr currNodePtr = currNode->xmlChildrenNode;
    for (; currNodePtr; currNodePtr = currNodePtr->next) {
        if (xmlStrcmp(currNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_SWITCH.c_str())) == 0) {
            char* switchValue = reinterpret_cast<char*>(xmlNodeGetContent(currNodePtr));
            if (!switchValue) {
                CONCUR_LOGE("ParsePowerMode:: switch is null!");
                continue;
            }
            if (strncmp(switchValue, "1", 1) == 0) {
                powerModeSchedSwitch_ = true;
            } else if (strncmp(switchValue, "0", 1) == 0) {
                powerModeSchedSwitch_ = false;
            } else {
                CONCUR_LOGE("ParsePowerMode:: invalid switch value!");
            }
            xmlFree(switchValue);
        }

        if (xmlStrcmp(currNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_DEGRADATION_FPS.c_str())) == 0) {
            char* fpsValue = reinterpret_cast<char*>(xmlGetProp(currNodePtr,
                reinterpret_cast<const xmlChar*>(XML_TAG_FPS.c_str())));
            char* deFpsValue = reinterpret_cast<char*>(xmlNodeGetContent(currNodePtr));
            if (fpsValue && deFpsValue && IsValidFps(fpsValue) && IsPositiveInt(deFpsValue)) {
                degradationFpsMap_.insert(std::make_pair(atoi(fpsValue), atoi(deFpsValue)));
            } else {
                CONCUR_LOGE("ParsePowerMode:: fps is null or invalid!");
            }
            if (fpsValue) {
                xmlFree(fpsValue);
            }
            if (deFpsValue) {
                xmlFree(deFpsValue);
            }
        }
    }
}

bool ConfigReader::LoadFromConfigFile(const std::string& configFile)
{
    // skip the empty string, else you will get empty node
    xmlDocPtr xmlDocPtr = xmlReadFile(configFile.c_str(), nullptr,
        XML_PARSE_NOBLANKS | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!xmlDocPtr) {
        CONCUR_LOGE("LoadFromConfigFile:: xmlReadFile error!");
        return false;
    }
    xmlNodePtr rootNodePtr = xmlDocGetRootElement(xmlDocPtr);
    if (!rootNodePtr || !rootNodePtr->name ||
        xmlStrcmp(rootNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_QOS_CONFIG.c_str())) != 0) {
        CONCUR_LOGE("LoadFromConfigFile:: root element tag error!");
        xmlFreeDoc(xmlDocPtr);
        return false;
    }
    xmlNodePtr currNodePtr = rootNodePtr->xmlChildrenNode;
    for (; currNodePtr; currNodePtr = currNodePtr->next) {
        if (!IsValidNode(currNodePtr)) {
            CONCUR_LOGE("LoadFromConfigFile:: IsInvalidNode!");
            continue;
        }
        if (xmlStrcmp(currNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_QOS_AUTH.c_str())) == 0) {
            ParseAuth(currNodePtr);
        }
        if (xmlStrcmp(currNodePtr->name, reinterpret_cast<const xmlChar*>(XML_TAG_POWER_MODE.c_str())) == 0) {
            ParsePowerMode(currNodePtr);
        }
    }
    ConfigHilog();
    xmlFreeDoc(xmlDocPtr);
    return true;
}

void ConfigReader::GetRealConfigPath(const char* configName, std::string& configPath)
{
    if (!configName) {
        CONCUR_LOGE("GetRealConfigPath:: configName is nullptr!");
        return;
    }
    char buf[PATH_MAX] = {0};
    char* configFilePath = GetOneCfgFile(configName, buf, PATH_MAX);
    char tmpPath[PATH_MAX] = {0};
    if (!configFilePath || strlen(configFilePath) == 0 || strlen(configFilePath) > PATH_MAX ||
        !realpath(configFilePath, tmpPath)) {
        CONCUR_LOGE("GetRealConfigPath:: get config file path error!");
        configPath = "";
        return;
    }
    configPath = tmpPath;
}

bool ConfigReader::IsUidAuth(pid_t uid)
{
    if (authProcUidConfigs_.find(uid) != authProcUidConfigs_.end()) {
        return true;
    }
    return false;
}

bool ConfigReader::IsBundleNameAuth(std::string& bundleName)
{
    if (authProcBundleNameConfigs_.find(bundleName) != authProcBundleNameConfigs_.end()) {
        return true;
    }
    return false;
}

bool ConfigReader::GetPowerModeSchedSwitch()
{
    return powerModeSchedSwitch_;
}

int ConfigReader::GetDegratationFps(int fps)
{
    if (degradationFpsMap_.find(fps) == degradationFpsMap_.end()) {
        return fps;
    }
    return degradationFpsMap_[fps] + FPS_OFFSET;
}

bool ConfigReader::IsValidFps(const std::string& fps)
{
    if (fps == XML_TAG_FPS_HIGH || fps == XML_TAG_FPS_MEDIUM || fps == XML_TAG_FPS_STANDARD) {
        return true;
    }
    return false;
}

bool ConfigReader::IsPositiveInt(const std::string& intStr)
{
    int num = 0;
    try {
        num = stoi(intStr);
    } catch (...) {
        CONCUR_LOGE("Unexpected number format!");
        return false;
    }
    return num > 0;
}

void ConfigReader::ConfigHilog()
{
    bool getConfigRead = OHOS::system::GetBoolParameter("persist.qos.configreadlog", false);
    if (getConfigRead) {
        for (auto iter : authProcUidConfigs_) {
            CONCUR_LOGI("authProcUidConfigs_ contain uid = %{public}d", (int32_t)iter);
        }
        for (auto iter : authProcBundleNameConfigs_) {
            CONCUR_LOGI("authProcBundleNameConfigs_ contain bundleName = %{public}s", iter.c_str());
        }
        CONCUR_LOGI("powerModeSchedSwitch_ = %{public}d", powerModeSchedSwitch_);
        for (auto iter : degradationFpsMap_) {
            CONCUR_LOGI("fps = %{public}d degradationFps = %{public}d", iter.first, iter.second);
        }
    }
}
}
}