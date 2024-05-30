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
    if (!IsValidNode) {
        CONCUR_LOGE("FillinUidInfo:: currNode is nullptr!");
        return;
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
    if (!IsValidNode) {
        CONCUR_LOGE("FillinBundleNameInfo:: currNode is nullptr!");
        return;
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

    bool cfgTestEnable = OHOS::system::GetBoolParameter("persist.qos.configTest", false);
    if (cfgTestEnable) {
        for (auto iter : authProcUidConfigs_) {
            CONCUR_LOGI("ParseAuth:: authProcUidConfigs_ contain uid = %{public}d", (int32_t)iter);
        }
        for (auto iter : authProcBundleNameConfigs_) {
            CONCUR_LOGI("ParseAuth:: authProcBundleNameConfigs_ contain bundleName = %{public}s", iter.c_str());
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
    }
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
}
}