# resourceschedule_qos_manager

## 简介<a name="section_introduction"></a>

权限管控服务目前服务于并发编程框架FFRT，为特定的线程提供调用底层Qos和RTG接口的能力。服务接收全局资源调度管控子系统中的帧感知调度插件发送的场景信息，为系统服务uid与前台app的uid赋予调用底层对应接口的权限。同时将多级Qos的配置信息下发到内核，为而为并发编程框架FFRT提供支撑。

## 目录<a name="section_catalogue"></a>

```
//foundation/resourceschedule/qos_manager
├── etc
│   └── init                                # 权限管控服务配置文件
|
├── sa_profile                              # 权限管控服务xml
├── include                                 # 部件通用工具类
│   └── concurrent_task_log.h               # 封装hilog，用于日志打印
│
├── interfaces/inner_api
│   └── concurrent_task_client.h            # 部件间调用接口
|
├── frameworks
│   └── concurrent_task_client              # 服务client端
|
├── services                                # 服务service端
│
└── test                                    # 自测试用例目录
```


## 框架<a name="section_frameworks"></a>

权限管控服务根据其对接的内核功能模块，主要可以分为两个部分。即RTG权限管控与分组管理、多级QoS权限管控与信息下发。

- **RTG权限管控与分组管理**：主要分为基于uid的RTG权限管控模块、RTG分组管理模块。其中：

  基于uid的RTG权限管控模块，主要接收帧感知调度发送的场景信息，基于这些消息，将一些特权uid、以及切换到前台的app对应的uid赋予RTG操作权限，使拥有这些uid的线程可以对RTG分组执行特定操作。

  RTG分组管理模块，统一管理RTG分组，为并发编程框架目前对接的外部场景用到的RTG分组执行创建、销毁等操作。

- **多级QoS权限管控与信息下发**：主要分为基于uid的QoS权限管控模块、多级QoS信息下发模块。其中：

  基于uid的QoS权限管控模块，和RTG权限管控模块类似，主要接收帧感知调度发送的场景信息，基于这些消息，将一些特权uid、以及切换到前台的app对应的uid赋予设置QoS等级的权限。

  多级QoS信息下发模块，将不同场景下的不同QoS等级对应的nice、uclamp等参数下发到内核，为线程的QoS等级设置服务。

两个部分中的权限管控模块，统筹了权限管控服务所需要的外部事件，并根据事件类型下发对应的参数和权限，和并发编程框架相互合作，共同保障系统的性能供给。

## 使用说明<a name="section_instructions"></a>

系统开发者可以通过配置productdefine/common/products下的产品定义json文件，增加或移除本部件，来启用或停用本部件：

```
"qos_manager:concurrent_task_client":{}
```

## 相关仓<a name="section_related_repositories"></a>

- [resource_schedule_service](https://gitee.com/openharmony/resourceschedule_resource_schedule_service)
- [frame_aware_sched](https://gitee.com/openharmony/frame_aware_sched)
- **resourceschedule_qos_manager**







