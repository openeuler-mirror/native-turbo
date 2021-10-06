# native-turbo

#### 介绍
Native-Turbo 是操作系统原生性能加速框架; 通过微架构优化和软硬件协同等技术, 提升大型应用性能;



#### 软件架构

![](doc/img/Native-Turbo-stack.svg)

A-tune作为智能中心管理OS性能策略;
wisdom接收A-tune策略, 执行调度算法;
Native-Turbo提供操作系统各层级软件的性能优化机制, A-tune进行智能管理;



Native-Turbo包含微架构优化技术, 基础库优化, 系统调用优化, 中断聚合, 软硬件协同等技术;



微架构优化技术

动态库拼接
通过ld加载阶段将分散的动态库的代码段数据段拼接聚合，然后使用大页内存提升iTLB命中率。

exec原生大页
用户态大页机制需要应用修改配置和重编译，exec原生大页机制直接在内核加载ELF文件阶段使用大页内存，对APP透明。

消除PLT跳转
应用代码调用动态库函数的流程，需要先跳转PLT表，然后跳转真实函数，消除PLT跳转能提升IPC。

热点Section在线重排
默认情况下代码段是按动态库粒度排布的，通过在线重排技术可以实现热点代码按Section粒度重排。



#### 构建/安装教程

请参考doc目录下各特性说明文档;



#### 使用说明

请参考doc目录下各特性说明文档;



#### 参与贡献

1.  发现BUG或者有新需求请提issue;  https://gitee.com/openeuler/native-turbo/issues
2.  修复BUG或者新特性的补丁请通过Pull Request提交; 

