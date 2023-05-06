## sysboost操作手册

### 安装sysboost

#### 1.使用openEuler默认自带的sysboost

支持操作系统：openEuler 22.03 LTS SP2及以上版本

安装操作系统后应当默认包含sysboost，或者通过yum安装。

~~~
yum install sysboost
~~~

#### 2.编译安装

* 安装依赖包

  ~~~
  yum install meson clang ncurses-devel binutils bison
  ~~~

* 下载源码

  ~~~
  git clone https://gitee.com/openeuler/native-turbo.git
  ~~~

* 编译

  ~~~
  cd native-turbo
  make release
  make
  ~~~

  注：此为编译release版本，如需编译debug版本，使用make debug替换make release即可

### 服务

sysboost服务由systemctl管理，通常情况下，安装openEuler并启动后sysboost服务会自动运行。

* 查看运行状态

~~~
systemctl status sysboost.service
~~~

* 启动服务

~~~
systemctl start sysboost.service
~~~

* 停止服务

~~~
systemctl stop sysboost.service
~~~

其他操作参考systemctl手册，sysboost不支持多个服务同时启动

### 手动执行

sysboost提供名为sysboost的命令

#### 1.一键合并

~~~
sysboost --daemon
~~~

注：需要确保sysboost、包含重定位信息的bash和ncurses包正常安装

#### 2.静态合并

~~~
sysboost -static <ELFs>
# 当前只支持bash合并，执行sysboost -static bash libtinfo.so即可
~~~

