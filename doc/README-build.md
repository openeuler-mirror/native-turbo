## sysboost操作手册

### 安装sysboost

支持操作系统：openEuler 22.03 LTS SP2及以上版本

安装操作系统后应当默认包含sysboost，或者通过yum安装。

~~~
yum install sysboost
~~~

### 服务

* 服务配置
~~~
# 服务配置文件目录为：/etc/sysboost.d/
cat /etc/sysboost.d/bash.toml

elf_path = "/usr/bin/bash"
mode = "static"
libs = "/usr/lib64/libtinfo.so.6"
~~~
当前只支持配置bash，请管理员确认配置正确，以避免未知错误发生

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

#### 一键合并

~~~
sysboostd
~~~

注：需要确保sysboost、包含重定位信息的bash和ncurses包正常安装，其他操作参考systemctl手册

**注：sysboostd只能单实例运行，多实例运行后果不可知**

### 手动执行

**sysboost属于内部命令, 变化较快, 管理员请勿直接使用**

~~~
sysboost -static <ELFs>
# 当前只支持bash合并，执行sysboost -static bash libtinfo.so即可
~~~

