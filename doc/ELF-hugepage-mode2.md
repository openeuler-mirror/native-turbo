# 可执行程序和动态库大页技术-模式2

#### 介绍

将所有动态库的代码段和数据段连续拼接, 忽略设置RWX属性; 所有代码段和数据段区域都使用2M大页内存; 

动态库解释器先预占2个4G虚拟内存区域; 一个用于加载编译阶段依赖的动态库, 一个用于加载dlopen加载的动态库; 加载动态库的时候从虚拟机地址开始位置逐个放入各个动态库的LOAD段, 下个动态库的LOAD段紧接着上个动态库的结束位置; dlopen的动态库存在反复卸载和加载的情况, 需要通过伙伴系统位图管理, 避免内存碎片; 



#### 构建/安装教程

1. 下载centos-7.6的源码包，进行解压，提取源码:

   ```shell
   rpm2cpio glibc-2.17-260.el7.src.rpm | cpio -iv
   ```

2. 适配补丁：

   glibc-patch目录下glibc-2.17中存放了针对模式2适配的glibc补丁，合入特性补丁代码

   ```shell
   sed -i "/glibc-rh1471405.patch/a\Patch6000: 0001-Factor-mmap-munmap-of-PT_LOAD-segments-out-of-_dl_ma.patch" glibc.spec
   sed -i "/0001-Factor-mmap-munmap-of-PT_LOAD-segments-out-of-_dl_ma.patc/a\Patch6001: 0002-Check-for-__mprotect-failure-in-_dl_map_segments-BZ-.patch" glibc.spec
   sed -i "/0002-Check-for-__mprotect-failure-in-_dl_map_segments-BZ-.patch/a\Patch6002: 0003-elf-load-elf-files-with-hugepages.patch" glibc.spec
   sed -i "/patch2751 -p1/a\%patch6000 -p1" glibc.spec
   sed -i "/patch6000 -p1/a\%patch6001 -p1" glibc.spec
   sed -i "/patch6001 -p1/a\%patch6002 -p1" glibc.spec
   ```

3. 打开特性开关：

   ```shell
   sed -i "/--enable-obsolete-rpc/a\        --enable-hugepage-shared-library \\\\" glibc.spec
   ```

4. 构建：

   ```shell
   rpmbuild -ba -D "_sourcedir `pwd`" -D "_builddir `pwd`" glibc.spec
   ```

#### 使用说明

1. 若需使用新编译的ld.so加载测试程序的动态库，在编译可执行程序的时候需要通过-Wl,--dyanmic-linker指定新编ld.so的位置

   或者直接替换编译好的glibc

2. 通过启动参数配置或者开机后通过sysfs接口配置大页内存池 

   ```shell
   default_hugepagesz=2M hugepagesz=2M hugepages=xxx 
   echo 300 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
   ```

3. 设置环境变量LD_HUGEPAGE_LIB=2 ，启动可执行程序，ld.so加载动态库的代码段和数据段区域会使用大页





