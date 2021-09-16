# native-turbo

#### 介绍
Native-Turbo is the performance optimization framework of native microarchitecture of operating system.

#### 软件架构
软件架构说明
1. glibc动态加载器ld.so加载动态库支持将动态库映射到大页内存区间从而降低TLB cache miss以提升性能

#### 构建/安装教程

1. apply patch：glibc-patch目录中有针对openEuler SP1版本glibc的补丁，合入特性补丁代码
	如果内核未支持定制化的mmap，0002-elf-ld.so-use-special-mmap-for-hugepage-to-get-symbo.patch无需合入
2. 构建：在glibc源码目录的同层级目录下执行如下命令：
	mkdir build && cd build && ../glibc-2.28/configure --prefix=/usr --enable-static-pie --enable-hugepage-shared-library && make -j

#### 使用说明

1.  若需使用新编译的ld.so加载测试程序的动态库，在编译可执行程序的时候需要通过-Wl,--dyanmic-linker指定新编ld.so的位置
2.  对于要使用大页的动态库（libA.so为例），构建完成之后，使用hugepageedit标记动态库：./hugepageedit libA.so
3.  设置环境变量HUGEPAGE_PROBE非空，启动可执行程序，ld.so加载被hugepageedit标记的动态库会使用大页

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request


#### 特技

1.  使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2.  Gitee 官方博客 [blog.gitee.com](https://blog.gitee.com)
3.  你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解 Gitee 上的优秀开源项目
4.  [GVP](https://gitee.com/gvp) 全称是 Gitee 最有价值开源项目，是综合评定出的优秀开源项目
5.  Gitee 官方提供的使用手册 [https://gitee.com/help](https://gitee.com/help)
6.  Gitee 封面人物是一档用来展示 Gitee 会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
