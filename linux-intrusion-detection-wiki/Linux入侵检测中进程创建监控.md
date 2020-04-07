
# Linux 入侵检测中的进程创建监控

## 0x01 常见方式
目前来看，常见的获取进程创建的信息的方式有以下四种：
So preload
NetlinkConnector
Audit
Syscall hook

## 0x02 So preload
1.Linux 中大部分的可执行程序是动态链接的，常用的有关进程执行的函数例如 execve均实现在 libc.so 这个动态链接库中。
2.Linux 提供了一个 so preload 的机制，它允许定义优先加载的动态链接库，方便使用者有选择地载入不同动态链接库中的相同函数。结合上述两点不难得出，我们可以通过 so preload 来覆盖 libc.so 中的 execve等函数来监控进程的创建。
### Demo
一个简单的 demo 
1. 创建文件 hook.c 
内容如下：
```
#define _GNU_SOURCE#include <stdio.h>#include <unistd.h>#include <dlfcn.h>

typedef ssize_t (*execve_func_t)(const char* filename, char* const argv[], char* const envp[]);
static execve_func_t old_execve = NULL;

int execve(const char* filename, char* const argv[], char* const envp[]) {
printf("Running hook\n");
printf("Program executed: %s\n", filename);
old_execve = dlsym(RTLD_NEXT, "execve");
return old_execve(filename, argv, envp);
} 
```
该文件的主要部分就是重新定义了 execve函数，在原始的 execve执行之前打印可执行文件的名字。
2. 生成动态链接库：`gcc hook.c-fPIC-shared-o hook.so`
3. 将上面生成的动态链接库注册成 preload ：`echo'/path/to/hook.so'>/etc/ld.so.preload`
4.退出当前 shell 并重新登录，执行命令即可看到我们编写的代码已被执行：
![](https://github.com/redbullsecteam/intrusion-detection-wiki/blob/master/image/id.png)

使用条件该方法没有什么条件限制，只需有 root 权限即可（做入侵监控程序 root 权限是必需的，后面的几种方法默认也都是在 root 权限下）。
### 优缺点
优点
轻量级，只修改库函数代码，不与内核进行交互。
缺点
对于使用方法的第四步，为什么一定要重新获取 shell 才可以看到效果呢？这是因为其实在当前 shell 下执行命令（也就是执行 execve）的实际上是当前的 shell 可执行程序，例如 bash ，而 bash 所需的动态链接库在其开始运行时就已确定，所以我们后续添加的 preload 并不会影响到当前 bash ，只有在添加 preload 之后创建的进程才会受 preload 的影响。这也就得出了该方法的第一个缺点：
只能影响在 preload 之后创建的进程，这就需要检测 Agent 安装得越早越好，尽量在其他应用进程启动之前就完成安装。
除此之外还有以下几点缺点：无法监控静态链接的程序：目前一些蠕虫木马为了降低对环境的依赖性都是用静态链接，不会加载共享库，这种情况下这种监控方式就失效了。
容易被攻击者发现并篡改：目前一些蠕虫木马本身也会向 /etc/ld.so.preload 中写入后门，以方便其对机器的持久掌控，这种情况下这种监控方式也会失效。
攻击者可通过 int80h绕过 libc 直接调用系统调用，这种情况下这种监控方式也会失效。
## 0x03 Netlink Connector
首先了解一下 Netlink 是什么，Netlink 是一个套接字家族（socket family），它被用于内核与用户态进程以及用户态进程之间的 IPC 通信，我们常用的 ss命令就是通过 Netlink 与内核通信获取的信息。Netlink Connector 是一种 Netlink ，它的 Netlink 协议号是 NETLINK_CONNECTOR，其代码位于 
`https://github.com/torvalds/linux/tree/master/drivers/connector`，其中 connectors.c 和 cnqueue.c 是 Netlink Connector 的实现代码，而 cnproc.c 是一个应用实例，名为进程事件连接器，我们可以通过该连接器来实现对进程创建的监控。
系统架构：
![](https://github.com/redbullsecteam/intrusion-detection-wiki/blob/master/image/Connector.png)

具体流程：
![](https://github.com/redbullsecteam/intrusion-detection-wiki/blob/master/image/%E6%B5%81%E7%A8%8B.png)

图中的 ncp 为 Netlink Connector Process，即用户态我们需要开发的程序。
Demo
在 Github 上已有人基于进程事件连接器开发了一个简单的进程监控程序：
https://github.com/ggrandes-clones/pmon/blob/master/src/pmon.c其核心函数为以下三个：
nl_connect：与内核建立连接set_proc_ev_listen：订阅进程事件handle_proc_ev：处理进程事件
其执行流程正如上图所示。我们通过 gcc pmon.c-o pmon生成可执行程序，然后执行该程序即可看到效果：![](https://github.com/redbullsecteam/intrusion-detection-wiki/blob/master/image/pmon.png)

获取到的 pid 之后，再去 /proc/<pid>/目录下获取进程的详细信息即可。
使用条件

内核支持 Netlink Connector

版本 > 2.6.14 内核配置开启： cat/boot/config-$(uname-r)|egrep'CONFIG_CONNECTOR|CONFIG_PROC_EVENTS'

### 优缺点

优点

轻量级，在用户态即可获得内核提供的信息。
缺点

仅能获取到 pid ，详细信息需要查 /proc/<pid>/，这就存在时间差，可能有数据丢失。
## 0x04 Audit

原理

Linux Audit 是 Linux 内核中用来进行审计的组件，可监控系统调用和文件访问，具体架构如下
图片描述
![](https://github.com/redbullsecteam/intrusion-detection-wiki/blob/master/image/audit.png)

1.用户通过用户态的管理进程配置规则（例如图中的 go-audit ，也可替换为常用的 auditd ），并通过 Netlink 套接字通知给内核。

2.内核中的 kauditd 通过 Netlink 获取到规则并加载。

3.应用程序在调用系统调用和系统调用返回时都会经过 kauditd ，kauditd 会将这些事件记录下来并通过 Netlink 回传给用户态进程。

4.用户态进程解析事件日志并输出。

Demo

从上面的架构图可知，整个框架分为用户态和内核态两部分，内核空间的 kauditd 是不可变的，用户态的程序是可以定制的，目前最常用的用户态程序就是 auditd ，除此之外知名的 osquery 在底层也是通过与 Audit 交互来获取进程事件的（https://medium.com/palantir/a...）。下面我们就简单介绍一下如何通过 auditd 来监控进程创建。

首先安装并启动 auditd ：

`apt update && apt install auditd`
`systemctl start auditd && systemctl status auditd`
auditd 软件包中含有一个命名行控制程序 auditctl，我们可以通过它在命令行中与 auditd 进行交互，用如下命令创建一个对 execve这个系统调用的监控：

auditctl -a exit,always -F arch=b64 -S execve
再通过 auditd 软件包中的 ausearch来检索 auditd 产生的日志：

ausearch -sc execve | grep /usr/bin/id 

整个过程的执行结果如下：
![9e5d3aaf3723f5b93f057e0b593d063c.png](en-resource://database/8990:1)


至于其他的使用方法可以通过 man auditd和 man auditctl来查看。
使用条件

### 内核开启 Audit

cat/boot/config-$(uname-r)|grep^CONFIG_AUDIT

### 优缺点

优点

组件完善，使用 auditd 软件包中的工具即可满足大部分需求，无需额外开发代码。相比于 Netlink Connector ，获取的信息更为全面，不仅仅是 pid 。
缺点

性能消耗随着进程数量提升有所上升，需要通过添加白名单等配置来限制其资源占用。
## 0x05 Syscall hook

上面的 Netlink Connector 和 Audit 都是 Linux 本身提供的监控系统调用的方法，如果我们想拥有更大程度的可定制化，我们就需要通过安装内核模块的方式来对系统调用进行 hook 。

原理

目前常用的 hook 方法是通过修改 sys_call_table（ Linux 系统调用表）来实现，具体原理就是系统在执行系统调用时是通过系统调用号在 sys_call_table中找到相应的函数进行调用，所以只要将 sys_call_table中 execve对应的地址改为我们安装的内核模块中的函数地址即可。

具体的实现细节可参考 YSRC 的这篇关于驭龙 HIDS 如何实现进程监控的文章：https://mp.weixin.qq.com/s/ntE5FNM8UaXQFC5l4iKUUw，这里贴出文章里的一张图方便大家对整个流程有个直观地了解：
![8a65a1ff7bfdc8f9af95e3f9ff065629.png](en-resource://database/8992:1)


Demo

关于 Syscall hook 的 Demo ，我在 Github 上找了很多 Demo 代码，其中就包括驭龙 HIDS 的 hook 模块，但是这些都无法在我的机器上（ Ubuntu 16.04 Kernel 4.4.0-151-generic ）正常运行，这也就暴露了 Syscall hook 的兼容性问题。

最后我决定使用 Sysdig 来进行演示，Sysdig 是一个开源的系统监控工具，其核心原理是通过内核模块监控系统调用，并将系统调用抽象成事件，用户根据这些事件定制检测规则。作为一个相对成熟的产品，Sysdig 的兼容性做得比较好，所以这里用它来演示，同时也可以方便大家自己进行测试。

具体步骤如下：

1.通过官方的安装脚本进行安装：

curl-s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash
2.检测内核模块是否已经安全：lsmod|grep sysdig

3.启动对 execve的监控：sysdig evt.type=execve

最终的执行效果如下：
https://segmentfault.com/img/bVbvmiC?w=1016&h=72

有关于 Sysdig 的更多信息可以访问其 wiki 进行获取，另外，Sysdig 团队推出了一个专门用于安全监控的工具 Falco ，Falco 在 Sysdig 的基础上抽象出了可读性更高的检测规则，并支持在容器内部署，同样，大家如果感兴趣可以访问其 wiki 获取更多信息。
使用条件

可以安装内核模块。需针对不同 Linux 发行版和内核版本进行定制。

### 优缺点

优点

高定制化，从系统调用层面获取完整信息。
缺点

开发难度大。兼容性差，需针对不同发行版和内核版本进行定制和测试。

## 0x06 总结

本文共讲了4种常见的监控进程创建的方法，这些方法本质上是对库函数或系统调用的监控，各有优劣，

So preload ：Hook 库函数，不与内核交互，轻量但易被绕过。
Netlink Connector ：从内核获取数据，监控系统调用，轻量，仅能直接获取 pid ，其他信息需要通过读取 /proc/<pid>/来补全。
Audit ：从内核获取数据，监控系统调用，功能多，不只监控进程创建，获取的信息相对全面。
Syscall hook ：从内核获取数据，监控系统调用，最接近实际系统调用，定制度高，兼容性差。
对个人来讲，不是内核开发，Audit 已经够底层的收集了日志，没有主机被动防护的需求话，没必要搞底层hook代码，linux audit的syacall颗粒细度完全足够且好用，但对日志匹配的规则需要细化，略存在成本，总体而言audit是一个不错的选择。

## 参考文献：
`https://mp.weixin.qq.com/s?__biz=MzI4MzI4MDg1NA==&mid=2247483953&idx=1&sn=1c34aba130041bc6f4c6afdaf19eb1c7&scene=21#wechat_redirect`
`https://medium.com/palantir/auditing-with-osquery-part-one-introduction-to-the-linux-audit-framework-217967cec406`
