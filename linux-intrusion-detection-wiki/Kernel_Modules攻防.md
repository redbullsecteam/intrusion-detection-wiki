
# 内核模块攻防

## 说明
可加载内核模块（或LKM）是可以按需加载和卸载到内核中的代码段。它们扩展了内核的功能，而无需重新启动系统，
当恶意使用时，可加载内核模块（LKM）可以是一种以最高操作系统特权（Ring 0）运行的内核模式Rootkit。
攻击者可以使用可加载的内核模块秘密地保留在系统上并逃避防御。
基于LKM的rootkit的常见功能包括：隐藏自身，有选择地隐藏文件，进程和网络活动以及日志篡改，提供经过身份验证的后门并允许对非特权用户的root访问。
LKM可加载内核模块简单实例编写
Helloworld.c文件
```
1.	#include <linux/kernel.h>  
2.	#include<linux/module.h>  
3.	#include<linux/init.h>  
4.	MODULE_LICENSE("GPL");  
5.	static int hello_init(void)  
6.	{  
7.	printk(KERN_WARNING "HELLOWORLD");  
8.	return 0;  
9.	}  
10.	  
11.	static void hello_exit(void)  
12.	{  
13.	printk("BYE");  
14.	}  
15.	module_init(hello_init);  
16.	module_exit(hello_exit); 
```
Makefile文件
```
1.	obj-m :=helloworld.o  //会编译一个模块（-m），生成的name.o文件来自于name.c文件
2.	all:  
3.	        $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules  
4.	clean:  
5.	        $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clea 
```
 
编译完成之后能够看到模块文件：
![](https://github.com/redbullsecteam/intrusion-detection-wiki/blob/master/image/meke_Helloworld.png)
### 常见模块功能
insmod ./hello.ko #加载
rmmod hello #删除
rmmod ./hello.ko#删除
lsmod查看模块是否被加载
 
![](https://github.com/redbullsecteam/intrusion-detection-wiki/blob/master/image/insmod_Helloworld.png)
 

## 监控
```
1.	-w /etc/sysctl.conf -p wa -k sysctl  
2.	-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k T1215_Kernel_Modules_and_Extensions  
3.	-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k T1215_Kernel_Modules_and_Extensions  
4.	-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k T1215_Kernel_Modules_and_Extensions  
5.	-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k T1215_Kernel_Modules_and_Extensions  
6.	-a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k T1215_Kernel_Modules_and_Extensions  
7.	-w /etc/modprobe.conf -p wa -k T1215_Kernel_Modules_and_Extensions  
```

### 文件监控
主要修改两个配置文件对内核参数进行修改
```
/etc/sysctl.conf	内核参数设置
/etc/modprobe.d/	自动处理可载入模块
```

### 命令监控
监控常见的模块使用命令
```
insmod	用于载入模块	insmod led.o 
modprobe 用于自动处理可载入模块	modprobe -v floppy
rmmod	删除模块	rmmod -v pppoe
```

### 内核模块函数
```
1.	init_module，finit_module—加载内核模块  
 init_module（）  
将ELF映像加载到内核空间，执行任何必要的符号重定位，将模块参数初始化为值由调用者提供，然后运行模块的init函数。  
int init_module(void *module_image, unsigned long len,const char *param_values);  
```
```
finit_module  
finit_module（）系统调用的是init_module（），但读取待从文件描述符加载模块的fd。当可以根据内核模块在文件系统中的位置确定其真实性时  
int finit_module(int fd, const char *param_values,int flags);  
```
```
 delete_module-卸载内核模块
delete_module（）系统调用试图消除查明的未使用的可加载模块的条目名称。如果模块具有退出功能，则在卸载模块之前执行该功能。的标志参数用于修改系统调用的行为，如下面所述。此系统调用需要特权。
 int delete_module(const char *name, int flags);
 ```
### 缓解措施
用于检测Linux rootkit的常见工具包括：rkhunter，chrootkit
应用程序白名单和软件限制工具（例如SELinux）也可以帮助限制内核模块的加载
限制对root帐户的访问，并通过适当的特权分离和限制特权升级机会来防止用户加载内核模块和扩展

##参考文献：
http://www.man7.org/linux/man-pages/man2/finit_module.2.html
https://linux.die.net/man/2/delete_module
https://www.cnblogs.com/pengdonglin137/p/3494646.html
https://www.freebuf.com/articles/system/186012.html

 


