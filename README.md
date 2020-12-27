# ZBDebugCheck
iOS 反调试和反反调试的代码，内附一个测试工程。

## 代码目录
Core
├── Check (反调试代码)
│   ├── AntiDebugCheck.h
│   └── AntiDebugCheck.m
├── Crack (反反调试代码)
│   ├── AntiDebugCrack.h
│   └── AntiDebugCrack.m
├── Fishhook (hook 系统 c 函数的库)
│   ├── fishhook.c
│   └── fishhook.h
├── Patch (patch 指令的库)
│   ├── AntiDebugPatch.h
│   └── AntiDebugPatch.m
└── ptrace.h (ptrace 头文件)

## 介绍
demo 中按原理分以下3类，
+ ptrace，拒绝当前进程被调试器附加
+ sysctl，检查当前进程的调试标记
+ isatty，检查设备类型，判断输出文件是否是为终端机
其余的方式都是基于上述3种方式的变种。在demo 中按变种的方式进行了以下分类

### ptrace
+ prace

### sysctl
+ sysctl

### syscall 
+ syscall -> ptrace
+ syscall -> sysctl

### dlsym
+ dlsym -> ptrace
+ dlsym -> sysctl
+ dlsym -> syscall -> ptrace
+ dlsym -> syscall -> sysctl

### svc
+ svc -> ptrace
+ svc -> sysctl
+ svc -> syscall -> ptrace

### isatty
+ isatty

您可以通过运行工程去理解各种反调试策略以及应对的反反调试方案。
    
