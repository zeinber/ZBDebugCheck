//
//  AntiDebugCheck.m
//  ZBCheckDebugCheck
//
//  Created by 隐姓埋名 on 2020/12/17.
//  Copyright © 2020 展斌程. All rights reserved.
//

#import "AntiDebugCheck.h"
#import <dlfcn.h>
// 可以通过申明的方式，这里为了省事，直接去 Mac 端导入头文件
#import "ptrace.h"
#import <unistd.h>
#import <sys/sysctl.h>
#import <sys/syscall.h>
#import <sys/kdebug_signpost.h>

@implementation AntiDebugCheck

#pragma mark - ptrace
/// ptrace 阻止调试器附加
+ (void)antiDebugCheck_ptrace {
    printf("\n❗️❗️❗️ptrace 拒绝调试器附加❗️❗️❗️\n");
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
}

#pragma mark - sysctl
/// sysctl 检查当前进程的调试标记
+ (void)antiDebugCheck_sysctl {
    int name[4];//指定査询信息的数组
    struct kinfo_proc info;//査询的返回结果
    size_t infosize = sizeof(struct kinfo_proc);
    info.kp_proc.p_flag = 0;
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    if (sysctl(name, 4, &info, &infosize, NULL, 0) == -1) {
        printf("\n❌❌❌sysctl error❌❌❌\n");
        return;
    }
    if (info.kp_proc.p_flag & P_TRACED) {//命中调试标签
        printf("\n❗️❗️❗️sysctl 检测到当前进程被调试❗️❗️❗️\n");
        //为了测试效果就直接abort，其实这里可以使用其他方式或者将状态上传到后端
        abort();
    }
}

#pragma mark - syscall
/// syscall -> ptrace
+ (void)antiDebugCheck_syscall_ptrace {
    printf("\n❗️❗️❗️syscall_ptrace 拒绝调试器附加❗️❗️❗️\n");
    syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0);
}

/// syscall -> sysctl
+ (void)antiDebugCheck_syscall_sysctl {
    int name[4];//指定査询信息的数组
    struct kinfo_proc info;//査询的返回结果
    size_t infosize = sizeof(struct kinfo_proc);
    info.kp_proc.p_flag = 0;
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    int f = syscall(SYS_sysctl, name, 4, &info, &infosize, NULL, 0);
    if (f == -1) {
        printf("\n❌❌❌syscall_sysctl error❌❌❌\n");
        return;
    }
    if (info.kp_proc.p_flag & P_TRACED) {//命中调试标签
        printf("\n❗️❗️❗️syscall_sysctl 检测到当前进程被调试❗️❗️❗️\n");
        //为了测试效果就直接abort，其实这里可以使用其他方式或者将状态上传到后端
        abort();
    }
}

/// syscall ->  syscall -> ptrace or sysctl （syscall套娃的方式会报错，Thread 1: signal SIGSYS）
//+ (void)antiDebugChecks_syscall_syscall {
//    printf("\n❗️❗️❗️syscall_syscall_ptrace 拒绝调试器附加❗️❗️❗️\n");
//    syscall(SYS_syscall, SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0);
//}

#pragma mark - dlsym
/// dlsym -> ptrace
+ (void)antiDebugCheck_dlsym_ptrace {
    printf("\n❗️❗️❗️dlsym_ptrace 拒绝调试器附加❗️❗️❗️\n");
    //获取ptrace的函数地址
    typedef int (*PTRACE_T)(int _request, pid_t _pid, caddr_t _addr, int _data);
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    PTRACE_T ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}

/// dlsym -> sysctl
+ (void)antiDebugCheck_dlsym_sysctl {
    //获取sysctl的函数地址
    typedef int (*SYSCTL_T)(int *, u_int, void *, size_t *, void *, size_t);
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    SYSCTL_T sysctl_ptr = dlsym(handle, "sysctl");
    
    int name[4];//指定査询信息的数组
    struct kinfo_proc info;//査询的返回结果
    size_t infosize = sizeof(struct kinfo_proc);
    info.kp_proc.p_flag = 0;
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    if (sysctl_ptr(name, 4, &info, &infosize, NULL, 0) == -1) {
        printf("\n❌❌❌dlsym_sysctl error❌❌❌\n");
        return;
    }
    if (info.kp_proc.p_flag & P_TRACED) {//命中调试标签
        printf("\n❗️❗️❗️dlsym_sysctl 检测到当前进程被调试❗️❗️❗️\n");
        //为了测试效果就直接abort，其实这里可以使用其他方式或者将状态上传到后端
        abort();
    }
    dlclose(handle);
}

/// dlsym -> syscall -> ptrace
+ (void)antiDebugCheck_dlsym_syscall_ptrace {
    printf("\n❗️❗️❗️dlsym_syscall_ptrace 拒绝调试器附加❗️❗️❗️\n");
    //获取sysctl的函数地址
    typedef int (*SYSCALL_T)(int, ...);
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    SYSCALL_T syscall_ptr = dlsym(handle, "syscall");
    syscall_ptr(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}

/// dlsym -> syscall -> sysctl
+ (void)antiDebugCheck_dlsym_syscall_sysctl {
    //获取sysctl的函数地址
    typedef int (*SYSCALL_T)(int, ...);
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    SYSCALL_T syscall_ptr = dlsym(handle, "syscall");
    
    int name[4];//指定査询信息的数组
    struct kinfo_proc info;//査询的返回结果
    size_t infosize = sizeof(struct kinfo_proc);
    info.kp_proc.p_flag = 0;
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    if (syscall_ptr(SYS_sysctl, name, 4, &info, &infosize, NULL, 0) == -1) {
        printf("\n❌❌❌dlsym_syscall_sysctl error❌❌❌\n");
        return;
    }
    if (info.kp_proc.p_flag & P_TRACED) {//命中调试标签
        printf("\n❗️❗️❗️dlsym_syscall_sysctl 检测到当前进程被调试，退出❗️❗️❗️\n");
        //为了测试效果就直接abort，其实这里可以使用其他方式或者将状态上传到后端
        abort();
    }
}
@end
