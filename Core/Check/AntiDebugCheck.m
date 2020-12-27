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
//#import <sys/kdebug_signpost.h>
#import <sys/ioctl.h>
//#import <unistd.h>

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
        printf("\n❗️❗️❗️dlsym_syscall_sysctl 检测到当前进程被调试❗️❗️❗️\n");
        //为了测试效果就直接abort，其实这里可以使用其他方式或者将状态上传到后端
        abort();
    }
}

#pragma mark - svc
/// svc -> ptrace
+ (void)antiDebugCheck_svc_ptrace {
#ifdef __arm64__
    printf("\n❗️❗️❗️svc_ptrace 拒绝调试器附加❗️❗️❗️\n");
    asm volatile(
                 "mov x0, #31\n"
                 "mov x1, #0\n"
                 "mov x2, #0\n"
                 "mov x3, #0\n"
                 "mov x16, #26\n"
                 "svc #0x80\n"//svc执行系统调用ptrace
                 );
    printf("\n⚠️⚠️⚠️svc_ptrace 被绕过⚠️⚠️⚠️\n");
#endif
}

/// svc -> sysctl
+ (void)antiDebugCheck_svc_sysctl {
#ifdef __arm64__
    int name[4];//指定査询信息的数组
    struct kinfo_proc info;//査询的返回结果
    size_t infosize = sizeof(struct kinfo_proc);
    info.kp_proc.p_flag = 0;
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    asm volatile(
                 "mov x0, %[name_ptr]\n"
                 "mov x1, #4\n"
                 "mov x2, %[info_ptr]\n"
                 "mov x3, %[infosize_ptr]\n"
                 "mov x4, #0\n"
                 "mov x5, #0\n"
                 "mov x16, #202\n"
                 "svc #0x80\n"
                 :
                 : [name_ptr] "r"(name), [info_ptr] "r"(&info),[infosize_ptr] "r"(&infosize)
                 );
    if (info.kp_proc.p_flag & P_TRACED) {//命中调试标签
        printf("\n❗️❗️❗️svc_sysctl 检测到当前进程被调试❗️❗️❗️\n");
        //为了测试效果就直接abort，其实这里可以使用其他方式或者将状态上传到后端
        abort();
    }
#endif
}

/// svc -> syscall -> ptrace
+ (void)antiDebugCheck_svc_syscall_ptrace {
#ifdef __arm64__
    printf("\n❗️❗️❗️svc_syscall_ptrace 拒绝调试器附加❗️❗️❗️\n");
    asm volatile(
                 "mov x0, #26\n"
                 "mov x1, #31\n"
                 "mov x2, #0\n"
                 "mov x3, #0\n"
                 "mov x4, #0\n"
                 "mov x16, #0\n"
                 "svc #0x80\n"//svc执行系统调用syscall
                 );
    printf("\n⚠️⚠️⚠️svc_syscall_ptrace 被绕过⚠️⚠️⚠️\n");
#endif
}

#pragma mark - isatty
/// isatty
+ (void)antiDebugCheck_isatty {
    /**
     * 主要功能是检查设备类型，判断文件描述词是否是为终端机
     * 原理
     * STDIN_FILENO     0    standard input file descriptor - 检测输入日志来自终端机(terminal), 返回1，否则为0
     * STDOUT_FILENO    1    standard output file descriptor - 检测输出日志来自终端机(terminal), 返回1，否则为0
     * STDERR_FILENO    2    standard error file descriptor - 检测输出错误日志来自终端机(terminal), 返回1，否则为0
     */
    //因此，连接调试器的时候，传入STDOUT_FILENO、STDERR_FILENO 时会输出1，否则为0
    if (isatty(STDOUT_FILENO) | isatty(STDERR_FILENO)) {
        printf("\n❗️❗️❗️isatty 检测到当前进程被调试❗️❗️❗️\n");
        abort();
    }
}

@end
