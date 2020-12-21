//
//  AntiDebugCrack.m
//  ZBCheckDebugCheck
//
//  Created by 隐姓埋名 on 2020/12/17.
//  Copyright © 2020 展斌程. All rights reserved.
//

#import "AntiDebugCrack.h"
#import "fishhook.h"
#import <sys/sysctl.h>
#import "ptrace.h"
#import <sys/syscall.h>

@implementation AntiDebugCrack
#pragma mark - 入口函数
/// dyld 加载的时会执行构造方法
__attribute__((constructor)) static void entry(){
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [AntiDebugCrack antiDebugCheck_ptrace];
        [AntiDebugCrack antiDebugCheck_sysctl];
        [AntiDebugCrack antiDebugCheck_syscall_summary];
        [AntiDebugCrack antiDebugCheck_dlsym_summary];
//        [AntiDebugCrack antiDebugCheck_dlsym_ptrace];
//        [AntiDebugCrack antiDebugCheck_dlsym_sysctl];
//        [AntiDebugCrack antiDebugCheck_dlsym_syscall_ptrace];
//        [AntiDebugCrack antiDebugCheck_dlsym_syscall_sysctl];
    });
}

#pragma mark - ptrace
typedef int (*ptrace_ptr_t)(int _request,pid_t _pid, caddr_t _addr,int _data);
static ptrace_ptr_t orig_ptrace = NULL;
int my_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);
int my_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data){
    //request不是PT_DENY_ATTACH（31），执行原有调用，否则直接return 0
    if (_request != 31) {
        return orig_ptrace(_request,_pid,_addr,_data);
    }
    printf("\n⚠️⚠️⚠️ptrace 被成功绕过⚠️⚠️⚠️\n");
    return 0;
}
/// ptrace 阻止调试器附加
+ (void)antiDebugCheck_ptrace {
    rebind_symbols((struct rebinding[1]){{"ptrace", my_ptrace, (void*)&orig_ptrace}}, 1);
}

#pragma mark - sysctl
/// sysctl 检查当前进程的调试标记
typedef int (*sysctl_ptr_t)(int *,u_int, void*, size_t*,void*, size_t);
static sysctl_ptr_t orig_sysctl = NULL;
int my_sysctl(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize);
typedef struct kinfo_proc _kinfo_proc;
int my_sysctl(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize) {
    int ret = orig_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
    if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && namelen == 4 && info && infosize && ((int)*infosize == sizeof(_kinfo_proc))) {//根据特征定位 sysctl 检测调试的代码
        struct kinfo_proc *info_ptr = (struct kinfo_proc *)info;
        if (info_ptr && (info_ptr->kp_proc.p_flag & P_TRACED) != 0) {//检测到调试被绕过
            info_ptr->kp_proc.p_flag ^= P_TRACED;//将被篡改的调试状态复原
            if ((info_ptr->kp_proc.p_flag & P_TRACED) == 0) {
                printf("\n⚠️⚠️⚠️sysctl 被成功绕过⚠️⚠️⚠️\n");
            }
        }
    }
    return ret;
}
/// sysctl 检查当前进程的调试标记
+ (void)antiDebugCheck_sysctl {
    rebind_symbols((struct rebinding[1]){{"sysctl", my_sysctl, (void*)&orig_sysctl}}, 1);
}

#pragma mark - syscall
/**
 * syscall -> ptrace
 * syscall -> sysctl
 */
 typedef int (*syscall_ptr_t)(int, ...);
static syscall_ptr_t orig_syscall = NULL;
int my_syscall(int code, ...);
int my_syscall(int code, ...) {
    //检测到syscall调用ptrace，直接返回
    va_list arg;
    va_start(arg, code);
    va_list narg;
    va_copy(narg, arg);
    int request = va_arg(arg, int);
    va_end(arg);
    if (code == SYS_ptrace) {
        if (request == PT_DENY_ATTACH) {
            printf("\n⚠️⚠️⚠️syscall_ptrace 被成功绕过⚠️⚠️⚠️\n");
            return 0;
        }
    }
    //检测到syscall调用sysctl检测调试标记
    if (code == SYS_sysctl) {
        va_list sysctl_arg;
        va_start(sysctl_arg, code);
        int *name = va_arg(sysctl_arg, int *);
        u_int namelen = va_arg(sysctl_arg, u_int);

        
        //传入需要构造的参数
        int newname[4];//指定査询信息的数组
        for (int i = 0; i < 4; i++) {
            newname[i] = name[i];
        }
        struct kinfo_proc newinfo;//査询的返回结果
        size_t newinfosize = sizeof(struct kinfo_proc);
        newinfo.kp_proc.p_flag = 0;
        void *newinfo_ptr = &newinfo;
        va_end(sysctl_arg);
        
        int ret = orig_syscall(code, newname, 4, &newinfo, &newinfosize, NULL, 0);
        if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && namelen == 4 && newinfo_ptr && newinfosize) {//根据特征定位 sysctl 检测调试的代码
            struct kinfo_proc *info_ptr = (struct kinfo_proc *)newinfo_ptr;
            if (info_ptr && (info_ptr->kp_proc.p_flag & P_TRACED) != 0) {//检测到调试被绕过
                info_ptr->kp_proc.p_flag ^= P_TRACED;//将被篡改的调试状态复原
                if ((info_ptr->kp_proc.p_flag & P_TRACED) == 0) {
                    printf("\n⚠️⚠️⚠️syscall_sysctl 被成功绕过⚠️⚠️⚠️\n");
                }
            }
        }
        return ret;
    }
    va_list orig_arg;
    va_start(orig_arg, code);
    int ret = orig_syscall(code, orig_arg);
    va_end(orig_arg);
    return ret;
}

+ (void)antiDebugCheck_syscall_summary {
    rebind_symbols((struct rebinding[1]){{"syscall", my_syscall, (void*)&orig_syscall}}, 1);
}

#pragma mark - dlsym
/// dlsym -> ptrace
typedef void* (*dlsym_ptr_t)(void * __handle, const char* __symbol);
static dlsym_ptr_t orig_dlsym = NULL;
void* my_dlsym(void* __handle, const char* __symbol);
void* my_dlsym(void* __handle, const char* __symbol){
    if (!strcmp(__symbol, "ptrace")) {
        printf("\n⚠️⚠️⚠️dlsym_ptrace 被成功绕过⚠️⚠️⚠️\n");
        return my_ptrace;
    }
    if (!strcmp(__symbol, "sysctl")) {
        printf("\n⚠️⚠️⚠️dlsym_sysctl 被成功绕过⚠️⚠️⚠️\n");
        return my_sysctl;
    }
    if (!strcmp(__symbol, "syscall")) {
        printf("\n⚠️⚠️⚠️dlsym_syscall 被成功绕过⚠️⚠️⚠️\n");
        return my_syscall;
    }
    return orig_dlsym(__handle, __symbol);
}

+ (void)antiDebugCheck_dlsym_summary {
    rebind_symbols((struct rebinding[1]){{"dlsym", my_dlsym, (void*)&orig_dlsym}}, 1);
}

@end
