//
//  AntiDebugCheck.h
//  ZBCheckDebugCheck
//
//  Created by 隐姓埋名 on 2020/12/17.
//  Copyright © 2020 展斌程. All rights reserved.
//

#import <Foundation/Foundation.h>


/**
* 反调试的手段
*/

@interface AntiDebugCheck : NSObject
#pragma mark - ptrace
/// ptrace 阻止调试器附加
+ (void)antiDebugCheck_ptrace;

#pragma mark - sysctl
/// sysctl 检查当前进程的调试标记
+ (void)antiDebugCheck_sysctl;

#pragma mark - syscall
/// syscall -> ptrace
+ (void)antiDebugCheck_syscall_ptrace;
/// syscall -> sysctl
+ (void)antiDebugCheck_syscall_sysctl;

#pragma mark - dlsym
/// dlsym -> ptrace
+ (void)antiDebugCheck_dlsym_ptrace;
/// dlsym -> sysctl
+ (void)antiDebugCheck_dlsym_sysctl;
/// dlsym -> syscall -> ptrace
+ (void)antiDebugCheck_dlsym_syscall_ptrace;
/// dlsym -> syscall -> sysctl
+ (void)antiDebugCheck_dlsym_syscall_sysctl;

#pragma mark - svc
/// svc -> ptrace
+ (void)antiDebugCheck_svc_ptrace;
/// svc -> syscall -> ptrace
+ (void)antiDebugCheck_svc_syscall_ptrace;
/// svc -> sysctl
+ (void)antiDebugCheck_svc_sysctl;

#pragma mark - isatty
/// isatty
+ (void)antiDebugCheck_isatty;
@end
