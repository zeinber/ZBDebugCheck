//
//  AntiDebugCheck.h
//  ZBCheckDebugCheck
//
//  Created by 隐姓埋名 on 2020/12/17.
//  Copyright © 2020 展斌程. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

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

@end

NS_ASSUME_NONNULL_END
