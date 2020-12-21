//
//  AppDelegate.m
//  ZBDebugCheck
//
//  Created by 隐姓埋名 on 2020/12/19.
//  Copyright © 2020 展斌程. All rights reserved.
//

#import "AppDelegate.h"
/// 反调试
#import "AntiDebugCheck.h"
/// 反反调试
#import "AntiDebugCrack.h"

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {

    ///反调试
#pragma mark - ptrace
    /// ptrace 阻止调试器附加
    [AntiDebugCheck antiDebugCheck_ptrace];

#pragma mark - sysctl
    /// sysctl 检查当前进程的调试标记
    [AntiDebugCheck antiDebugCheck_sysctl];

#pragma mark - syscall
    /// syscall -> ptrace
    [AntiDebugCheck antiDebugCheck_syscall_ptrace];
    /// syscall -> sysctl
    [AntiDebugCheck antiDebugCheck_syscall_sysctl];

#pragma mark - dlsym
    /// dlsym -> ptrace
    [AntiDebugCheck antiDebugCheck_dlsym_ptrace];
    /// dlsym -> sysctl
    [AntiDebugCheck antiDebugCheck_dlsym_sysctl];
    /// dlsym -> syscall -> ptrace
    [AntiDebugCheck antiDebugCheck_dlsym_syscall_ptrace];
    /// dlsym -> syscall -> sysctl
    [AntiDebugCheck antiDebugCheck_dlsym_syscall_sysctl];
    return YES;
}

#pragma mark - UISceneSession lifecycle


- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options {
    // Called when a new scene session is being created.
    // Use this method to select a configuration to create the new scene with.
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions {
    // Called when the user discards a scene session.
    // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
    // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
}


@end
