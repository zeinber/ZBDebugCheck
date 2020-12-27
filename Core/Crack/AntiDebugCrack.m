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
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import "AntiDebugPatch.h"

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
        [AntiDebugCrack antiDebugCheck_svc_summary];
        [AntiDebugCrack antiDebugCheck_isatty_summary];
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
    char *stack[8];
    va_list arg;
    va_start(arg, code);
    memcpy(stack, arg, 8 * 8);
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
    return orig_syscall(code,stack[0],stack[1],stack[2],stack[3],stack[4],stack[5],stack[6],stack[7]);
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

#pragma mark - svc
struct AntiDebugTextSegment {
    uint64_t start;
    uint64_t end;
};
///获取可执行文件的macho文件
uint32_t getMachOHeaderIndex(void) {
//    struct mach_header_64 *machHeader = NULL;
    uint32_t res_index = 0;
    uint32_t dyld_count = _dyld_image_count();
    for (uint32_t i = 0; i < dyld_count; i++) {
        @autoreleasepool {
            NSString *dyld_image_name = [NSString stringWithCString:_dyld_get_image_name(i) ?: "" encoding:NSUTF8StringEncoding];
            if ([dyld_image_name isEqualToString:[NSBundle mainBundle].executablePath]) {
                res_index = i;
                break;
            }
        }
    }
    return res_index;
}

/// 获取Section(__TEXT,__text)段运行时的地址区间
void getTextSegmentAddress(struct AntiDebugTextSegment *textSegment) {
    // 读取可执行文件在dyld加载的images里的下标
    uint32_t appMachOIndex = getMachOHeaderIndex();
    struct mach_header_64 *header = (struct mach_header_64*)_dyld_get_image_header(appMachOIndex);
    if (header->magic != MH_MAGIC_64) {
        return;
    }
    uint32_t offset = sizeof(struct mach_header_64);
    uint32_t ncmds = header->ncmds;
    while (ncmds--) {
        // 找到load_command里的__TEXT段
        struct load_command *lc = (struct load_command *)((uint8_t*)header + offset);
        offset += lc->cmdsize;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segment = (struct segment_command_64 *)lc;
            struct section_64 *section = (struct section_64*)((uint8_t*)segment + sizeof(struct segment_command_64));
            
            // 找到当前section是（__TEXT,__text）的段
            if (!strcmp(section->segname, "__TEXT") && !strcmp(section->sectname, "__text")) {
                uint64_t memoryAddr = section->addr;
                textSegment->start = memoryAddr + _dyld_get_image_vmaddr_slide(appMachOIndex);
                textSegment->end = textSegment->start + section->size;
                break;
            }
            
        }
    }
}

/// 查找svc 0x80相关的中断代码所在的节点，放入数组
NSMutableArray *getArrayFromLookupSvc(void* target_addr, uint64_t size) {
    uint8_t *p = (uint8_t*)target_addr;
    NSMutableArray *ptrArray = [NSMutableArray new];
    for (uint64_t i = 0; i < size; i++){
        /**
         mov x0, #31 -> 0xd28003e0
         mov x1, #0 -> 0xd2800001
         mov x2, #0 -> 0xd2800002
         mov x3, #0 -> 0xd2800003
         mov x16, #26 -> 0xd2800350
         svc #0x80  -> 0xd4001001
         */
        if (*((uint32_t*)p-4) == 0xd28003e0 && *((uint32_t*)p) == 0xd2800350 && *((uint32_t*)p+1) == 0xd4001001) {//svc->ptrace特征
            printf("\n🔍🔍🔍查找到svc_ptrace的指令🔍🔍🔍\n");
            [ptrArray addObject:@((uint64_t)p)];
        }
        /**
         mov x0, #26  -> 0xd2800340
         mov x1, #31  -> 0xd28003e1
         mov x2, #0  -> 0xd2800002
         mov x3, #0  -> 0xd2800003
         mov x4, #0  -> 0xd2800004
         mov x16, #0  -> 0xd2800010
         svc #0x80  -> 0xd4001001
         */
        else if (*((uint32_t*)p-5) == 0xd2800340 && *((uint32_t*)p-4) == 0xd28003e1 && *((uint32_t*)p) == 0xd2800010 && *((uint32_t*)p+1) == 0xd4001001) {//svc->syscall->ptrace特征
            printf("\n🔍🔍🔍查找到svc_syscall_ptrace的指令🔍🔍🔍\n");
            [ptrArray addObject:@((uint64_t)p)];
        }
        p++;
    }
    return [ptrArray copy];
}

+ (void)antiDebugCheck_svc_summary {
    struct AntiDebugTextSegment textSegment;
    getTextSegmentAddress(&textSegment);
    NSArray *svc_array = getArrayFromLookupSvc((void *)textSegment.start, textSegment.end - textSegment.start);
    if (!svc_array.count) {
        printf("\n❌❌❌svc pointer not found❌❌❌\n");
        return;
    }
    //nop的机器码
    uint8_t patch_ins_data[4] = {0x1f,0x20,0x03,0xd5};
    for (int i = 0; i < svc_array.count; i++) {
        uint8_t *svc_ptr = (uint8_t *)([svc_array[i] unsignedLongLongValue]);
        bool f = AntiDebug_patchCode(svc_ptr + 4,patch_ins_data, 4);
        printf("\n🎉🎉🎉patchStatus:%d🎉🎉🎉\n",f);
    }
}

#pragma mark - isatty
typedef int (*isatty_ptr_t)(int);
static isatty_ptr_t orig_isatty = NULL;
int my_isatty(int desc);
int my_isatty(int desc) {
    printf("\n⚠️⚠️⚠️isatty 被成功绕过⚠️⚠️⚠️\n");
    return 0;
}

+ (void)antiDebugCheck_isatty_summary {
    rebind_symbols((struct rebinding[1]){{"isatty", my_isatty, (void*)&orig_isatty}}, 1);
}

@end
