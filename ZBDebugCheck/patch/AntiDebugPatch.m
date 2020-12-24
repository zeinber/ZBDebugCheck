//
//  AntiDebugPatch.m
//  ZBDebugCheck
//
//  Created by 隐姓埋名 on 2020/12/24.
//  Copyright © 2020 展斌程. All rights reserved.
//

#import "AntiDebugPatch.h"
#import <mach/mach.h>
#import <sys/mman.h>

/// patch code
bool AntiDebug_patchCode(void* patch_addr, uint8_t* patch_data, int patch_data_size) {
    kern_return_t kret;
    task_t self_task = (task_t)mach_task_self();
    void* target_addr = patch_addr;
    
    // 获取目标的patch地址target_addr在PAGE页的起始地址以及偏移
    unsigned long page_start = (unsigned long) (target_addr) & ~PAGE_MASK;
    unsigned long patch_offset = (unsigned long)target_addr - page_start;

    // 使用mmap新建一块内存，把这块内存叫做new_page
    void *new_page = (void *)mmap(NULL, PAGE_SIZE, 0x1 | 0x2, 0x1000 | 0x0001, -1, 0);
    if (!new_page) {
        printf("\n❌❌❌mmap failed❌❌❌\n");
        return false;
    }
    
    // 使用vm_copy把想要篡改的处于__text段内的内存拷贝到new_page里
    kret = (kern_return_t)vm_copy(self_task, (unsigned long)page_start, PAGE_SIZE, (vm_address_t)new_page);
    if (kret != KERN_SUCCESS){
        printf("\n❌❌❌vm_copy faild❌❌❌\n");
        return false;
    }
    
    // 开始 patch，向new_page里将指定位置的指令改为nop
    /*
     nop -> {0x1f, 0x20, 0x03, 0xd5}
     ret -> {0xc0, 0x03, 0x5f, 0xd6}
     */
    memcpy((void *)((uint64_t)new_page + patch_offset), patch_data, patch_data_size);
    
    // 调用mprotect将newpage从rwx改为r-x
    mprotect(new_page, PAGE_SIZE, PROT_READ | PROT_EXEC);
    
    // remap
    vm_prot_t prot;
    vm_inherit_t inherit;
    // get page info
    vm_address_t region = (vm_address_t) page_start;
    vm_size_t region_len = 0;
    struct vm_region_submap_short_info_64 vm_info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t max_depth = 99999;
    kret = (kern_return_t)vm_region_recurse_64(self_task, &region, &region_len,
                                               &max_depth,
                                               (vm_region_recurse_info_t) &vm_info,
                                               &info_count);
    if (kret != KERN_SUCCESS) {
        printf("\n❌❌❌vm_region_recurse_64 faild❌❌❌\n");
        return false;
    }
    
    prot = vm_info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
    inherit = vm_info.inheritance;
    
    vm_prot_t c;
    vm_prot_t m;
    mach_vm_address_t target = (mach_vm_address_t)page_start;
    // xnu源码libsyscall/mach/mach_vm.c里有具体实现，符号其实存在，在此处申明方便调用
    extern kern_return_t mach_vm_remap(mach_port_name_t target,mach_vm_address_t *address,mach_vm_size_t size,mach_vm_offset_t mask,int flags,mach_port_name_t src_task,mach_vm_address_t src_address,boolean_t copy,vm_prot_t *cur_protection,vm_prot_t *max_protection,vm_inherit_t inheritance);
    // 调用mach_vm_remap把new_page的内容写回去
    kret = (kern_return_t)mach_vm_remap(self_task, &target, PAGE_SIZE, 0,
                                        VM_FLAGS_OVERWRITE, self_task,
                                        (uint64_t) new_page, true,
                                        &c, &m, inherit);
    if (kret != KERN_SUCCESS) {
        printf("\n❌❌❌remap mach_vm_remap faild❌❌❌\n");
        return false;
    }
    
    // clear cache
    void* clear_start_ = (void*)(page_start + patch_offset);
    extern void sys_icache_invalidate(void *start, size_t len);
    extern void sys_dcache_flush(void *start, size_t len);
    sys_icache_invalidate(clear_start_, 4);
    sys_dcache_flush(clear_start_, 4);
    return true;
}
