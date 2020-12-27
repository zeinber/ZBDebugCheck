//
//  AntiDebugPatch.h
//  ZBDebugCheck
//
//  Created by 隐姓埋名 on 2020/12/24.
//  Copyright © 2020 展斌程. All rights reserved.
//

#import <Foundation/Foundation.h>
/// patch code
bool AntiDebug_patchCode(void* patch_addr, uint8_t* patch_data, int patch_data_size);
