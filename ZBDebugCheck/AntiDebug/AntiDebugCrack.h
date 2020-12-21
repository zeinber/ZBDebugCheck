//
//  AntiDebugCrack.h
//  ZBCheckDebugCheck
//
//  Created by 隐姓埋名 on 2020/12/17.
//  Copyright © 2020 展斌程. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * 主要类主要是破解反调试的手段
 * 由于需要早于反调试代码执行，为方便测试，就在类加载的方法 + (void)load 内进行反调试破解
 */
@interface AntiDebugCrack : NSObject

@end

NS_ASSUME_NONNULL_END
