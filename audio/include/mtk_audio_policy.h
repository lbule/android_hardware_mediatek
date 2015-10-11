
#ifndef ANDROID_MTK_AUDIO_POLICY_INTERFACE_H
#define ANDROID_MTK_AUDIO_POLICY_INTERFACE_H

#include <hardware/audio_policy.h>

struct mtk_audio_policy : audio_policy {
    int (*set_policy_parameters)(struct audio_policy *pol,int par1, int par2 ,int par3,int par4);
};

#endif  // ANDROID_MTK_AUDIO_POLICY_INTERFACE_H
