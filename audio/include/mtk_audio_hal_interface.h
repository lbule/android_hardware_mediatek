
#ifndef MTK_AUDIO_HAL_INTERFACE_H
#define MTK_AUDIO_HAL_INTERFACE_H

#include <hardware/audio.h>

__BEGIN_DECLS

struct audio_hw_device_mtk {
    struct audio_hw_device legacy_hw_device;
    int (*SetEMParameter)(struct audio_hw_device_mtk *dev,void *ptr , int len);
    int (*GetEMParameter)(struct audio_hw_device_mtk *dev,void *ptr , int len);
    int (*SetAudioCommand)(struct audio_hw_device_mtk *dev,int par1 , int par2);
    int (*GetAudioCommand)(struct audio_hw_device_mtk *dev,int par1);
    int (*SetAudioData)(struct audio_hw_device_mtk *dev,int par1,size_t len,void *ptr);
    int (*GetAudioData)(struct audio_hw_device_mtk *dev,int par1,size_t len,void *ptr);
    int (*SetACFPreviewParameter)(struct audio_hw_device_mtk *dev,void *ptr , int len);
    int (*SetHCFPreviewParameter)(struct audio_hw_device_mtk *dev,void *ptr , int len);
};
typedef struct audio_hw_device_mtk audio_hw_device_mtk_t;

__END_DECLS

#endif  // MTK_AUDIO_HAL_INTERFACE_H
