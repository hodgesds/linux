/* SPDX-License-Identifier: MIT */

#ifndef __DRM_DUMB_BUFFERS_H__
#define __DRM_DUMB_BUFFERS_H__

#include <linux/types.h>

struct drm_device;
struct drm_file;
struct drm_mode_create_dumb;

int drm_mode_create_dumb(struct drm_device *dev,
			 struct drm_mode_create_dumb *args,
			 struct drm_file *file_priv);
int drm_mode_destroy_dumb(struct drm_device *dev, u32 handle,
			  struct drm_file *file_priv);

#endif
