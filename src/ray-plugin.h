#ifndef __RAY_PLUGIN_H__
#define __RAY_PLUGIN_H__

#define HAVE_RAY_PLUGIN

#include "ray-plugin-ext.h"


void RayPluginLoad(void);
void RayPluginInit(void);
void RayPluginDestroy(void);

void RayPluginCallPointDecode(ThreadVars *, Packet *);
void RayPluginCallPointFlowWorker(ThreadVars *, Packet *);
void RayPluginCallPointStreamState(ThreadVars *, Packet *);
void RayPluginCallPointAppDetectEnd(ThreadVars *, Packet *);
void RayPluginCallPointAppParse(ThreadVars *, Packet *);
void RayPluginCallPointDetectSgh(ThreadVars *, Packet *, void *);
void RayPluginCallPointDetectNone(ThreadVars *, Packet *);
void RayPluginCallPointDetectEnd(ThreadVars *, Packet *);
void RayPluginCallPointOutputFileData(ThreadVars *, Packet *, void *);
void RayPluginCallPointOutput(ThreadVars *, Packet *);

#endif /* __RAY_PLUGIN_H__ */
