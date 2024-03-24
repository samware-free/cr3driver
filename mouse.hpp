#pragma once

#include "definitions.hpp"

extern "C" POBJECT_TYPE* IoDriverObjectType;

typedef int BOOL;
typedef unsigned __int64 QWORD;

typedef VOID
(*MouseClassServiceCallbackFn)(
	PDEVICE_OBJECT DeviceObject,
	PMOUSE_INPUT_DATA InputDataStart,
	PMOUSE_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
	);
typedef struct _MOUSE_OBJECT
{
	PDEVICE_OBJECT              mouse_device;
	MouseClassServiceCallbackFn service_callback;
	BOOL                        use_mouse;
	QWORD                       target_routine;
} MOUSE_OBJECT, * PMOUSE_OBJECT;
namespace mouse {
	void mouse_move(long x, long y, unsigned short button_flags);
}
