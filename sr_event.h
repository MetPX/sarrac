
#ifndef SR_EVENT_H
#define SR_EVENT_H 1

typedef unsigned char sr_event_s;

#define SR_EVENT_CREATE      ((sr_event_s)(0x001))
#define SR_EVENT_MODIFY      ((sr_event_s)(0x002))
#define SR_EVENT_LINK        ((sr_event_s)(0x004))
#define SR_EVENT_DELETE      ((sr_event_s)(0x008))
#define SR_EVENT_ATTRIB      ((sr_event_s)(0x010))
#define SR_EVENT_MKDIR       ((sr_event_s)(0x020))
#define SR_EVENT_RMDIR       ((sr_event_s)(0x040))
#define SR_EVENT_ERROR       ((sr_event_s)(0x400))
#define SR_EVENT_NONEXISTENT ((sr_event_s)(0x800))

sr_event_s sr_parse_events(char *);

#endif
