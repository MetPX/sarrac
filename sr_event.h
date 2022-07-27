
#ifndef SR_EVENT_H
#define SR_EVENT_H 1

typedef unsigned char sr_event_s;

#define SR_EVENT_CREATE      ((sr_event_s)(0x01))
#define SR_EVENT_MODIFY      ((sr_event_s)(0x02))
#define SR_EVENT_LINK        ((sr_event_s)(0x04))
#define SR_EVENT_DELETE      ((sr_event_s)(0x08))
#define SR_EVENT_ATTRIB      ((sr_event_s)(0x10))
#define SR_EVENT_ERROR       ((sr_event_s)(0x20))
#define SR_EVENT_NONEXISTENT ((sr_event_s)(0x40))

sr_event_s sr_parse_events(char *);

#endif
