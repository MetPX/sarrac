
#ifndef SR_EVENT_H
#define SR_EVENT_H 1

typedef unsigned char sr_event_s;

#define SR_CREATE ((sr_event_s)(0x01))
#define SR_MODIFY ((sr_event_s)(0x02))
#define SR_LINK   ((sr_event_s)(0x04))
#define SR_DELETE ((sr_event_s)(0x08))

sr_event_s sr_parse_events(char *);

#endif
