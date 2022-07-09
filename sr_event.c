
#include <string.h>
#include <stdbool.h>

#include "sr_event.h"

/*
 * 
 * FIXME: No error handling! if you mis-spell an event, it just sucks to be you! 
 */
static void str2event(char *evstr, sr_event_s * evbm)
{
        bool found=false;

	if (!strcmp(evstr, "modify")) {
		(*evbm) |= SR_EVENT_MODIFY;
                found=true;
        }
	if (!strcmp(evstr, "link")) {
		(*evbm) |= SR_EVENT_LINK;
                found=true;
        }
	if (!strcmp(evstr, "delete")) {
		(*evbm) |= SR_EVENT_DELETE;
                found=true;
        }
	if (!strcmp(evstr, "create")) {
		(*evbm) |= SR_EVENT_CREATE;
                found=true;
        }
	if (!strcmp(evstr, "attrib")) {
		(*evbm) |= SR_EVENT_ATTRIB;
                found=true;
        }
    
	if (!strcmp(evstr, "default")) {
		(*evbm) |= SR_EVENT_DEFAULT;
                found=true;
        }
    
        if (!found) {
        	(*evbm) |= SR_EVENT_ERROR ;
        }
}

sr_event_s sr_parse_events(char *el)
{
	char *es;
	sr_event_s e;

	e = 0;
	es = strtok(el, ",");
	while (es) {
		str2event(es, &e);
		es = strtok(NULL, ",");
	}
	return (e);
}
