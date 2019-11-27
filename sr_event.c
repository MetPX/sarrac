
#include <string.h>

#include "sr_event.h"

static void str2event(char *evstr, sr_event_s * evbm)
{
	if (!strcmp(evstr, "modify"))
		(*evbm) |= SR_MODIFY;
	if (!strcmp(evstr, "link"))
		(*evbm) |= SR_LINK;
	if (!strcmp(evstr, "delete"))
		(*evbm) |= SR_DELETE;
	if (!strcmp(evstr, "create"))
		(*evbm) |= SR_CREATE;
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
