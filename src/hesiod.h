#ifndef _HSK_hesiod_
#define _HSK_hesiod_

#include "dns.h"
#include "req.h"

hsk_dns_msg_t *
hsk_hesiod_resolve(hsk_dns_req_t *req, hsk_ns_t *ns);

#endif
