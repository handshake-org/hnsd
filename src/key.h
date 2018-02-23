#ifndef _HSK_KEY_H
#define _HSK_KEY_H

#include <ldns/ldns.h>

ldns_key *
hsk_key_get(void);

ldns_key_list *
hsk_key_get_list(void);

ldns_rr *
hsk_key_get_dnskey(void);

ldns_rr *
hsk_key_get_ds(void);

bool
hsk_key_sign_rr_list(ldns_rr_list *an);

bool
hsk_key_sign(ldns_rr_list *an, ldns_rr_type type, bool dnssec);
#endif
