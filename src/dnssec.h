#ifndef _HSK_DNSSEC_H
#define _HSK_DNSSEC_H

#include "ldns/ldns.h"

ldns_key *
hsk_dnssec_get_key(void);

ldns_key_list *
hsk_dnssec_get_list(void);

ldns_rr *
hsk_dnssec_get_dnskey(void);

ldns_rr *
hsk_dnssec_get_ds(void);

bool
hsk_dnssec_sign_rr_list(ldns_rr_list *an);

bool
hsk_dnssec_sign(ldns_rr_list *an, ldns_rr_type type, bool dnssec);
#endif
