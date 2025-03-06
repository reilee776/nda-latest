#ifndef _ND_NIX_NFM_SESSIONS_V2_H__
#define _ND_NIX_NFM_SESSIONS_V2_H__

#include "nd_nix_nfm_common.h"

int nd_add_session_item (__u8 protocol, __u32 sip, __u32 dip, __u16 org_destport, __u16 fake_destport, __u16 clientport);

void remove_session_data(__u32 sip, __u32 dip, __u16 clientport);

struct session_data* nd_chk_session_item(__u32 sip, __u32 dip, __u16 org_destport);

int count_session_data(void);

#endif //_ND_NIX_NFM_SESSIONS_V2_H__
