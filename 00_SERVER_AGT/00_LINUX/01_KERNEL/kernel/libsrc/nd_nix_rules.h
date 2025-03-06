#ifndef _ND_NIX_NFM_RULES_V2_H__
#define _ND_NIX_NFM_RULES_V2_H__

#include "../nd_nix_nfm_common.h"
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

int nd_get_struct_data_by_type(char * szData, struct cmd_service_rule_pars_data *_data);
#ifdef ND_OLD_RULE_TUPE
int nd_check_targetItem_in_targetlinkedlist(struct list_head *head,void * struct_data, __u32 uType);
#endif //ND_OLD_RULE_TUPE

int nd_nfm_chk_rule_v2( struct nd_5tuple_data tuples, __u16 *forwardport);
int nd_nfm_comfirm_the_policy_for_incoming_packet(struct nd_5tuple_data tuples, struct /*nd_packets_applied_to_policy*/ nd_modifled_packet_result ** _collect_data );

int nd_add_service(__u16 _uService, __u16 _uForwardPort, __u32 _uMode,char * _sErrMsg);
int nd_mod_service_to_index(struct cmd_service_rule_pars_data* service_data);
int nd_del_service(__u16 _uService, char * _sErrMsg);
int nd_nfm_get_service_rule_index(__u16 _uService);

int nd_add_action_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _SipRange, __u32 _uEipAddr, char * _sErrMsg);
int nd_add_action_in_service_rule_for_struct(struct cmd_service_sub_rule_pars_data* sub_rule, char * _sErrMsg);
int nd_mod_action_in_service_rule_to_index(struct cmd_service_sub_rule_pars_data* sub_rule);
int nd_del_action_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uSipRange,__u32 _uEipAddr, char * _ErrMsg);
int nd_get_actions_in_service_rule_to_index(struct cmd_service_sub_rule_pars_data* sub_rule);


int nd_reset_all_rule (void);

int nd_nfm_get_service_rules(char *output);
int nd_nfm_get_action_rules(char * output);

int nd_nfm_add_nic_rule (struct cmd_nic_rule_pars_data * pNicData ,char * sErrCode);
int nd_nfm_del_nic_rule (struct cmd_nic_rule_pars_data * pNicData ,char * sErrCode);
int nd_nfm_reset_nic_rules (void);
#ifdef _OLD_SRC
int nd_nfm_chk_nic_rule ( const char *name, const unsigned char *dev_addr );
#endif

int nd_nfm_chk_nic_rule (struct in_ifaddr * ifa);

int nd_nfm_add_bypass_rule(struct cmd_bypass_rule_pars_data *bypass_rule, char * acErrMsg );
int nd_nfm_del_bypass_rule (struct cmd_bypass_rule_pars_data *bypass_rule, char *acErrMsg );
int nd_nfm_check_bypass_rule( __u32 sourceIpAddr );
int nd_nfm_reset_bypass_rule (void);

#endif

