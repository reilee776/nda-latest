#include "nd_nix_rules.h"

#include <linux/string.h>
#include "nd_nix_util_str.h"

static DEFINE_RAW_SPINLOCK(nd_raw_spinlock);

/*
 *
 */
int nd_nfm_chk_iprang(__u32 ip, __u32 start, __u32 end)
{
	if (start > end)		{
		return 0;
	}
	
        if ((ip & 0xFFFFFF00) != (start & 0xFFFFFF00) || (ip & 0xFFFFFF00) != (end & 0xFFFFFF00)) {

                return 0;
        }

        return (ip >= start && ip <= end);
}

/*
 *
 */
static int nd_checkTargetInList(struct list_head *head,void * struct_data, __u32 uType)
{
	struct nd_service_rule_data_new *service, *service_temp;
	struct nd_service_act_rule_data* action, *action_tmp;
	struct list_head        *pos, *next;

	if (list_empty(head))             {

			return ND_CHECK_NO; // notfound
	}

	if (uType == INDX_RULE_TYPE_SERVICE)            {

		service = (struct nd_service_rule_data_new*)struct_data;
		list_for_each_safe (pos, next, head)    {
			service_temp = list_entry ( pos, struct nd_service_rule_data_new, list );
			if (!service_temp)              {
					return ND_CHECK_NO; // error
			}

			if (service_temp->service == service->service)  {
					return ND_CHECK_OK;
			}
		}
	}

	else if (uType == INDX_RULE_TYPE_ACTION)		{
		action = (struct nd_service_act_rule_data*)struct_data;
		list_for_each_safe (pos, next, head)		{
			action_tmp = list_entry (pos, struct nd_service_act_rule_data, list);
			if (!action_tmp)		{

				return ND_CHECK_NO;	
			}

			if (action_tmp->startIpaddr == action_tmp->endIpaddr && action->startIpaddr == action->endIpaddr)
			{
				if (action_tmp->startIpaddr == action->startIpaddr)
				{
					//printk (KERN_ERR "same target ipaddress.......already exist.. (%d)(%d)", action_tmp->startIpaddr, action->startIpaddr);
					return ND_CHECK_OK;
				}
			}

			else
			{
				if (action_tmp->startIpaddr == action->startIpaddr && action_tmp->endIpaddr == action->endIpaddr)
				{
					//printk (KERN_ERR "same target range ipaddress...... already exist..(%d)(%d)|(%d)(%d)",action_tmp->startIpaddr, action->startIpaddr, action_tmp->endIpaddr,  action->endIpaddr);
					return ND_CHECK_OK;
				}
				
			}
#ifdef _OLD_SRC
			
			if (action_tmp->nType == INDX_RULE_IPADDR_SPECIFIC  )
			{
				if (action_tmp->startIpaddr == action->startIpaddr)
				{
					return ND_CHECK_OK;
				} 
			}

			else if (action_tmp->nType == INDX_RULE_IPADDR_HOSTRANGE)
			{
				if ((action_tmp->startIpaddr == action->startIpaddr && action_tmp->startIprange == action->startIprange))
				{
					return ND_CHECK_OK;
				}
				/*
				if (nd_nfm_chk_iprang(action_tmp->startIpaddr, action->startIpaddr, action->startIpaddr + action->startIprange))
				{
					return ND_CHECK_OK;
				}
				*/
			}

			else if (action->nType == INDX_RULE_IPADDR_SUBNET )
                        {

                        }

			else
			{

			}
#endif //_OLD_SRC
		}
	}

	else		{

		return ND_CHECK_NO;
	}
	
	return ND_CHECK_NO;
}

/*
 *
 */
int nd_nfm_get_rule_info(char *output )
{
	return 0;
}

/*
 *
 */
int nd_nfm_chk_rule_v2( struct nd_5tuple_data tuples, __u16 *forwardport)
{
	struct nd_service_rule_data_new *service;
	struct nd_service_act_rule_data *action;
	struct list_head *spos, *snext, *actpos, *actnext;

	__u16 service_port 	= 0;
	__u16 standard_port 	= 0;
	__u32 action_saddr 	= 0;
	__u32 action_daddr	= 0;

	int result 		= ND_PLOICY_NONE;

	list_for_each_safe (spos, snext, &nd_list_service_rules_new.list)          {

		service = list_entry (spos, struct nd_service_rule_data_new, list );
                if (!service)      {
                        return ND_PLOICY_EXCLUSION;
                }

                if (tuples.hook == NF_INET_PRE_ROUTING)         {
                        service_port    = tuples.dport;
                        standard_port   = service->service;
                        action_saddr    = tuples.saddr;
			action_daddr	= tuples.daddr;
                }

                else if (tuples.hook == NF_INET_LOCAL_OUT)      {
                        service_port    = tuples.sport;
                        standard_port   = service->forwardport;
                        action_saddr    = tuples.daddr;
			action_daddr	= tuples.saddr;
                }

		if (standard_port == service_port )             {

			list_for_each_safe (actpos, actnext, &service->act_rule.list)	{
				
				action = list_entry (actpos, struct nd_service_act_rule_data, list);
				if (action)
				{

					if (action->nType == INDX_RULE_IPADDR_SPECIFIC)
					{
						if (action->startIpaddr == action_saddr/* &&
							action->endIpaddr == action_daddr*/)	
						{
							result = ND_POLICY_APPLY;
						}
					}

					else if (action->nType == INDX_RULE_IPADDR_HOSTRANGE)
					{
						if (nd_nfm_chk_iprang(action_saddr, action->startIpaddr, action->startIpaddr + action->startIprange))	
						{
							result = ND_POLICY_APPLY;
						}
					}

					else if (action->nType == INDX_RULE_IPADDR_SUBNET)
					{
						
					}

					else
					{

					}
				}

			}

			if (tuples.hook == NF_INET_PRE_ROUTING)	
			{
				*forwardport = service->forwardport;

			}
			
			else if (tuples.hook == NF_INET_LOCAL_OUT)
			{
				*forwardport = service->service;
			}

			else
			{

			}
		}
	}

	return result;
}

/*
 *
 */
int nd_nfm_comfirm_the_policy_for_incoming_packet(struct nd_5tuple_data tuples, struct nd_modifled_packet_result ** _collect_data )
{
	struct nd_service_rule_data_new     *service;
	struct nd_service_act_rule_data		*action;
	struct list_head 					*pos, *next;
	struct list_head 					*actpos, *actnext;

	__u32 _uSourceAddr = 0;
	__u32 _uDestinationAddr = 0;

        bool bIstargetService = false;
        int retChkdata = ND_ACT_FLOWRULE_NOTFOUND;

	if (!_collect_data || !*_collect_data)		{
		//return ND_ACT_FLOWRULE_INVALID_PTR;
		//printk(KERN_ERR "nd_nfm_comfirm_the_policy_for_incoming_packet  ND_ACT_FLOWRULE_FASS 001:");
		return ND_ACT_FLOWRULE_FASS;
	}

	if (list_empty (&nd_list_service_rules_new.list ))      {
		//printk(KERN_ERR "nd_nfm_comfirm_the_policy_for_incoming_packet  ND_ACT_FLOWRULE_FASS 002");
                return ND_ACT_FLOWRULE_FASS;
        }

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list) 	{

                service = list_entry (pos, struct nd_service_rule_data_new, list);
                if (!service ) continue;

		if (tuples.hook == NF_INET_PRE_ROUTING)         
		{
			if (nd_nfm_check_bypass_rule (tuples.saddr) == ND_CHECK_OK)     {
				//printk(KERN_ERR "nd_nfm_comfirm_the_policy_for_incoming_packet NF_INET_PRE_ROUTING bypass~~~");
                		return ND_ACT_FLOWRULE_FASS;
        		}

			
			if (service->service == tuples.dport)           {
				//printk(KERN_ERR "nd_nfm_comfirm_the_policy_for_incoming_packet  ND_ACT_FLOWRULE_FASS 003:");
				bIstargetService 	= true;
				_uSourceAddr 		= tuples.saddr;
				_uDestinationAddr 	= tuples.daddr;
				break;
			}
		}

		else if(tuples.hook == NF_INET_LOCAL_OUT)               
		{

			if (nd_nfm_check_bypass_rule (tuples.daddr) == ND_CHECK_OK)     {
                		return ND_ACT_FLOWRULE_FASS;
        		}

			if (service->forwardport == tuples.sport)                  {
				bIstargetService 	= true;
				_uSourceAddr 		= tuples.daddr;
				_uDestinationAddr 	= tuples.saddr;
				break;
			}
		}
		
		else
		{
			return ND_ACT_FLOWRULE_FASS;
		}
	}

	if (!bIstargetService)           {
		return ND_ACT_FLOWRULE_FASS;
	}

#ifdef _NEED_IP_ACTION_RULE
	if (list_empty (&service->act_rule.list))	{

		return ND_ACT_FLOWRULE_FASS;
	}

	list_for_each_safe (actpos, actnext, &service->act_rule.list)
	{
		action = list_entry (actpos, struct nd_service_act_rule_data, list);
		if (!action) continue;
		
		switch (action->nType)		{
			case INDX_RULE_IPADDR_SPECIFIC:
				if (action->startIpaddr == _uSourceAddr)	{
					retChkdata              = ND_ACT_FLOWRULE_APPLY;
					break;
				}
				break;

			case INDX_RULE_IPADDR_HOSTRANGE:
				if (nd_nfm_chk_iprang(_uSourceAddr, action->startIpaddr, action->startIpaddr+ action->startIprange))	{
				
					retChkdata              = ND_ACT_FLOWRULE_APPLY;
                                        break;
				}
				break;
			case INDX_RULE_IPADDR_SUBNET:
				break;

			default:
				break;
		}

		if (retChkdata == ND_ACT_FLOWRULE_APPLY)        {

                	break;
                }
	}

	if (retChkdata != ND_ACT_FLOWRULE_APPLY)	{
		return ND_ACT_FLOWRULE_FASS;
	}

#else	//_NEED_IP_ACTION_RULE
	retChkdata              = ND_ACT_FLOWRULE_APPLY;
#endif //_NEED_IP_ACTION_RULE

	if (tuples.hook == NF_INET_PRE_ROUTING) {
		(*_collect_data)->serviceport = tuples.saddr;
		(*_collect_data)->forwardport = service->forwardport;
	}
	else if (tuples.hook == NF_INET_LOCAL_OUT )     {
		(*_collect_data)->serviceport = tuples.saddr;
		(*_collect_data)->forwardport = service->service;
	}



        return retChkdata;	
}

/*
 *
 */
int nd_add_service(__u16 _uService, __u16 _uForwardPort, __u32 _uMode, char * _sErrMsg)
{
	struct nd_service_rule_data_new *service_rule;
    struct list_head *pos, *next;

	if (!list_empty (&nd_list_service_rules_new.list))
	{
		list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

			service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
			if (service_rule)
			{
				if (service_rule->service == _uService)         {

					sprintf (_sErrMsg, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004505);	
					return ND_ERROR_ALREADEXIST_RULE;
				}
			}
		}
	}

	service_rule = kmalloc (sizeof (struct nd_service_rule_data_new), GFP_KERNEL );
	if (!service_rule)		{
		sprintf (_sErrMsg, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004550);
		return ND_ERROR_ALREADEXIST_RULE;
	}

	raw_spin_lock (&nd_raw_spinlock );

	service_rule->service   	= _uService;
	service_rule->forwardport  	= _uForwardPort;
	service_rule->mode      	= _uMode;

	INIT_LIST_HEAD (&service_rule->act_rule.list);
	INIT_LIST_HEAD (&service_rule->list);

	list_add_tail (&service_rule->list, &nd_list_service_rules_new.list);

	raw_spin_unlock (&nd_raw_spinlock );

	return ND_ERROR_SUCCESS;
}

/*
 *
 */
int nd_mod_service_to_index(struct cmd_service_rule_pars_data* service_data)
{
	struct nd_service_rule_data_new *service;
	struct list_head *pos, *next;
	int index = 0;

	if (service_data == NULL )
	{
			return -1;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list) {

			service = list_entry (pos, struct nd_service_rule_data_new, list );
			if (service)            {

					if (index == service_data->ret)      {

							service->service        = service_data->service;
							service->forwardport    = service_data->forward;
							service->mode           = service_data->data;

							return 0;
					}
					index ++;
			}
	}

	return 0;
}

/*
 *
 */
int nd_del_service(__u16 _uService, char * _sErrMsg)
{
	struct nd_service_rule_data_new *service;
	struct nd_service_act_rule_data *action;
	struct list_head *pos, *next;
	struct list_head *actpos, *actnext;
	bool bFinded = false;


	if (!list_empty (&nd_list_service_rules_new.list))
	{
			list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

					service = list_entry (pos, struct nd_service_rule_data_new, list);
					if (service)
					{
							if (service->service == _uService)         {
									bFinded = true;
									break;
							}
					}
			}
	}

	if (bFinded == false    )               {

			//failed to delete target service rule - [%u] is not found\n", _uService
	sprintf (_sErrMsg , "%s",ND_ERROR_NIXNK_LKMIRQ_M_004507);
			return -1;
	}

	raw_spin_lock( &nd_raw_spinlock);
        list_for_each_safe (pos, next, &nd_list_service_rules_new.list) 
	{
        service = list_entry (pos, struct nd_service_rule_data_new, list );
		if (service && service->service == _uService )  {
			if (!list_empty (&service->act_rule.list))
			{
				list_for_each_safe (actpos, actnext, &service->act_rule.list)	
				{
					action = list_entry (actpos, struct nd_service_act_rule_data, list);
					if (action)
					{
						list_del(actpos);
						kfree (action);
					}
				} 
			}
			
					
			list_del (pos);
			kfree (service);

			raw_spin_unlock (&nd_raw_spinlock );

			return 0;
		}
	}

	sprintf (_sErrMsg, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004506);
	
	raw_spin_unlock (&nd_raw_spinlock );
    return -1;

}

/*
 *
 */
int nd_nfm_get_service_rule_index(__u16 _uService)
{
	struct nd_service_rule_data_new *service_rule;
    struct list_head * pos, * next;
    int index = 0;

	if (!list_empty (&nd_list_service_rules_new.list ))     {

		list_for_each_safe (pos, next,  &nd_list_service_rules_new.list)        {
			service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
			if (service_rule )
			{
					if (service_rule->service == _uService) {
							return index;
					}

					index ++;
			}
		}
	}

    return -1;
}

/*
	//
*/
#ifdef _reserve_func
static int add_action_to_service_rule(struct nd_service_rule_data_new *service_rule, 
                                       __u32 _uSipAddr, __u32 _uSipRange, __u32 _uType, 
                                       char *_sErrMsg) 		{

	struct nd_service_act_rule_data *action = kmalloc(sizeof(struct nd_service_act_rule_data), GFP_KERNEL);
	if (!action) {
		//set_error_message(_sErrMsg, ND_ERROR_NIXNK_LKMIRQ_M_004550);
		return -1;
	}

	action->startIpaddr = _uSipAddr;
	action->startIprange = _uSipRange;
	action->nType = _uType;

	if (!list_empty(&service_rule->act_rule.list)) {
		int ret = nd_checkTargetInList(&service_rule->act_rule.list, action, INDX_RULE_TYPE_ACTION);
		if (ret == ND_CHECK_OK) {
			kfree(action);
		    	//set_error_message(_sErrMsg, ND_ERROR_NIXNK_LKMIRQ_M_004510);
		    	return -1;
		}
	}

	INIT_LIST_HEAD(&action->list);
	raw_spin_lock(&nd_raw_spinlock);
	list_add_tail(&action->list, &service_rule->act_rule.list);
	raw_spin_unlock(&nd_raw_spinlock);

	return 0;
}
#endif //reserve

/*
* backup src
*/
int nd_add_action_in_service_rule_bak(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uSipRange, __u32 _uEipAddr, char *_sErrMsg)
{
	struct nd_service_rule_data_new *service_rule;
	struct nd_service_act_rule_data *action;
	struct list_head * pos, *next;
	int ret = 0;

	bool bFinded = false, bFindedService = false;

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

	    if (list_empty (&nd_list_service_rules_new.list) )
	    {
		    sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004508);
		    return -1;
	    }
	    service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
	    if (!service_rule)      {
		    sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004509);
		    return -1;
	    }

	    if (service_rule->service == _uService )                {

		    bFindedService = true;

		    action = kmalloc (sizeof(struct nd_service_act_rule_data), GFP_KERNEL );
		    if (!action)       {
			    sprintf (_sErrMsg, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004550);
			    return -1;
		    }

		    action->startIpaddr = _uSipAddr;
		    action->startIprange= _uSipRange;
		    action->endIpaddr   = _uEipAddr;
		    action->nType       = _uType;

		    if (!list_empty (&service_rule->act_rule.list))       {

			    ret = nd_checkTargetInList (&service_rule->act_rule.list, action, INDX_RULE_TYPE_ACTION);
			    if (ret == ND_CHECK_OK )
			    {
				    bFinded = true;
			    }
		    }
	    }
	}

	if (bFindedService == false)
	{
	    sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004508);
	    return -1;
	}

	if (bFinded == true )
	{
	    sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004509);
	    return -1;
	}

	if (action)
	{
	    kfree (action);
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)
	{
	    service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
	    if (!service_rule)      {
		    sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004508);
		    raw_spin_unlock (&nd_raw_spinlock);
		    return -1;
	    }

	    if (service_rule->service == _uService )
	    {

		    action = kmalloc (sizeof(struct nd_service_act_rule_data), GFP_KERNEL);
		    if (!action)
		    {
			    sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004550);
			    raw_spin_unlock (&nd_raw_spinlock);
			    return -1;
		    }

		    action->startIpaddr = _uSipAddr;
		    action->startIprange= _uSipRange;
		    action->endIpaddr	= _uEipAddr;
		    action->nType       = _uType;

		    if (!list_empty (&service_rule->act_rule.list))
		    {
			    ret = nd_checkTargetInList (&service_rule->act_rule.list, action, INDX_RULE_TYPE_ACTION);
			    if (ret == ND_CHECK_OK)
			    {
				    kfree (action);
				    sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004510);
				    raw_spin_unlock (&nd_raw_spinlock);
				    return -1;
			    }
		    }

		    raw_spin_lock (&nd_raw_spinlock);

		    INIT_LIST_HEAD (&action->list);
		    list_add_tail (&action->list, &service_rule->act_rule.list);

		    raw_spin_unlock (&nd_raw_spinlock);
		    return 0;
	    }
	}

	raw_spin_unlock (&nd_raw_spinlock);

	return -1;

}

/*
 *  
*/
int nd_add_action_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uSipRange, __u32 _uEipAddr, char *_sErrMsg)
{
	struct nd_service_rule_data_new *service_rule;
	struct nd_service_act_rule_data *action;
	struct list_head * pos, *next;
	int ret = 0;

	bool bFindedService = false;

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

		if (list_empty (&nd_list_service_rules_new.list) )
		{
			sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004508);
			return -1;
		}

		service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
		if (!service_rule)      {
			sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004509);
			return -1;
		}

		if (service_rule->service == _uService )                {

			bFindedService = true;

			action = kmalloc (sizeof(struct nd_service_act_rule_data), GFP_KERNEL );
			if (!action)       {
					sprintf (_sErrMsg, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004550);
					return -1;
			}

			action->startIpaddr = _uSipAddr;
			action->startIprange= _uSipRange;
			action->endIpaddr   = _uEipAddr;
			action->nType       = _uType;

			raw_spin_lock(&nd_raw_spinlock);

			if (!list_empty (&service_rule->act_rule.list))       {

				ret = nd_checkTargetInList (&service_rule->act_rule.list, action, INDX_RULE_TYPE_ACTION);
				if (ret == ND_CHECK_OK )
				{
					kfree(action);
					raw_spin_unlock(&nd_raw_spinlock);
					sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004510);
					return -1;
				}
			}

			INIT_LIST_HEAD(&action->list);
			list_add_tail (&action->list, &service_rule->act_rule.list);
			raw_spin_unlock(&nd_raw_spinlock);

			return 0;
		}
	}

	if (!bFindedService)
	{
		return -1;
	}

    return -1;
}

/*
 *
 */
int nd_add_action_in_service_rule_for_struct(struct cmd_service_sub_rule_pars_data* sub_rule, char * _sErrMsg)
{
	struct nd_service_rule_data_new *service;
	struct nd_service_act_rule_data *action;
	struct list_head *pos, *next;
	int  ret = 0;
	bool bFinded = false, bFindedService = false;

	if (sub_rule == NULL)   {
		return -1;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

		if (list_empty (&nd_list_service_rules_new.list) )
		{
			sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004508);
			return ND_ERROR_DATA_EMPTY;
		}

		service = list_entry (pos , struct nd_service_rule_data_new, list );
		if (!service)      {
			sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004509);
			return ND_ERROR_DATA_EMPTY;
		}

		if (service->service ==  sub_rule->service )                {

			bFindedService = true;
			action = kmalloc (sizeof(struct nd_service_act_rule_data), GFP_KERNEL );
			if (!action)       {
				sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004550);
						return ND_ERROR_ENOMEM;
			}

			action->startIpaddr =  sub_rule->saddr;
			action->startIprange=  sub_rule->s_range;
			action->nType       =  sub_rule->type;

			if (!list_empty (&service->act_rule.list))       {

				ret = nd_checkTargetInList (&service->act_rule.list, action, INDX_RULE_TYPE_ACTION);
				if (ret == ND_CHECK_OK )
				{
						bFinded = true;
				}
			}
		}
	}

	if (bFindedService == false)
	{
		sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004508);
		return ND_ERROR_ENOMEM;
	}

	if (bFinded == true )
	{
		sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004510);
		return ND_ERROR_ALREADEXIST_RULE;
	}

	if (action)
	{
		kfree (action);
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)
	{
		service = list_entry (pos , struct nd_service_rule_data_new, list );
		if (!service)      {
			sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004509);
			return -1;
		}

		if (service->service == sub_rule->service )
		{
			action = kmalloc (sizeof(struct nd_service_act_rule_data), GFP_KERNEL);
			if (!action)
			{
				sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004550);
				return ND_ERROR_ENOMEM;
			}

			action->startIpaddr =  sub_rule->saddr;
			action->startIprange=  sub_rule->s_range;
			action->nType       =  sub_rule->type;

			if (!list_empty (&service->act_rule.list))
			{
				ret = nd_checkTargetInList (&service->act_rule.list, action, INDX_RULE_TYPE_ACTION);
				if (ret == ND_CHECK_OK)
				{
						kfree (action);
						sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004510);
						return ND_ERROR_ALREADEXIST_RULE;
				}
			}

			raw_spin_lock (&nd_raw_spinlock);

			INIT_LIST_HEAD (&action->list);
			list_add_tail (&action->list, &service->act_rule.list);

			raw_spin_unlock (&nd_raw_spinlock);
			return 0;
		}
	}

    return -1;
}

/*
 *
 */
int nd_mod_action_in_service_rule_to_index(struct cmd_service_sub_rule_pars_data* sub_rule)
{
	struct nd_service_rule_data_new *service;
	struct nd_service_act_rule_data *action;
	struct list_head *pos, *next, *actpos, *actnext;
	int index = 0;

	if (sub_rule == NULL)   {
		return -1;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list) 	{

		service = list_entry (pos, struct nd_service_rule_data_new, list );
		if (service)            {

			if (service->service == sub_rule->service)      {

				if (!list_empty(&service->act_rule.list))     {

					list_for_each_safe (actpos, actnext, &service->act_rule.list)     {

						action = list_entry (actpos, struct nd_service_act_rule_data, list);
						if (action && (sub_rule->ret == index))
						{
								raw_spin_lock (&nd_raw_spinlock );

								action->nType       = sub_rule->type;
								action->startIpaddr = sub_rule->saddr;
								action->startIprange= sub_rule->s_range;

								raw_spin_lock (&nd_raw_spinlock );
								return 0;
						}

						index ++;
					}
				}
			}
		}
	}

	return -1;

}

/*
 *
 */
int nd_del_action_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uSipRange, __u32 _uEipAddr, char * _sErrMsg)
{
	struct nd_service_rule_data_new *service_rule;
	struct nd_service_act_rule_data *action;
	struct list_head * pos, *next;
	struct list_head *actpos, *actnext;
	int ret = 0;
	bool bFinded = false, bFindedService = false;


	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

			service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
			if (!service_rule)      {
				sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004512);
				return -1;
			}

			if (service_rule->service == _uService )                {
				bFindedService = true;
				if (!list_empty (&service_rule->act_rule.list))       {

						list_for_each_safe (actpos, actnext, &service_rule->act_rule.list)  {
						action = list_entry (actpos, struct nd_service_act_rule_data, list);
						if (action)        {

							ret = nd_checkTargetInList (&service_rule->act_rule.list, action, INDX_RULE_TYPE_ACTION);
							if (ret == ND_CHECK_OK )
							{

									bFinded = true;
							}
						}
					}
				}
			}
        }

        if (!bFindedService)
        {
			sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004508);
            return -1;
        }

	if (!bFinded)           
	{
		sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004513);
		return -1;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

		service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
		if (!service_rule)
		{
	sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004512);
				return -1;
		}

		if (service_rule->service == _uService )
		{

			list_for_each_safe (actpos, actnext, &service_rule->act_rule.list)
			{
				action = list_entry (actpos, struct nd_service_act_rule_data, list);
				if (action)
				{
					if (action->nType == _uType)
					{
						if (action->nType == INDX_RULE_IPADDR_SPECIFIC )
						{
							if (action->startIpaddr == _uSipAddr )
							{
								raw_spin_lock (&nd_raw_spinlock);

								list_del(actpos);
								kfree (action);

								raw_spin_unlock(&nd_raw_spinlock);
								return 0;
							}
						}	
						else if (action->nType == INDX_RULE_IPADDR_HOSTRANGE)
						{
							if (action->startIpaddr == _uSipAddr &&
								action->startIprange== _uSipRange )
							{
								raw_spin_lock (&nd_raw_spinlock);

								list_del(actpos);
								kfree (action);

								raw_spin_unlock(&nd_raw_spinlock);
								return 0;
							}
						}		
					}
				}
			}
		}
	}

	sprintf (_sErrMsg , "%s", ND_ERROR_NIXNK_LKMIRQ_M_004514);
	return -1;

}

/*
 *
 */
int nd_get_actions_in_service_rule_to_index(struct cmd_service_sub_rule_pars_data* sub_rule)
{
	return 0;
}

/*
 *
 */
int nd_reset_all_rule (void)
{
	struct nd_service_rule_data_new *service;
	struct nd_service_act_rule_data *action;
	struct list_head *pos, *next;
	struct list_head *actpos, *actnext;

	raw_spin_lock (&nd_raw_spinlock );

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {
		service = list_entry (pos, struct nd_service_rule_data_new, list );

		if (service )           {

			if (!list_empty(&service->act_rule.list))     {

				list_for_each_safe (actpos, actnext, &service->act_rule.list)     {

					action = list_entry (actpos, struct nd_service_act_rule_data, list);
					if (action)
					{
						list_del(actpos);

						kfree (action);
					}
				}
			}
		}

		list_del (pos);
		kfree (service);

    }

	raw_spin_unlock (&nd_raw_spinlock );

	return 0;
}

/*
 *
 */
int nd_nfm_get_service_rules(char *output)
{
	struct nd_service_rule_data_new *service_rule;
	struct list_head * pos, * next;
	int size = 0, len = 0;
	char szTmp[24] = {0,};

	if (output == NULL)
	{
		return -1;
	}

	if (!list_empty (&nd_list_service_rules_new.list ))     {

		list_for_each_safe (pos, next,  &nd_list_service_rules_new.list)        {
			service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
			if (service_rule )
			{
				memset (&szTmp, 0, sizeof (szTmp));
				size = snprintf (szTmp, sizeof (szTmp), "%u|%u|%u|||\n", service_rule->service,service_rule->forwardport,  service_rule->mode);

				strcat_safe (output + len, szTmp, ND_NETLINK_DATA_SIZE - len);

				len += size;
			}
		}
	}

	return 0;

}

/*
 *
 */
int nd_nfm_get_action_rules(char * output)
{
	return 0;
}

/*
 * NIC RULE ADD
 */
int nd_nfm_add_nic_rule (struct cmd_nic_rule_pars_data * pNicData ,char * sErrCode)
{
	struct nd_nic_rule_data_v2 *nic_rule, *new_nic_rule;
	struct list_head *pos, *next;

	if (!list_empty (&nd_list_nic_rules.list) )	
	{
		list_for_each_safe (pos, next, &nd_list_nic_rules.list)	
		{
			nic_rule = list_entry (pos, struct nd_nic_rule_data_v2, list );
			if (nic_rule )		{
				if (nic_rule->address == pNicData->address)
				{
					sprintf (sErrCode, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004521);
                                        return ND_ERROR_ALREADEXIST_RULE;
				}
#ifdef _OLD_SRC
				if (memcmp (nic_rule->mac_addr, pNicData->mac_addr, sizeof (nic_rule->mac_addr)) == 0)	{

					sprintf (sErrCode, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004521);
					return ND_ERROR_ALREADEXIST_RULE;
				}
#endif //_OLD_SRC
			}	
		}
	}

	new_nic_rule = kmalloc (sizeof (struct nd_nic_rule_data_v2), GFP_KERNEL);
	if (!new_nic_rule)
	{
		sprintf (sErrCode, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004507);

		return ND_ERROR_INVALID_BUFFER;
	}

	raw_spin_lock (&nd_raw_spinlock );
#ifdef _OLD_SRC
	strncpy(new_nic_rule->name, pNicData->name, IFNAMSIZ);
	memcpy (new_nic_rule->mac_addr, pNicData->mac_addr, 6);
#endif
	new_nic_rule->address = pNicData->address;	
	//printk (KERN_INFO "nd_nfm_add_nic_rule ADD ADDRESS [%d]", new_nic_rule->address);

	INIT_LIST_HEAD (&new_nic_rule->list);
	list_add_tail(&new_nic_rule->list, &nd_list_nic_rules.list);

	raw_spin_unlock (&nd_raw_spinlock );

	return ND_ERROR_SUCCESS;
}

/*
 * NIC RULE MOD
 */
int nd_nfm_mod_nic_rule (void )
{
	return 0;
}

/*
 * NIC RULE DEL
 */
int nd_nfm_del_nic_rule (struct cmd_nic_rule_pars_data * pNicData, char * sErrCode )
{
	struct nd_nic_rule_data *nic_rule;
    struct list_head *pos, *next;

	raw_spin_lock (&nd_raw_spinlock );
	if (!list_empty (&nd_list_nic_rules.list) )
	{
		list_for_each_safe (pos, next, &nd_list_nic_rules.list)
		{
			nic_rule = list_entry (pos, struct nd_nic_rule_data, list );
			if (nic_rule )          {
#ifdef _OLD_SRC
				if (memcmp (nic_rule->mac_addr, pNicData->mac_addr, sizeof (nic_rule->mac_addr)) == 0)  {

					list_del (pos);
					kfree (nic_rule);

					raw_spin_unlock (&nd_raw_spinlock );

					return ND_ERROR_SUCCESS;
				}
#endif //_OLD_SRC
			}
		}
	}

	sprintf (sErrCode, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004522);

	raw_spin_unlock (&nd_raw_spinlock );
	return -1;
}

/*
 * NIC RULE GET
 */
int nd_nfm_reset_nic_rules (void)
{
	struct nd_nic_rule_data *nic_rule;
	struct list_head *pos, *next;

	raw_spin_lock (&nd_raw_spinlock );
	if (!list_empty (&nd_list_nic_rules.list) )
	{
		list_for_each_safe (pos, next, &nd_list_nic_rules.list)
		{
			nic_rule = list_entry (pos, struct nd_nic_rule_data, list );
			if (nic_rule )          {

				list_del (pos);
				kfree (nic_rule);

				//raw_spin_unlock (&nd_raw_spinlock );
			}
		}
	}

	raw_spin_unlock (&nd_raw_spinlock );
	return ND_ERROR_SUCCESS;
}


int nd_nfm_chk_nic_rule (struct in_ifaddr * ifa)		{

	struct nd_nic_rule_data_v2 *nic_rule;
        struct list_head *pos, *next;

        if (!list_empty (&nd_list_nic_rules.list) )
        {
                list_for_each_safe (pos, next, &nd_list_nic_rules.list)
                {
                        nic_rule = list_entry (pos, struct nd_nic_rule_data_v2, list );
                        if (nic_rule )          {

			
				if (ifa->ifa_address == nic_rule->address){
					
					return ND_CHECK_OK;
				}
                       }
                }
        }
	else
	{
		//except status , same mode off
		return ND_CHECK_OK;
	}


        return ND_CHECK_NONE;


}

#ifdef _OLD_SRC
int nd_nfm_chk_nic_rule ( const char *name, const unsigned char *dev_addr )
{
	struct nd_nic_rule_data *nic_rule;
	struct list_head *pos, *next;

	if (!list_empty (&nd_list_nic_rules.list) )
	{
		list_for_each_safe (pos, next, &nd_list_nic_rules.list)
		{
			nic_rule = list_entry (pos, struct nd_nic_rule_data, list );
			if (nic_rule )          {

				if (nic_rule->name[0] == '\0' && nic_rule->mac_addr[0] == '\0')
					continue;
			
				else	{
					
					if (nic_rule->name[0] == '\0' ||  nic_rule->mac_addr[0] == '\0')
					{
						if  (nic_rule->name[0] == '\0')         {

							if (memcmp (nic_rule->mac_addr, dev_addr, ETH_ALEN) == 0)
							{
								return ND_CHECK_OK;
							}
						}

						else   
						{

							if (strncmp (name, nic_rule->name, IFNAMSIZ) == 0 )
							{
								return ND_CHECK_OK;
							}
						}
					}
					else
					{
						if (strncmp(name, nic_rule->name, IFNAMSIZ) == 0 || memcmp (nic_rule->mac_addr, dev_addr, ETH_ALEN) == 0)  {

							return ND_CHECK_OK;
						}
					}
				}
			}
		}
	}

	return ND_CHECK_NONE;
}
#endif //_OLD_SRC

int nd_nfm_add_bypass_rule(struct cmd_bypass_rule_pars_data *_bypass_rule, char * sErrCode )
{
	struct nd_bypass_rule_data *bypass_rule, *new_bypass_rule;
	struct list_head *pos, *next;

	if (!list_empty (&nd_list_bypass_rules.list) )
	{
			list_for_each_safe (pos, next, &nd_list_bypass_rules.list)
			{
					bypass_rule = list_entry (pos, struct nd_bypass_rule_data, list );
					if (bypass_rule )          {
			
				if (_bypass_rule->saddr == _bypass_rule->eaddr && bypass_rule->saddr == bypass_rule->eaddr)
				{
					if (_bypass_rule->saddr == bypass_rule->saddr)
					{
						sprintf (sErrCode, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004552);
						return ND_CHECK_OK;
					}
				}

				else
				{
					if (_bypass_rule->saddr == bypass_rule->saddr && _bypass_rule->eaddr == bypass_rule->eaddr)
					{
						sprintf (sErrCode, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004552);
						return ND_CHECK_OK;
					}
				}
			}
		}
    }

	new_bypass_rule = kmalloc (sizeof (struct nd_bypass_rule_data), GFP_KERNEL);
	if (!new_bypass_rule)
	{
		sprintf (sErrCode, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004507);

		return ND_ERROR_INVALID_BUFFER;
	}

	raw_spin_lock (&nd_raw_spinlock );

	new_bypass_rule->saddr = _bypass_rule->saddr;
	new_bypass_rule->eaddr = _bypass_rule->eaddr;

	//printk (KERN_ERR "saddr : %d/ eaddr : %d", _bypass_rule->saddr, _bypass_rule->eaddr);

	INIT_LIST_HEAD (&new_bypass_rule->list);
	list_add_tail(&new_bypass_rule->list, &nd_list_bypass_rules.list);

	raw_spin_unlock (&nd_raw_spinlock );
	return ND_ERROR_SUCCESS;
}

int nd_nfm_del_bypass_rule (struct cmd_bypass_rule_pars_data *_bypass_rule, char *sErrCode )
{
	struct nd_bypass_rule_data *bypass_rule;
	struct list_head *pos, *next;

	raw_spin_lock (&nd_raw_spinlock );
	if (!list_empty (&nd_list_bypass_rules.list) )
	{
		list_for_each_safe (pos, next, &nd_list_bypass_rules.list)
		{
			bypass_rule = list_entry (pos, struct nd_bypass_rule_data, list );
			if (bypass_rule )          {

				if (_bypass_rule->saddr == _bypass_rule->eaddr && bypass_rule->saddr == bypass_rule->eaddr)
				{
					if (_bypass_rule->saddr == bypass_rule->saddr)		{
						list_del (pos);
						kfree (bypass_rule);

						raw_spin_unlock (&nd_raw_spinlock );

						return ND_ERROR_SUCCESS;
					}
						
				}

				else
				{
					if (_bypass_rule->saddr == bypass_rule->saddr && _bypass_rule->eaddr == bypass_rule->eaddr)		{

						list_del (pos);
						kfree (bypass_rule);

						raw_spin_unlock (&nd_raw_spinlock );
					
						return ND_ERROR_SUCCESS;
					}
				}
			}
		}
	}

	sprintf (sErrCode, "%s", ND_ERROR_NIXNK_LKMIRQ_M_004522);

	raw_spin_unlock (&nd_raw_spinlock );
    return -1;
}

int nd_nfm_reset_bypass_rule (void)
{
	struct nd_bypass_rule_data *bypass_rule;
	struct list_head *pos, *next;

	raw_spin_lock (&nd_raw_spinlock );
	if (!list_empty (&nd_list_bypass_rules.list) )
	{
		list_for_each_safe (pos, next, &nd_list_bypass_rules.list)
		{
			bypass_rule = list_entry (pos, struct nd_bypass_rule_data, list );
			if (bypass_rule )          {

				list_del (pos);
				kfree (bypass_rule);

				raw_spin_unlock (&nd_raw_spinlock );
			}
		}
	}

	raw_spin_unlock (&nd_raw_spinlock );
	return ND_ERROR_SUCCESS;
}

int nd_nfm_check_bypass_rule( __u32 sourceIpAddr )
{
	struct nd_bypass_rule_data *bypass_rule;
	struct list_head *pos, *next;

	if (!list_empty (&nd_list_bypass_rules.list) )
	{
		list_for_each_safe (pos, next, &nd_list_bypass_rules.list)
		{
			bypass_rule = list_entry (pos, struct nd_bypass_rule_data, list );
			if (bypass_rule )          {

				if (bypass_rule->saddr == bypass_rule->eaddr)
				{
					if (bypass_rule->saddr == sourceIpAddr)
						return ND_CHECK_OK;
				}

				else
				{
					if(nd_nfm_chk_iprang (sourceIpAddr, bypass_rule->saddr, bypass_rule->eaddr))
						return ND_CHECK_OK;
				}
			}
		}
	}
	
	return ND_CHECK_NONE;
}
