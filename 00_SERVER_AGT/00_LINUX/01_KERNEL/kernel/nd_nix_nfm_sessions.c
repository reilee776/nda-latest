#include "nd_nix_nfm_sessions.h"
#include "nd_nix_nfm_common.h"

#define DRIVER_AUTH "Saber-toothed cat <pingye@netand.co.kr>"
#define DRIVER_DESC "NETAND's network filtering driver that runs on Linux"

int nd_add_session_item (__u8 protocol, __u32 sip, __u32 dip, __u16 org_destport, __u16 fake_destport, __u16 clientport) {

	struct session_data *new_session;
	struct session_data *session;
	unsigned long flags;

	spin_lock_irqsave(&session_lock, flags);

	list_for_each_entry(session, &session_list, list) {
		if (session->sip == sip && session->dip == dip && session->org_destport == org_destport) {
			spin_unlock_irqrestore(&session_lock, flags);
		    	return -EEXIST; 
		}
	}

	new_session = kmalloc(sizeof(struct session_data), GFP_KERNEL);
	if (!new_session) {
		spin_unlock_irqrestore(&session_lock, flags);
		return -ENOMEM; 
	}

	new_session->protocol 	= protocol;
	new_session->sip 	= sip;
	new_session->dip 	= dip;
	new_session->org_destport 	= org_destport;
	new_session->fake_destport 	= fake_destport;
	new_session->clientport = clientport;

	list_add(&new_session->list, &session_list);

	spin_unlock_irqrestore(&session_lock, flags);
	return 0; //SUCCESS
}


void remove_session_data(__u32 sip, __u32 dip, __u16 clientport) {

	struct session_data *session;
	struct list_head *pos, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&session_lock, flags);

	list_for_each_safe(pos, tmp, &session_list) {
	session = list_entry(pos, struct session_data, list);
	if (session->sip == sip && session->dip == dip && session->clientport == clientport) 	{

			list_del(pos);
		    	kfree(session);
		    	spin_unlock_irqrestore(&session_lock, flags);
		    	return; //SUCCESS
		}
	}

	spin_unlock_irqrestore(&session_lock, flags);
}

int nd_del_session_item(__u32 sip, __u32 dip, __u16 clientport) {

	struct session_data *session;
	struct list_head *pos, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&session_lock, flags);

	list_for_each_safe(pos, tmp, &session_list) {
	session = list_entry(pos, struct session_data, list);
		if (session->sip == sip && session->dip == dip && session->clientport == clientport) {
		    	list_del(pos);
			kfree(session);
		    	spin_unlock_irqrestore(&session_lock, flags);
		    	return 0; //SUCCESS
		}
	}

	spin_unlock_irqrestore(&session_lock, flags);
	return -ENOENT; //NOT FOUND
}


struct session_data* nd_chk_session_item(__u32 sip, __u32 dip, __u16 clientport) {

	struct session_data *session;
	unsigned long flags;

	spin_lock_irqsave(&session_lock, flags);

	list_for_each_entry(session, &session_list, list) {

		if (session->sip == sip && session->dip == dip && session->clientport == clientport) {
			spin_unlock_irqrestore(&session_lock, flags);
			return session; //SUCCESS
		}
	}

	spin_unlock_irqrestore(&session_lock, flags);
	return NULL; //NOT FOUND
}

int count_session_data(void) {

	struct session_data *session;
	struct list_head *pos;
	int count = 0;

	spin_lock(&session_lock); //

	list_for_each(pos, &session_list) {
		session = list_entry(pos, struct session_data, list);
		count++;
	}

	spin_unlock(&session_lock); //
	return count;
}
