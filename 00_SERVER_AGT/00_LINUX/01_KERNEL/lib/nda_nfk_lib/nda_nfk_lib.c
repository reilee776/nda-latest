#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
//#include "nd_nix_nfm_lib.h"
#include "nda_nfk_lib.h"

int sdk_get_NdaNfkDrv_ManagedSessionCnt(char * cnt)
{
	int ret = 0, fd = 0;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
        {
                return -1;
        }

        ret = ioctl (fd, IOCTL_GET_CONNECTSESSIONCNT, cnt);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        close (fd);

        return 0;

}

int sdk_get_NdaNfkDrv_version(char * version)
{
	int ret = 0, fd = 0;
	
	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
	{
		return -1;
	}

	ret = ioctl (fd, IOCTL_GET_VERSION, version);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}

int sdk_NdaNfkDrv_start(void)
{
	int ret = 0;

        int fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl (fd, IOCTL_ON_MODE, NULL);
        if (ret < 0 )
        {
                close(fd);
                return -1;
        }

        close(fd);

        return 0;

}

int sdk_NdaNfkDrv_stop(void)
{
	int ret = 0;

        int fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl (fd, IOCTL_OFF_MODE, NULL);
        if (ret < 0 )
        {
                close(fd);
                return -1;
        }

        close(fd);

        return 0;

}

int sdk_get_NdaNfkDrv_state(char * sStatus)
{
	int ret = 0, fd = 0;
	
	fd = open (DEVICE_PATH, O_RDWR);
	if ( fd < 0 )	{
		return -1;
	}

	ret = ioctl (fd, IOCTL_GET_MODE, sStatus);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);
 	return 0;
}


int sdk_add_NdaNfkDrv_service_policy(const struct cmd_service_rule_pars_data * service)
{
	int ret = 0;

	if (service == NULL )
		return -1;

	int fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )	{
		return -1;
	}

	ret = ioctl (fd, IOCTL_ADD_SERVICE_POLICY, service);
	if (ret < 0 )
	{
		close(fd);
		return -1;
	}
	/*
	if (service->ret == 0x01)
	{
		printf("ret value is 0x01\n");
	}
	*/

	close(fd);

	return 0;
}


int sdk_add_NdaNfkDrv_action_policy(const struct cmd_service_sub_rule_pars_data * action)
{
	int ret = 0, fd = 0;

        if (action == NULL)
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_ADD_ACTION_POLICY, action);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        close(fd);

	return 0;
}


#ifdef ND_OLD_RULE_TYPE
int sdk_add_NdaNfkDrv_fakeExcept_policy(const struct cmd_service_sub_rule_pars_data * fakeexcept)
{
	int ret = 0, fd = 0;
	
	if (fakeexcept == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_ADD_FAKEEXCEPT_POLICY, fakeexcept);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close(fd);

	return 0;
}

int sdk_add_NdaNfkDrv_sourceips_policy(const struct cmd_service_sub_rule_pars_data * sourceips)
{
	int ret = 0, fd = 0;

	if (sourceips == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl(fd, IOCTL_ADD_SOURCEIPS_POLICY, sourceips);
	if (ret < 0 )	{
		close(fd);
		return -1;
	}

	close (fd);

	return 0;
}
#endif //ND_OLD_RULE_TYPE

int sdk_mod_NdaNfkDrv_service_policy_to_index(const struct cmd_service_rule_pars_data * service)
{
	int ret = 0, fd = 0;
	
	if (service == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_MOD_SERVICE_POLICY, service);
	if (ret < 0 )		{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}

int sdk_mod_NdaNfkDrv_action_policy_to_index(const struct cmd_service_sub_rule_pars_data * action)
{

	int ret = 0, fd = 0;

        if (action == NULL)
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_MOD_ACTION_POLICY, action);
        if (ret < 0)            {
                close (fd);
                return -1;
        }

        close (fd);
        return 0;

}


#ifdef ND_OLD_RULE_TYPE
int sdk_mod_NdaNfkDrv_fakeexcept_policy_to_index(const struct cmd_service_sub_rule_pars_data * except)
{
	int ret = 0, fd = 0;

	if (except == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_MOD_FAKEEXCEPT_POLICY, except);
	if (ret < 0)		{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}

int sdk_mod_NdaNfkDrv_sourceips_policy_to_index(const struct cmd_service_sub_rule_pars_data * sourceips)
{
	int ret = 0, fd = 0;

	if (sourceips == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_MOD_SOURCEIPS_POLICY, sourceips);
	if (ret < 0 )		{
		close (fd);
		return -1;
	}
	
	close (fd);
        return 0;
}
#endif //ND_OLD_RULE_TYPE

#ifdef _SERVICE_STRUCT_TYPE
int sdk_del_NdaNfkDrv_service_policy(const struct cmd_service_rule_pars_data * service )
{

	int ret = 0, fd = 0;

	if ( service == NULL )
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;


	ret = ioctl (fd, IOCTL_DEL_SERVICE_POLICY, service );
	if (ret < 0 )	{
		close (fd);
		return -1;
	}

	close (fd);
	 
	return 0;
}
#else

int sdk_del_NdaNfkDrv_service_policy(const char * service )
{

        int ret = 0, fd = 0;

        if ( service == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;


        ret = ioctl (fd, IOCTL_DEL_SERVICE_POLICY, service );
        if (ret < 0 )   {
                close (fd);
                return -1;
        }

        close (fd);

        return 0;
}


#endif //_SERVICE_STRUCT_TYPE


int sdk_del_NdaNfkDrv_action_policy(const struct cmd_service_sub_rule_pars_data * action )
{
	int ret = 0, fd = 0;

        if (action == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_DEL_ACTION_POLICY, action);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        close (fd);
        return 0;

}

#ifdef ND_OLD_RULE_TYPE
int sdk_del_NdaNfkDrv_fakeexcept_policy(const struct cmd_service_sub_rule_pars_data * fakeexcept )
{

	int ret = 0, fd = 0;

	if (fakeexcept == NULL )
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_DEL_FAKEEXCEPT_POLICY, fakeexcept);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}

int sdk_del_NdaNfkDrv_sourceips_policy(const struct cmd_service_sub_rule_pars_data * sourceips)
{
	int ret = 0, fd = 0;

	if (sourceips == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_DEL_SOURCEIPS_POLICY, sourceips);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}
#endif //ND_OLD_RULE_TYPE

int sdk_reset_NdaNfkDrv_policy (void)			{
	
	int ret = 0;

        int fd = open(DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl(fd, IOCTL_RESET_POLICY, NULL);;
        if (ret < 0 )   {

                close(fd);
                return -1;
        }

        close(fd);

	return 0;
}

int sdk_get_NdaNfkDrv_policy (char * data)
{
	int ret = 0, fd = 0;
	
	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )	
		return -1;

	ret = ioctl (fd, IOCTL_GET_POLICY, data);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}

int sdk_get_NdaNfkDrv_action_policy_index(const struct cmd_service_sub_rule_pars_data * action )
{
	int ret = 0, fd = 0;

        if (action == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_GET_ACTION_POLICY, action);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        ret = action->ret;

        close (fd);
        return ret;
}

#ifdef ND_OLD_RULE_TYPE
int sdk_get_NdaNfkDrv_sourceips_policy_index(const struct  cmd_service_sub_rule_pars_data *sourceips )
{
	int ret = 0, fd = 0;

        if (sourceips == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_GET_SOURCEIPS_POLICY_INDEX, sourceips);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        ret = sourceips->ret;

        close (fd);
        return ret;

}

int sdk_get_NdaNfkDrv_fakeexcept_policy_index(const struct cmd_service_sub_rule_pars_data *fakeexcept )
{
	int ret = 0, fd = 0;

        if (fakeexcept == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_GET_FAKEEXCEPT_POLICY_INDEX, fakeexcept);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

	ret = fakeexcept->ret;

        close (fd);
        return ret;

}
#endif //ND_OLD_RULE_TYPE

int sdk_get_NdaNfkDrv_service_policy_index(struct cmd_service_rule_pars_data * service )
{
	int ret = 0, fd = 0;
	if (service == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_GET_SERVICE_POLICY_INDEX, service);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}


int sdk_get_NdaNfkDrv_service_policy (char *data)
{
	int ret = 0, fd = 0;

	if (data == NULL )
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_GET_SERVICE_POLICY, data);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}

#ifdef ND_OLD_RULE_TYPE
int sdk_get_NdaNfkDrv_fakeexcept_policy (char *data)
{
	int ret = 0, fd = 0;

        if (data == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_GET_FAKEEXCEPT_POLICY, data);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        close (fd);

        return 0;

}
#endif //ND_OLD_RULE_TYPE

int sdk_get_NdaNfkDrv_logs(char *data)
{
	int ret = 0, fd = 0;

	if (data == NULL )
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )	{
		printf ("sdk_get_NdNixNfmDrv_logs open fail....\n");
		return -1;
	}

	ret = ioctl (fd, IOCTL_GET_LOG, data);
	if (ret < 0)
	{
		printf ("sdk_get_NdNixNfmDrv_logs ioctl fail....\n");
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}


int sdk_set_NdaNfkDrv_log_setting(int nLogLevel)
{
	int ret = 0, fd = 0;
	struct st_log_config config;

	memset (&config, 0x00, sizeof (struct st_log_config));

	config.debug_log_enabled 	= false;
	config.warn_log_enabled 	= false;
	config.error_log_enabled 	= false;
	config.trace_log_enabled 	= false;
	config.info_log_enabled 	= false;

	if (nLogLevel >= LOG_LEVEL_MAX)		{

		printf ("sdk_set_NdNixNfmDrv_log_setting oper fail... is not valid Log level.\n");
		return -1;
	}

	if (nLogLevel >= LOG_LEVEL_WARN )	{
		config.warn_log_enabled = true;
	}
	
	if (nLogLevel >= LOG_LEVEL_ERR)	{
		config.error_log_enabled = true;
	}

	if (nLogLevel >= LOG_LEVEL_INFO)	{
		config.info_log_enabled = true;
	}

	if (nLogLevel >= LOG_LEVEL_DEBUG)	{
		config.debug_log_enabled = true;
	}

	if (nLogLevel >= LOG_LEVEL_TRACE)	{
		config.trace_log_enabled = true;
	}
	
	
	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
	{
		printf ("int sdk_set_NdNixNfmDrv_log_setting open fail...\n");
		return -1;
	}

	ret = ioctl (fd, IOCTL_SET_LOG_SETTINGS, &config);
	if (ret < 0 )
	{
		printf ("sdk_set_NdNixNfmDrv_log_setting ioctl fail....\n");
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}

int sdk_get_NdaNfkDrv_log_setting(struct st_log_config * pconfig)
{
	int ret = 0, fd = 0;

        memset (pconfig, 0x00, sizeof (struct st_log_config));

	fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
        {
                printf ("int sdk_set_NdNixNfmDrv_log_setting open fail...\n");
                return -1;
        }

        ret = ioctl (fd, IOCTL_GET_LOG_SETTINGS, pconfig);
        if (ret < 0 )
        {
                printf ("sdk_set_NdNixNfmDrv_log_setting ioctl fail....\n");
                close (fd);
                return -1;
        }

        close (fd);
        return 0;
}

int sdk_add_NdaNfkDrv_nic_rule (struct cmd_nic_rule_pars_data * pNicData)
{
	int ret = 0;

        if (pNicData == NULL )
                return -1;

        int fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl (fd, IOCTL_ADD_NIC_RULE, pNicData);
        if (ret < 0 )
        {
                close(fd);
                return -1;
        }

        close(fd);

	return 0;
}


int sdk_del_NdaNfkDrv_nic_rule (struct cmd_nic_rule_pars_data * pNicData)
{
	int ret = 0;

        if (pNicData == NULL )
                return -1;

        int fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl (fd, IOCTL_DEL_NIC_RULE, pNicData);
        if (ret < 0 )
        {
                close(fd);
                return -1;
        }

        close(fd);

        return 0;
}

int sdk_reset_NdaNfkDrv_nic_rule (void)
{
	int ret = 0;

        int fd = open(DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl(fd, IOCTL_RESET_NIC_RULE, NULL);;
        if (ret < 0 )   {

                close(fd);
                return -1;
        }

        close(fd);

        return 0;
}

int sdk_add_NdaNfkDrv_bypass_rule (struct cmd_bypass_rule_pars_data* pBypassData)
{

	int ret = 0;
	
	if (pBypassData == NULL)
		return -1;

	int fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )		{
		return -1;
	}

	ret = ioctl (fd, IOCTL_ADD_BYPASS_RULE, pBypassData);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}

int sdk_del_NdaNfkDrv_bypass_rule (struct cmd_bypass_rule_pars_data * pBypassData)
{
	int ret = 0;
	
	if (pBypassData == NULL )
		return -1;

	int fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_DEL_BYPASS_RULE, pBypassData);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}

int sdk_reset_NdaNfkDrv_bypass_rule (void )
{
	int ret = 0;

	int fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_RESET_PYPASS_RULE, NULL);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}
