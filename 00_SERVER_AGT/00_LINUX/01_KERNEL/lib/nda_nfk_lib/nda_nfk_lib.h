#ifndef ND_NIX_NFM_LIB_H
#define ND_NIX_NFM_LIB_H

#include <errno.h>
#include <stdbool.h> 
#include <linux/types.h>
#include <net/if.h>

#define ND_IOCTL_MAGIC          'N'
#define MAX_STRING_LENGTH       1024
#define MAX_VERSION_LENGTH	16

#define ND_TYPE_STRUCT          1
#define ND_TYPE_STRING          2

#define ND_IOCTL_TYPE           ND_TYPE_STRUCT

#define MAX_LOGS 256
#define LOG_MSG_SIZE 256

#define MAX_SERVICE_LENGTH 6


#define MAX_BUFFER_SIZE (MAX_LOGS * (LOG_MSG_SIZE +1))


/*
#define IOCTL_ADD_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 0,        struct cmd_service_rule_pars_data)
#define IOCTL_ADD_ACTION_POLICY         _IOWR(ND_IOCTL_MAGIC, 1,        struct cmd_service_sub_rule_pars_data)
#define IOCTL_ADD_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 3,        struct cmd_service_sub_rule_pars_data)

#define IOCTL_MOD_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 4,        struct cmd_service_rule_pars_data)
#define IOCTL_MOD_ACTION_POLICY         _IOWR(ND_IOCTL_MAGIC, 5,        struct cmd_service_sub_rule_pars_data)
#define IOCTL_MOD_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 7,        struct cmd_service_sub_rule_pars_data)

//#define IOCTL_DEL_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 8,        struct cmd_service_rule_pars_data)
#define IOCTL_DEL_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 8, 	char [MAX_SERVICE_LENGTH])
#define IOCTL_DEL_ACTION_POLICY         _IOWR(ND_IOCTL_MAGIC, 9,        struct cmd_service_sub_rule_pars_data)
#define IOCTL_DEL_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 11,       struct cmd_service_sub_rule_pars_data)

#define IOCTL_RESET_POLICY              _IO(ND_IOCTL_MAGIC,12)

#define IOCTL_GET_POLICY                _IOR(ND_IOCTL_MAGIC, 13,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_SERVICE_POLICY_INDEX  _IOR(ND_IOCTL_MAGIC, 14,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_ACTION_POLICY_INDEX   _IOWR(ND_IOCTL_MAGIC, 15,       struct cmd_service_sub_rule_pars_data)

#define IOCTL_GET_SERVICE_POLICY        _IOR(ND_IOCTL_MAGIC, 17,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_ACTION_POLICY         _IOR(ND_IOCTL_MAGIC, 18,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_DROPEXCEPT_POLICY     _IOR(ND_IOCTL_MAGIC, 20,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_CONNECTSESSIONCNT     _IOR(ND_IOCTL_MAGIC, 21,        char [MAX_STRING_LENGTH])
///
#define IOCTL_ON_MODE                   _IO(ND_IOCTL_MAGIC, 30)
#define IOCTL_OFF_MODE                  _IO(ND_IOCTL_MAGIC, 31)
#define IOCTL_GET_MODE                  _IOR(ND_IOCTL_MAGIC, 32,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_VERSION               _IOR(ND_IOCTL_MAGIC, 40,        char [MAX_VERSION_LENGTH])
#define IOCTL_GET_LOG                   _IOR(ND_IOCTL_MAGIC, 41,        char *)
#define IOCTL_SET_LOG_SETTINGS          _IOW(ND_IOCTL_MAGIC, 42,        struct st_log_config)
#define IOCTL_GET_LOG_SETTINGS          _IOR(ND_IOCTL_MAGIC, 43,        struct st_log_config)

#define IOCTL_ADD_NIC_RULE              _IOW(ND_IOCTL_MAGIC, 45,        struct cmd_nic_rule_pars_data)
#define IOCTL_DEL_NIC_RULE              _IOW(ND_IOCTL_MAGIC, 46,        struct cmd_nic_rule_pars_data)
#define IOCTL_RESET_NIC_RULE		_IO(ND_IOCTL_MAGIC, 47)

#define IOCTL_ADD_BYPASS_RULE           _IOW(ND_IOCTL_MAGIC, 50,        struct cmd_bypass_rule_pars_data)
#define IOCTL_DEL_BYPASS_RULE           _IOW(ND_IOCTL_MAGIC, 51,        struct cmd_bypass_rule_pars_data)
#define IOCTL_RESET_PYPASS_RULE         _IO(ND_IOCTL_MAGIC, 52)
*/
#define IOCTL_ADD_SERVICE_POLICY                _IOWR(ND_IOCTL_MAGIC, 1,        struct cmd_service_rule_pars_data)
#define IOCTL_ADD_ACTION_POLICY                 _IOWR(ND_IOCTL_MAGIC, 2,    struct cmd_service_sub_rule_pars_data)
#define IOCTL_ADD_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 3,        struct cmd_service_sub_rule_pars_data)

#define IOCTL_MOD_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 4,        struct cmd_service_rule_pars_data)
#define IOCTL_MOD_ACTION_POLICY         _IOWR(ND_IOCTL_MAGIC, 5,    struct cmd_service_sub_rule_pars_data)
#define IOCTL_MOD_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 7,        struct cmd_service_sub_rule_pars_data)

//#define IOCTL_DEL_SERVICE_POLICY                _IOWR(ND_IOCTL_MAGIC, 8,        struct cmd_service_rule_pars_data)
#define IOCTL_DEL_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 8,        char [MAX_SERVICE_LENGTH])
#define IOCTL_DEL_ACTION_POLICY                 _IOWR(ND_IOCTL_MAGIC, 9,    struct cmd_service_sub_rule_pars_data)
#define IOCTL_DEL_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 11,       struct cmd_service_sub_rule_pars_data)

#define IOCTL_RESET_POLICY                              _IO(ND_IOCTL_MAGIC,12)

#define IOCTL_GET_POLICY                                _IOR(ND_IOCTL_MAGIC, 13,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_SERVICE_POLICY_INDEX  _IOR(ND_IOCTL_MAGIC, 14,    char [MAX_STRING_LENGTH])
#define IOCTL_GET_ACTION_POLICY_INDEX   _IOWR(ND_IOCTL_MAGIC, 15,   struct cmd_service_sub_rule_pars_data)

#define IOCTL_GET_SERVICE_POLICY                _IOR(ND_IOCTL_MAGIC, 17,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_ACTION_POLICY         _IOR(ND_IOCTL_MAGIC, 18,    char [MAX_STRING_LENGTH])
#define IOCTL_GET_DROPEXCEPT_POLICY             _IOR(ND_IOCTL_MAGIC, 20,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_CONNECTSESSIONCNT     _IOR(ND_IOCTL_MAGIC, 21,    char [MAX_STRING_LENGTH])
///
#define IOCTL_ON_MODE                                   _IO(ND_IOCTL_MAGIC, 30)
#define IOCTL_OFF_MODE                                  _IO(ND_IOCTL_MAGIC, 31)
#define IOCTL_GET_MODE                                  _IOR(ND_IOCTL_MAGIC, 32,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_VERSION                               _IOR(ND_IOCTL_MAGIC, 40,        char [MAX_VERSION_LENGTH])
#define IOCTL_GET_LOG                                   _IOR(ND_IOCTL_MAGIC, 41,        char *)
#define IOCTL_SET_LOG_SETTINGS                  _IOW(ND_IOCTL_MAGIC, 42,        struct st_log_config)
#define IOCTL_GET_LOG_SETTINGS                  _IOR(ND_IOCTL_MAGIC, 43,        struct st_log_config)
#define IOCTL_ADD_NIC_RULE              _IOW(ND_IOCTL_MAGIC, 45,    struct cmd_nic_rule_pars_data)
#define IOCTL_DEL_NIC_RULE              _IOW(ND_IOCTL_MAGIC, 46,    struct cmd_nic_rule_pars_data)
#define IOCTL_RESET_NIC_RULE            _IO(ND_IOCTL_MAGIC, 47)

#define IOCTL_ADD_BYPASS_RULE                   _IOW(ND_IOCTL_MAGIC, 50,        struct cmd_bypass_rule_pars_data)
#define IOCTL_DEL_BYPASS_RULE                   _IOW(ND_IOCTL_MAGIC, 51,        struct cmd_bypass_rule_pars_data)
#define IOCTL_RESET_PYPASS_RULE                 _IO(ND_IOCTL_MAGIC, 52)


#define ND_DEVICE_NAME "nd_nix_chardev"
#define DEVICE_PATH "/dev/nd_nix_chardev"

struct cmd_service_rule_pars_data
{
       // __u32 rule_type;
        __u16 service;
        __u16 forward;
        __u32 data;
	__u32 ret;
};

struct cmd_service_sub_rule_pars_data
{
        __u16 service;
        __u32 type;
        __u32 saddr;
	__u32 s_range;
        __u32 eaddr;
	__u32 ret;
};


struct cmd_nic_rule_pars_data
{
#ifdef _OLD_SRC
        char name[IFNAMSIZ];
        unsigned char mac_addr[6];
#endif //_OLD_SRC
	__u32 address;
};

struct cmd_bypass_rule_pars_data
{
        __u32 saddr;
        __u32 eaddr;
};


/*
struct nd_nic_rule_data {

        char name[IFNAMSIZ];
        unsigned char mac_addr[6];

        struct list_head list;
};
*/

struct st_log_config {
        bool debug_log_enabled;
        bool warn_log_enabled;
        bool error_log_enabled;
        bool trace_log_enabled;
        bool info_log_enabled;
};


enum log_level_index {

        LOG_LEVEL_NONE  = 0,
        LOG_LEVEL_WARN  ,
        LOG_LEVEL_ERR   ,
        LOG_LEVEL_INFO  ,
        LOG_LEVEL_DEBUG ,
        LOG_LEVEL_TRACE ,
        LOG_LEVEL_MAX
};


/*
 *
 */
int sdk_get_NdaNfkDrv_ManagedSessionCnt(char * cnt);

/*	
 * SDK that outputs version information
 */
int sdk_get_NdaNfkDrv_version (char * version);

/*
 * SDK that activates the operating mode
 */
int sdk_NdaNfkDrv_start (void);

/*
 * SDK that changes the operating mode to cleanup
 */
int sdk_NdaNfkDrv_stop (void);

/*
 * SDK to obtain current operating mode information
 */
int sdk_get_NdaNfkDrv_state (char * sStatus );

/*
 * SDK for adding service policies to the driver
 */
int sdk_add_NdaNfkDrv_service_policy(const struct cmd_service_rule_pars_data * service);

/*
 * SDK for adding action service policies to the driver
 * [add 2024-10-10]
 */
int sdk_add_NdaNfkDrv_action_policy(const struct cmd_service_sub_rule_pars_data * action);

/*
 * SDK for modifying service policies in the driver
 */
int sdk_mod_NdaNfkDrv_service_policy_to_index(const struct cmd_service_rule_pars_data * service);

/*
 * SDK for modifying action service policies in the driver
 * [add 2024-10-10]
 */
int sdk_mod_NdaNfkDrv_action_policy_to_index(const struct cmd_service_sub_rule_pars_data * action);


/*
 * SDK to delete service policy from driver
 */
#ifdef _SERVICE_STRUCT_TYPE
int sdk_del_NdaNfkDrv_service_policy(const struct cmd_service_rule_pars_data * service );
#else
int sdk_del_NdaNfkDrv_service_policy(const char * service );
#endif //_SERVICE_STRUCT_TYPE

/*
 * SDK for deleting action service policies from the driver
 * [add 2024-10-10]
 */
int sdk_del_NdaNfkDrv_action_policy(const struct cmd_service_sub_rule_pars_data * action );


/*
 * sdk to delete all policies from driver
 */
int sdk_reset_NdaNfkDrv_policy (void);


/*
 * SDK for retrieving service policies from the driver
 * [add 2024-10-10]
 */
int sdk_get_NdaNfkDrv_service_policy_index(struct cmd_service_rule_pars_data * service);

/*
 * SDK for retrieving action service policies from the driver
 */
int sdk_get_NdaNfkDrv_action_policy_index(const struct cmd_service_sub_rule_pars_data * action );


/*
 * SDK that retrieves all service policy from driver
 */
int sdk_get_NdaNfkDrv_policy (char * data);

/*
 * SDK that retrieves service policy from driver
 */
int sdk_get_NdaNfkDrv_service_policy (char *data);


/*
 * SDK for retrieving stored logs from the driver
 */
int sdk_get_NdaNfkDrv_logs(char *data);

/*
 *
 */
int sdk_set_NdaNfkDrv_log_setting(int nLogLevel);

/*
 *
 */
int sdk_get_NdaNfkDrv_log_setting(struct st_log_config * pconfig);


/*
 *
 */
int sdk_add_NdaNfkDrv_nic_rule (struct cmd_nic_rule_pars_data * pNicData);

/*
 *
 */
int sdk_del_NdaNfkDrv_nic_rule (struct cmd_nic_rule_pars_data * pNicData);

/*
 *
 */
int sdk_reset_NdaNfkDrv_nic_rule (void);

/*
 *
 */
int sdk_add_NdaNfkDrv_bypass_rule (struct cmd_bypass_rule_pars_data* pBypassData);

/*
 *
 */
int sdk_del_NdaNfkDrv_bypass_rule (struct cmd_bypass_rule_pars_data * pBypassData);

/*
 *
 */
int sdk_reset_NdaNfkDrv_bypass_rule (void );

#endif
