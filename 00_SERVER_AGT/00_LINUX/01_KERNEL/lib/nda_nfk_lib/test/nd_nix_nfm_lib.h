#ifndef ND_NIX_NFM_LIB_H
#define ND_NIX_NFM_LIB_H

#include <errno.h>
#include <linux/types.h>

#define ND_IOCTL_MAGIC          'N'
#define MAX_STRING_LENGTH       1024

#define ND_TYPE_STRUCT          1
#define ND_TYPE_STRING          2

#define ND_IOCTL_TYPE           ND_TYPE_STRUCT

#define IOCTL_ADD_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 0, struct cmd_service_rule_pars_data)
#define IOCTL_ADD_FAKEEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 1, struct cmd_service_sub_rule_pars_data)
#define IOCTL_ADD_SOURCEIPS_POLICY      _IOWR(ND_IOCTL_MAGIC, 2, struct cmd_service_sub_rule_pars_data)
#define IOCTL_ADD_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 3, struct cmd_service_sub_rule_pars_data)

#define IOCTL_DEL_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 4, struct cmd_service_rule_pars_data)
#define IOCTL_DEL_FAKEEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 5, struct cmd_service_sub_rule_pars_data)
#define IOCTL_DEL_SOURCEIPS_POLICY      _IOWR(ND_IOCTL_MAGIC, 6, struct cmd_service_sub_rule_pars_data)
#define IOCTL_DEL_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 7, struct cmd_service_sub_rule_pars_data)

#define IOCTL_RESET_POLICY 		_IO(ND_IOCTL_MAGIC,8)

#define IOCTL_GET_POLICY                _IOR(ND_IOCTL_MAGIC, 9, char [MAX_STRING_LENGTH])

#define IOCTL_GET_SERVICE_POLICY        _IOR(ND_IOCTL_MAGIC, 10, char [MAX_STRING_LENGTH])
#define IOCTL_GET_FAKEEXCEPT_POLICY     _IOR(ND_IOCTL_MAGIC, 11, char [MAX_STRING_LENGTH])
#define IOCTL_GET_SOURCEIPS_POLICY      _IOR(ND_IOCTL_MAGIC, 12, char [MAX_STRING_LENGTH])
#define IOCTL_GET_DROPEXCEPT_POLICY     _IOR(ND_IOCTL_MAGIC, 13, char [MAX_STRING_LENGTH])

#define IOCTL_ON_MODE                   _IO(ND_IOCTL_MAGIC, 30)
#define IOCTL_OFF_MODE                  _IO(ND_IOCTL_MAGIC, 31)
#define IOCTL_GET_MODE                  _IOR(ND_IOCTL_MAGIC, 32, char [MAX_STRING_LENGTH])

#define ND_DEVICE_NAME "nd_nix_chardev"
#define DEVICE_PATH "/dev/nd_nix_chardev"

struct cmd_service_rule_pars_data
{
        __u32 rule_type;
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
        __u32 eaddr;
	__u32 ret;
};

/*	
 * SDK that outputs version information
 */
int sdk_get_NdNixNfmDrv_version (void);

/*
 * SDK that activates the operating mode
 */
int sdk_NdNixNfmDrv_start (void);

/*
 * SDK that changes the operating mode to cleanup
 */
int sdk_NdNixNfmDrv_stop (void);

/*
 * SDK to obtain current operating mode information
 */
int sdk_get_NdNixNfmDrv_state (void );

/*
 * SDK that retrieves service policy from driver
 */
int sdk_add_NdNixNfmDrv_service_policy(const struct cmd_service_rule_pars_data * service);

/*
 * SDK that retrieves exception service policy from driver
 */
int sdk_add_NdNixNfmDrv_fakeExcept_policy(const struct cmd_service_sub_rule_pars_data * fakeexcept);

/*
 * SDK that retrieves source IP service policy from driver
 */
int sdk_add_NdNixNfmDrv_sourceips_policy(const struct cmd_service_sub_rule_pars_data * sourceips);

/*
 * SDK to delete service policy from driver
 */
int sdk_del_NdNixNfmDrv_service_policy(const struct cmd_service_rule_pars_data * service );

/*
 * SDK to delete exception service policy from driver
 */
int sdk_del_NdNixNfmDrv_fakeexcept_policy(const struct cmd_service_sub_rule_pars_data * fakeexcept );

/*
 * SDK to delete source IP service policy from driver
 */
int sdk_del_NdNixNfmDrv_sourceips_policy(const struct cmd_service_sub_rule_pars_data * sourceips);

/*
 * sdk to delete all policies from driver
 */
int sdk_reset_NdNixNfmDrv_policy (void);

/*
 * SDK that retrieves all service policy from driver
 */
int sdk_get_NdNixNfmDrv_policy (char * data);

/*
 * SDK that retrieves service policy from driver
 */
int sdk_get_NdNixNfmDrv_service_policy (char *data);

/*
 * SDK that retrieves the reserve service policy from the driver
 */
int sdk_get_NdNixNfmDrv_fakeexcept_policy (char *data);

#endif
