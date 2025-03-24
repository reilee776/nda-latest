/*
 * ==========================================================================
 * nd_nix_nfm
 * COPYRIGHTⓒ NETAND, ALL RIGHTS RESERVE
 * ==========================================================================
 */

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/netns/generic.h>
#include <net/checksum.h>
#include <net/net_namespace.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/pid_namespace.h>

#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include <linux/ioctl.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

//#define _DNS_QUERY_SUPPORT 1

/*
 */
#include "nd_nix_nfm_common.h"
#include "nd_nix_nfm_sessions.h"

#include "libsrc/nd_nix_util_str.h"
#include "libsrc/nd_nix_rules.h"
#include "libsrc/nd_nix_log.h"

#define DRIVER_AUTH "NETAND Security Team"
#define DRIVER_DESC "NETAND's network filtering driver that runs on Linux"

#define NETLINK_USER 31

#define _SUPP_SRCIP_IN_RULE

static const char *module_version = "1.0.0";

struct nd_nic_rule_data_v2 nd_list_nic_rules;
//struct nd_nic_rule_data nd_list_nic_rules;
struct nd_service_rule_data_new nd_list_service_rules_new;
struct nd_bypass_rule_data nd_list_bypass_rules;

#define NDA_NET_KMARK 0x1

struct custom_data
{
	int flag;
};

#define CUSTOM_CB(skb) ((struct custom_data *)((skb)->cb))

// static void nd_nix_hook_recv_cmd( struct sk_buff * skb);

struct st_log_config global_log_settings = {
	.debug_log_enabled = false,
	.warn_log_enabled = false,
	.trace_log_enabled = false,
	.info_log_enabled = false};

/*
static DEFINE_RAW_SPINLOCK(nd_list_lock);
*/

#define PORT_TABLE_SIZE 256 //
static struct hlist_head port_table[PORT_TABLE_SIZE];

#define MODE_ON 1
#define MODE_OFF 0
#define MODE_WARN 2

static const unsigned int MINOR_BASE = 0;
static const unsigned int MINOR_NUM = 1;

#define NOD_MAJOR 100

wait_queue_head_t log_wait_queue = __WAIT_QUEUE_HEAD_INITIALIZER(log_wait_queue);

static struct class *chardev_class = NULL;

struct log_entry log_list;

DEFINE_MUTEX(log_mutex);
DEFINE_SPINLOCK(session_lock);

struct list_head session_list = LIST_HEAD_INIT(session_list);

char g_ndlog_buffer[1024];

static int nd_major_number;

struct rb_root nd_log_tree = RB_ROOT;
int nd_log_count = 0;
int nd_log_index = 0;

struct ns_data
{
	struct sock *sk;
};

/*
 *
 */
unsigned int g_nLkmMode = 0;

/*
 *
 */
// struct rule_list 	nd_rules;
struct session_list nd_sessions;

char *log_buffer[MAX_LOGS];

// struct sock		*nl_sk = NULL;
// static unsigned int 	net_id;

unsigned int session_m_cnt = 0;

/**
 * calculate_tcp_checksum - 주어진 skb로부터 TCP 체크섬을 계산한다
 * @skb: TCP 패킷이 포함된 소켓 버퍼
 *
 * 반환값:
 *   계산된 TCP 체크섬 (__sum16)
 *   IP 헤더가 없거나 TCP 프로토콜이 아닌 경우, 또는 TCP 헤더가 없으면 0 반환
 */
__sum16 calculate_tcp_checksum(struct sk_buff *skb)
{

    struct iphdr *iph;
    struct tcphdr *tcph;
    __u16 tcp_len;
    __sum16 checksum;

    // IP 헤더와 TCP 헤더에 대한 포인터 설정
    // IP 헤더 포인터 획득
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return 0;// IP 헤더가 없거나 TCP 프로토콜이 아니면 체크섬 계산 생략

    // TCP 헤더 포인터 획득
    tcph = tcp_hdr(skb);
    if (!tcph)
        return 0;// TCP 헤더가 없으면 생략

    // TCP 세그먼트 길이 계산
    // 전체 IP 패킷 길이에서 IP 헤더 길이를 제외하여 TCP 페이로드 길이 계산
    tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;

    // TCP 체크섬 계산: 의사 헤더 포함한 체크섬 생성
    checksum = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                 tcp_len, IPPROTO_TCP,
                                 csum_partial(tcph, tcp_len, 0));

    return checksum;
}


/**
 * hash_function - protocol과 port 값을 기반으로 해시 테이블 인덱스를 계산
 * @protocol: 프로토콜 번호 (예: IPPROTO_TCP 또는 IPPROTO_UDP)
 * @port: 포트 번호
 *
 * 반환값:
 *   PORT_TABLE_SIZE 범위 내의 해시 인덱스
 *
 * 동작 설명:
 *   - protocol과 port를 XOR 연산 후 hash_32 함수를 이용해 해시 값 생성
 *   - 해시 값의 비트를 HASH_BITS(port_table) 만큼 사용
 *   - 결과 값을 PORT_TABLE_SIZE로 나눠 테이블 인덱스를 제한
 */
static inline unsigned int hash_function(__be32 protocol, unsigned short port)
{
	return (hash_32((unsigned long)(protocol ^ port), HASH_BITS(port_table))) % PORT_TABLE_SIZE;
}

/**
 * get_port_info_count - 해시 테이블(port_table)에 등록된 port_info 항목 수를 반환
 *
 * 반환값:
 *   현재 포트 정보 해시 테이블에 저장된 항목 개수 (size_t)
 *
 * 동작 설명:
 *   - hash_for_each 매크로를 사용하여 port_table 전체를 순회
 *   - 각 엔트리를 순회하며 count를 증가
 *   - 최종적으로 누적된 count 반환
 */
size_t get_port_info_count(void)
{
	size_t count = 0;
	struct port_info *info;
	unsigned long index;

    // 해시 테이블(port_table)의 각 버킷을 순회하며 항목 수 계산
	hash_for_each(port_table, index, info, node)
	{
		count++;
	}

	return count;
}

/**
 * save_port_info - 주어진 프로토콜과 포트 정보를 해시 테이블에 저장
 * @protocol: IP 프로토콜 번호 (예: IPPROTO_TCP)
 * @new_port: 저장할 포트 번호
 *
 * 동작 설명:
 *   - 주어진 protocol과 new_port를 기반으로 해시 인덱스를 계산
 *   - struct port_info를 동적 할당 후 값 설정
 *   - 해당 해시 버킷 리스트의 앞에 추가
 *   - session_m_cnt를 증가시켜 저장된 세션 수를 추적
 */
void save_port_info(__be32 protocol, unsigned short new_port)
{
	struct port_info *info;
	unsigned int index = hash_function(protocol, new_port);

    // port_info 구조체 메모리 할당
	info = kmalloc(sizeof(struct port_info), GFP_KERNEL);
	if (!info)
	{
        // 메모리 할당 실패 시 아무 작업도 하지 않음
		return;
	}

    // 포트 정보 설정
	info->protocol = protocol;
	info->sport = new_port;

    // 해시 테이블의 해당 버킷에 추가 (앞쪽에 삽입)
	hlist_add_head(&info->node, &port_table[index]);

    // 전체 세션 수 증가
	session_m_cnt++;
}


/**
 * check_port_info - 주어진 프로토콜과 포트가 해시 테이블에 존재하는지 확인
 * @protocol: IP 프로토콜 번호 (예: IPPROTO_TCP)
 * @port: 확인할 포트 번호
 *
 * 반환값:
 *   해당 프로토콜과 포트가 해시 테이블에 존재하면 true, 아니면 false
 *
 * 동작 설명:
 *   - protocol과 port를 기반으로 해시 인덱스를 계산
 *   - 해당 인덱스의 해시 리스트를 순회하면서 일치 항목이 있는지 확인
 */
bool check_port_info(__be32 protocol, unsigned short port)
{
	struct port_info *info;
	struct hlist_node *tmp;
	unsigned int index = hash_function(protocol, port);

    // 해당 해시 버킷의 리스트 순회
	hlist_for_each_entry_safe(info, tmp, &port_table[index], node)
	{
		if (info->protocol == protocol && info->sport == port)
		{
            // 일치하는 항목 발견 시 true 반환
			return true;
		}
	}
	return false;
}

/**
 * remove_port_info - 주어진 프로토콜과 포트에 해당하는 항목을 해시 테이블에서 제거
 * @protocol: IP 프로토콜 번호 (예: IPPROTO_TCP)
 * @port: 제거할 포트 번호
 *
 * 반환값:
 *   해당 항목이 존재하여 제거되었으면 true, 없으면 false
 *
 * 동작 설명:
 *   - 해시 인덱스를 계산하여 해당 버킷을 순회
 *   - 프로토콜과 포트가 일치하는 항목을 찾으면:
 *       - 리스트에서 제거
 *       - 메모리 해제
 *       - 세션 카운터 감소
 *       - true 반환
 *   - 일치 항목이 없으면 false 반환
 */
bool remove_port_info(__be32 protocol, unsigned short port)
{
	struct port_info *info;
	struct hlist_node *tmp;
	unsigned int index = hash_function(protocol, port);

    // 해시 테이블 버킷 순회
	hlist_for_each_entry_safe(info, tmp, &port_table[index], node)
	{
		if (info->protocol == protocol && info->sport == port)
		{
            // 일치 항목 삭제 및 해제
			hlist_del(&info->node);
			kfree(info);
			session_m_cnt--;
			return true;
		}
	}
	return false;
}

#ifdef _PORT_CHK_ACTIVE
/*
 *	// 포트 활성화 상태 확인 함수
 */
static int is_port_active(__be32 ip, __be16 port)
{
	struct socket *sock;
	struct sockaddr_in target;
	int ret;

	// 소켓 생성
	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret < 0)
	{
		return 0; // port is inactive.
	}

	// 대상 주소 설정
	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = ip;
	target.sin_port = port;

	// 포트 연결 시도
	ret = kernel_connect(sock, (struct sockaddr *)&target, sizeof(target), O_NONBLOCK);
	sock_release(sock);

	if (ret == 0)
	{
		return 1; // port is active.
	}

	return 0; // port is inactive.
}
#endif //_PORT_CHK_ACTIVE

/**
 * nd_device_ioctl - 사용자 공간에서 보낸 IOCTL 명령을 처리하는 함수
 * @file: 파일 객체 포인터
 * @cmd: IOCTL 명령 코드
 * @arg: 사용자 공간에서 전달된 인자 (보통 포인터)
 *
 * 반환값:
 *   0 성공
 *  -EFAULT 사용자 공간으로 복사 실패
 *  그 외 상황에 따라 적절한 에러코드 반환 가능
 */
static long nd_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{

	int ret = 0;
	struct cmd_service_rule_pars_data cmd_service_rule_pars;
	struct cmd_service_sub_rule_pars_data cmd_service_subrule_pars;
	struct cmd_nic_rule_pars_data cmd_nic_rule_pars;
	struct st_log_config log_set;
	struct cmd_bypass_rule_pars_data cmd_bypass_rule_pars;
	
	__u16 uServicePort = 0;
	char sServicePortData[6] = {0,};

	char sErrMsg[256] = {0,};
	char cmd_str_data[MAX_STRING_LENGTH] = {0,};
	char sLogData[LOG_MSG_SIZE] = {0,};

	//snprintf(sLogData, sizeof(sLogData), "TRACE: Received IOCTL command [0x%x] with argument [0x%lx] int (%d)", cmd, arg, cmd);
	//ND_LOG(LOG_TRC, sLogData);
	switch (cmd)
	{

	case IOCTL_GET_CONNECTSESSIONCNT:
		snprintf(sLogData, sizeof(sLogData), "Successfully retrieved the number of current connection sessions [%d]", session_m_cnt);
		ND_LOG(LOG_DBG, sLogData);

		sprintf(cmd_str_data, "%d", session_m_cnt);
		if (copy_to_user((char __user *)arg, cmd_str_data, strlen(cmd_str_data) + 1))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EFAULT;
		}
		break;
	case IOCTL_GET_VERSION:
		snprintf(sLogData, sizeof(sLogData), "Getting the version information of the driver., module version is [%s]", module_version);
		ND_LOG(LOG_DBG, sLogData);

		if (copy_to_user((char __user *)arg, module_version, strlen(module_version) + 1))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EFAULT;
		}
		break;

	case IOCTL_ON_MODE:
		snprintf(sLogData, sizeof(sLogData), "Changing the operating mode. Current mode: %d", g_nLkmMode);
		ND_LOG(LOG_TRC, sLogData);

		if (g_nLkmMode != MODE_ON)
		{
			g_nLkmMode = MODE_ON;
			snprintf(sLogData, sizeof(sLogData), "Activate kernel operation mode - Successfully enabled kernel operating mode\n");
		}
		else
		{
			snprintf(sLogData, sizeof(sLogData), "Activate kernel operation mode - Already activating kernel operating mode\n");
		}

		ND_LOG(LOG_INF, sLogData);
		break;

	case IOCTL_OFF_MODE:

		snprintf(sLogData, sizeof(sLogData), "Changing the operation mode. Current mode: %d", g_nLkmMode);
		ND_LOG(LOG_TRC, sLogData);

		if (g_nLkmMode != MODE_OFF)
		{
			g_nLkmMode = MODE_OFF;

			snprintf(sLogData, sizeof(sLogData), "disable kernel operation mode - Successfully disable kernel operating mode\n");
		}
		else
		{
			snprintf(sLogData, sizeof(sLogData), "disable kernel operation mode - Already disable kernel operating mode\n");
		}

		ND_LOG(LOG_INF, sLogData);
		break;

	case IOCTL_GET_MODE:
		snprintf(sLogData, sizeof(sLogData), "Retrieving the configured operating mode. Current mode: %d", g_nLkmMode);
		ND_LOG(LOG_TRC, sLogData);

		sprintf(cmd_str_data, "%s", (g_nLkmMode == MODE_ON) ? "MODE_ON" : "MODE_OFF");
		if (copy_to_user((char __user *)arg, cmd_str_data, strlen(cmd_str_data) + 1))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EFAULT;
		}

		snprintf(sLogData, sizeof(sLogData), "Successfully retrieved the configured operating mode.. Current mode: %d", g_nLkmMode);
		ND_LOG(LOG_TRC, sLogData);
		break;

	case IOCTL_ADD_SERVICE_POLICY:

		snprintf(sLogData, sizeof(sLogData), "Adding a service policy for forwarding. [Service: %u, Forward: %u]",
				 cmd_service_rule_pars.service, cmd_service_rule_pars.forward);
		ND_LOG(LOG_TRC, sLogData);

		ND_LOG(LOG_DBG, "Adding a service policy for forwarding.");

		if (copy_from_user(&cmd_service_rule_pars, (struct cmd_service_rule_pars_data *)arg, sizeof(struct cmd_service_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		snprintf(sLogData, sizeof(sLogData), "DEBUG: Copied data from user. Service: %u, Forward: %u",
				 cmd_service_rule_pars.service, cmd_service_rule_pars.forward);
		ND_LOG(LOG_DBG, sLogData);

		ret = nd_add_service(cmd_service_rule_pars.service, cmd_service_rule_pars.forward, cmd_service_rule_pars.data, sErrMsg);
		if (ret == 0)
		{

			snprintf(sLogData, sizeof(sLogData), "Successfully added a service policy for forwarding. Service name [%u] has been added.", cmd_service_rule_pars.service);
			ND_LOG(LOG_INF, sLogData);
			ND_LOG(LOG_DBG, sLogData);

			cmd_service_rule_pars.ret = ret;
		}
		else
		{
			if (strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004504") == 0)
			{
				snprintf(sLogData, sizeof(sLogData), "[%s]: Failed to add a service policy for forwarding.",
						 sErrMsg);
			}
			else if (strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004505") == 0)
			{
				snprintf(sLogData, sizeof(sLogData), "[%s]: Failed to add a service policy for forwarding.-There is a same policy.",
						 sErrMsg);
			}
			else if (strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004507") == 0)
			{
				snprintf(sLogData, sizeof(sLogData), "[%s]: Failed to add a service policy for forwarding.-The policy was not found.",
						 sErrMsg);
			}
			ND_LOG(LOG_ERR, sLogData);
			cmd_service_rule_pars.ret = ret;
		}

		if (copy_to_user((struct cmd_service_rule_pars_data *)arg, &cmd_service_rule_pars, sizeof(cmd_service_rule_pars)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EINVAL;
		}
		break;

	case IOCTL_ADD_ACTION_POLICY:

		if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data *)arg, sizeof(struct cmd_service_sub_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_add_action_in_service_rule(cmd_service_subrule_pars.service, cmd_service_subrule_pars.type, cmd_service_subrule_pars.saddr, cmd_service_subrule_pars.s_range, cmd_service_subrule_pars.eaddr, sErrMsg);
		if (ret == 0)
		{
			snprintf(sLogData, sizeof(sLogData), "Successfully added a mapping policy for the [%u] service.", cmd_service_subrule_pars.service);
			ND_LOG(LOG_INF, sLogData);
		}
		else
		{
			if (strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004508") == 0 ||
				strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004511") == 0)
			{
				ND_LOG(LOG_ERR, "[%s]: Failed to add a mapping policy for the [%u] service.-There are no registered target services.", sErrMsg, cmd_service_subrule_pars.service);
			}
			else if (strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004509") == 0 ||
					 strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004512") == 0 ||
					 strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004513") == 0)
			{
				ND_LOG(LOG_ERR, "[%s]: Failed to add a mapping policy for the [%u] service.-Failed to obtain the service object.", sErrMsg, cmd_service_subrule_pars.service);
			}
			else if (strcmp(sErrMsg, "NIXNK-LKMIRQ_M-004510") == 0)
			{
				ND_LOG(LOG_ERR, "[%s]: Failed to add a mapping policy for the [%u] service.-There is a same policy.", sErrMsg, cmd_service_subrule_pars.service);
			}
		}

		cmd_service_subrule_pars.ret = ret;

		if (copy_to_user((struct cmd_service_sub_rule_pars_data *)arg, &cmd_service_subrule_pars, sizeof(cmd_service_subrule_pars)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EINVAL;
		}

		break;

	case IOCTL_MOD_SERVICE_POLICY: // NOT USE

		if (copy_from_user(&cmd_service_rule_pars, (struct cmd_service_rule_pars_data *)arg, sizeof(struct cmd_service_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_mod_service_to_index(&cmd_service_rule_pars);
		if (ret == 0)
		{
			snprintf(sLogData, sizeof(sLogData), "INFO: Successfully moded policy - Service name [%u] has been moded...", cmd_service_rule_pars.service);
			ND_LOG(LOG_INF, sLogData);
		}

		break;

	case IOCTL_MOD_ACTION_POLICY: // NOT USE

		if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data *)arg, sizeof(struct cmd_service_sub_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_mod_action_in_service_rule_to_index(&cmd_service_subrule_pars);
		if (ret == 0)
		{
			snprintf(sLogData, sizeof(sLogData), "INFO: Successfully moded policy - action policy has been modified.");
			ND_LOG(LOG_INF, sLogData);
		}
		break;

	case IOCTL_MOD_DROPEXCEPT_POLICY: // NOT USE
		if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data *)arg, sizeof(struct cmd_service_sub_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}
		break;

	case IOCTL_DEL_SERVICE_POLICY:
#ifdef _SERVICE_STRUCT_TYPE
		if (copy_from_user(&cmd_service_rule_pars, (struct cmd_service_rule_pars_data *)arg, sizeof(cmd_service_rule_pars)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_del_service(cmd_service_rule_pars.service, sErrMsg);
		if (ret == 0)
		{
			snprintf(sLogData, sizeof(sLogData), "Successfully deleted the service policy for forwarding. - Service name [%u] has been deleted", cmd_service_rule_pars.service);
			ND_LOG(LOG_INF, sLogData);
		}
		else
		{
			ND_LOG(LOG_ERR, "[%s]: Failed to delete the service policy for forwarding.", sErrMsg);
		}
#endif //_SERVICE_STRUCT_TYPE
		if (copy_from_user(sServicePortData, (char __user *)arg, sizeof(sServicePortData))) {
                	return -EFAULT; // Error copying data from user space
            	}

		if (kstrtou16(sServicePortData, 10, &uServicePort) == 0 )
		{
			ret = nd_del_service(uServicePort, sErrMsg);
			if (ret == 0)
			{
				snprintf(sLogData, sizeof(sLogData), "Successfully deleted the service policy for forwarding. - Service name [%u] has been deleted", uServicePort);
				ND_LOG(LOG_INF, sLogData);
			}
		}
		else
		{
			ND_LOG(LOG_ERR, "[%s]: Failed to delete the service policy for forwarding.", sErrMsg);
		}
		
		
		break;

	case IOCTL_DEL_ACTION_POLICY:

		if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data *)arg, sizeof(struct cmd_service_sub_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_del_action_in_service_rule(cmd_service_subrule_pars.service, cmd_service_subrule_pars.type, cmd_service_subrule_pars.saddr, cmd_service_subrule_pars.s_range, cmd_service_subrule_pars.eaddr, sErrMsg);
		if (ret == 0)
		{
			snprintf(sLogData, sizeof(sLogData), "Successfully deleted the mapping policy for the [%u] service.", cmd_service_subrule_pars.service);
			ND_LOG(LOG_INF, sLogData);
		}
		else
		{
			ND_LOG(LOG_ERR, "[%s]: Failed to delete the mapping policy for the [%u] service.", sErrMsg, cmd_service_subrule_pars.service);
		}
		break;

	case IOCTL_RESET_SERVICE_POLICY:

		break; 

	case IOCTL_GET_SERVICE_POLICY_INDEX:

		if (copy_from_user(&cmd_service_rule_pars, (struct cmd_service_rule_pars_data *)arg, sizeof(cmd_service_rule_pars)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_nfm_get_service_rule_index(cmd_service_subrule_pars.service);

		cmd_service_subrule_pars.ret = ret;
		if (copy_to_user((struct cmd_service_sub_rule_pars_data *)arg, &cmd_service_subrule_pars, sizeof(cmd_service_subrule_pars)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EINVAL;
		}
		break;

	case IOCTL_GET_ACTION_POLICY_INDEX:

		if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data *)arg, sizeof(struct cmd_service_sub_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_get_actions_in_service_rule_to_index(&cmd_service_subrule_pars);

		cmd_service_subrule_pars.ret = ret;
		if (copy_to_user((struct cmd_service_sub_rule_pars_data *)arg, &cmd_service_subrule_pars, sizeof(cmd_service_subrule_pars)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EINVAL;
		}
		break;

	case IOCTL_GET_SERVICE_POLICY:

		if (copy_from_user(&cmd_str_data, (char __user *)arg, MAX_STRING_LENGTH))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		nd_nfm_get_service_rules(cmd_str_data);

		if (copy_to_user((char __user *)arg, cmd_str_data, sizeof(cmd_str_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EFAULT;
		}
		break;

	case IOCTL_GET_ACTION_POLICY:

		if (copy_from_user(&cmd_str_data, (char __user *)arg, MAX_STRING_LENGTH))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		nd_nfm_get_action_rules(cmd_str_data);

		if (copy_to_user((char __user *)arg, cmd_str_data, sizeof(cmd_str_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EFAULT;
		}

		break;

	case IOCTL_GET_DROPEXCEPT_POLICY:
		break;

	case IOCTL_RESET_POLICY:

		ret = nd_reset_all_rule();
		if (ret == 0)
		{
			ND_LOG(LOG_INF, "Successfully initialized all stored policies..");
		}
		else
		{
			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004503]: Failed to initialize all stored policies.");
		}

		break;

	case IOCTL_GET_LOG:

		return nd_get_logs((char __user *)arg, MAX_BUFFER_SIZE);
		break;

	case IOCTL_SET_LOG_SETTINGS:

		if (copy_from_user(&log_set, (struct st_log_config __user *)arg, sizeof(struct st_log_config)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		set_debug_log_enabled(log_set.debug_log_enabled);
		set_warn_log_enabled(log_set.warn_log_enabled);
		set_trace_log_enabled(log_set.trace_log_enabled);
		set_info_log_enabled(log_set.info_log_enabled);
		set_error_log_enabled(log_set.error_log_enabled);

		ND_LOG(LOG_INF, "Setting to Log config : warn[%d], error[%d], info[%d], debug[%d], trace[%d]", log_set.warn_log_enabled, log_set.error_log_enabled, log_set.info_log_enabled, log_set.debug_log_enabled, log_set.trace_log_enabled);

		break;

	case IOCTL_GET_LOG_SETTINGS:

		if (copy_to_user((struct st_log_config *)arg, &global_log_settings, sizeof(struct st_log_config)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004501]: copy_to_user function call failed: Failed to copy data to user memory.");
			return -EINVAL;
		}

		break;

	case IOCTL_ADD_NIC_RULE:
		if (copy_from_user(&cmd_nic_rule_pars, (struct cmd_nic_rule_pars_data *)arg, sizeof(struct cmd_nic_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_nfm_add_nic_rule(&cmd_nic_rule_pars, sErrMsg);
		if (ret == 0)
		{
			snprintf(sLogData, sizeof(sLogData), "Successfully added the network card policy."/* - added nic included in nic name %s", cmd_nic_rule_pars.name*/);
			ND_LOG(LOG_INF, sLogData);
		}
		else
		{
			if (strcmp(sErrMsg, "NIXNK-LKMIRQ_M-00450") == 0)
			{
				ND_LOG(LOG_ERR, "[%s]: Failed to add the network card policy.");
			}
			else if (strcmp(sErrMsg, "NIXNK-LKMIRQ_M-00451") == 0)
			{
				ND_LOG(LOG_ERR, "[%s]: Failed to add the network card policy.-There is a same policy.");
			}
		}

		break;

	case IOCTL_DEL_NIC_RULE:
		if (copy_from_user(&cmd_nic_rule_pars, (struct cmd_nic_rule_pars_data *)arg, sizeof(struct cmd_nic_rule_pars_data)))
		{

			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_nfm_del_nic_rule(&cmd_nic_rule_pars, sErrMsg);
		if (ret == 0)
		{
			snprintf(sLogData, sizeof(sLogData), "Successfully deleted the network card policy."/* - deleted nic included in nic name %s", cmd_nic_rule_pars.name*/);
			ND_LOG(LOG_INF, sLogData);
		}
		else
		{
			ND_LOG(LOG_ERR, "[%s]: Failed to delete the network card policy.", sErrMsg);
		}

		break;

	case IOCTL_RESET_NIC_RULE:
		ret = nd_nfm_reset_nic_rules();
		break;

	case IOCTL_ADD_BYPASS_RULE:
		if (copy_from_user(&cmd_bypass_rule_pars, (struct cmd_bypass_rule_pars_data *)arg, sizeof(struct cmd_bypass_rule_pars_data)))
		{
			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_nfm_add_bypass_rule(&cmd_bypass_rule_pars, sErrMsg);
		if (ret == 0)
		{
			snprintf(sLogData, sizeof(sLogData), "Successfully added bypass policy.");
			ND_LOG(LOG_INF, sLogData);
		}
		else
		{
			ND_LOG(LOG_ERR, "[%s]: Failed to added the bypass policy.", sErrMsg);
		}
		break;

	case IOCTL_DEL_BYPASS_RULE:
		if (copy_from_user(&cmd_bypass_rule_pars, (struct cmd_bypass_rule_pars_data *)arg, sizeof(struct cmd_bypass_rule_pars_data)))
		{
			ND_LOG(LOG_ERR, "[NIXNK-LKMIRQ_M-004502]: copy_from_user function call failed: Failed to copy data from user memory.");
			return -EFAULT;
		}

		ret = nd_nfm_del_bypass_rule(&cmd_bypass_rule_pars, sErrMsg);
		break;

	case IOCTL_RESET_PYPASS_RULE:
		ret = nd_nfm_reset_bypass_rule();
		break;

	default:
		ND_LOG (LOG_ERR, "IOCTL NOT FOUND!!");
		return -EINVAL;
	}

	return 0;
}

#ifdef _MON_SESSION


/**
 * monitor_conntrack_hook - Netfilter hook 함수, TCP 패킷의 연결 추적 상태를 모니터링
 * @priv: hook 등록 시 전달된 private 데이터 (사용 안 함)
 * @skb: 처리할 소켓 버퍼
 * @state: Netfilter hook state (입출력 디바이스, 위치 등)
 *
 * 반환값:
 *   NF_ACCEPT - 패킷을 계속 통과시킴
 *
 * 동작 설명:
 *   - IP 헤더를 추출하고 TCP 프로토콜 여부 확인
 *   - nf_conntrack을 통해 연결 추적 상태(ctinfo)를 가져옴
 *   - 연결 상태별로 로깅 또는 특정 동작을 할 수 있는 기반 마련
 *   - 현재는 모든 패킷을 ACCEPT
 */
static unsigned int monitor_conntrack_hook(void *priv,
										   struct sk_buff *skb,
										   const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	// Ensure the socket buffer is valid
	if (!skb)
	{
		return NF_ACCEPT;
	}
	// Extract IP header
	iph = ip_hdr(skb);
	if (!iph)
	{
		return NF_ACCEPT;
	}

	// Connection tracking for TCP packets only
	if (iph->protocol == IPPROTO_TCP)
	{
		ct = nf_ct_get(skb, &ctinfo);
		if (!ct)
		{
			return NF_ACCEPT;
		}

		// Get the connection state
		switch (ctinfo)
		{
		case IP_CT_NEW:
			//printk(KERN_ERR "Conntrack: NEW connection\n");
			break;
		case IP_CT_ESTABLISHED:
			//printk(KERN_ERR "Conntrack: ESTABLISHED connection\n");
			break;
		case IP_CT_RELATED:
			//printk(KERN_ERR "Conntrack: RELATED connection\n");
			break;
		case IP_CT_IS_REPLY:
			//printk(KERN_ERR "Conntrack: REPLY packet\n");
			break;
		case IP_CT_UNTRACKED:
			//printk(KERN_ERR "Conntrack: UNTRACKED packet\n");
			break;
		default:
			//printk(KERN_ERR "Conntrack: OTHER state: %d\n", ctinfo);
			break;
		}
	}

	return NF_ACCEPT;
}

#endif //_MON_SESSION

#define DNS_HEADER_SIZE 12

#ifdef _DNS_QUERY_SUPPORT
/*
	//A function that extracts the domain name.
*/
/**
 * extract_domain_name - DNS 패킷에서 질의 도메인 이름을 추출
 * @dns_data: DNS 패킷 데이터 포인터 (UDP payload 기준)
 * @dns_len: DNS 데이터의 전체 길이
 *
 * 설명:
 *   - DNS 헤더는 12바이트로 고정되어 있으며, 이후부터 도메인 질의 정보가 시작됨
 *   - 질의 이름은 label 형식으로 구성되어 있으며, 각 label은 [length][data] 형태
 *   - 예: "www.example.com" → [3]www[7]example[3]com[0]
 *   - 도메인 이름이 너무 크거나 포맷이 잘못된 경우 중단
 *   - 결과는 로그(DEBUG)로 출력됨
 */
static void  extract_domain_name(const unsigned char *dns_data, unsigned int dns_len)
{
	unsigned int i = 12; // DNS 헤더는 12 바이트
	unsigned char domain[256];// 도메인 이름을 저장할 버퍼
	unsigned int pos = 0;

    // 유효성 검사: 데이터가 충분히 있는지 확인
	if ( !dns_data || dns_len <= 12) {
		/**/
		//printk(KERN_INFO "DNS packet too short\n");
		return ;
	}

    // 도메인 이름 파싱 시작
	while (i < dns_len && dns_data[i] != 0) {
		unsigned int label_len = dns_data[i];
		i++;

        // label 길이가 남은 데이터 범위를 초과하면 잘못된 패킷
		if (label_len + i > dns_len) {
			/*
			printk(KERN_INFO "Invalid DNS packet: label length out of bounds\n");
			*/
			//kfree(domain);
			return;
		}

		// pos와 label_len이 domain 버퍼 크기를 초과하는지 확인
		if (pos + label_len >= sizeof(domain)) {
			/*
			printk(KERN_INFO "Domain name too long for buffer\n");
			*/
			//kfree(domain);
			return;
		}

        // label 복사
		memcpy(domain + pos, dns_data + i, label_len);
		pos += label_len;

        // 각 label 사이에 '.' 추가
		domain[pos++] = '.';
		i += label_len;
	}

    // 마지막 '.'을 '\0'로 대체하여 문자열 종료
	if (pos > 0) {
		domain[pos - 1] = '\0'; // 마지막 점을 제거하고 null-terminate
	} else {
		domain[pos] = '\0'; // 비어 있는 경우에도 안전하게 처리
	}

	 ND_LOG(LOG_DBG, "DEBUG: DNS Query for: %s\n", domain);

	//return domain;
}


/**
 * extract_ip_addresses - DNS 응답 패킷에서 Answer Section의 IP 주소를 추출
 * @dns_data: DNS 패킷 데이터 (UDP payload 기준)
 * @dns_len: 데이터 전체 길이
 *
 * 설명:
 *   - DNS 응답 패킷에서 Answer Section을 파싱하여 IPv4 주소를 추출
 *   - RDATA의 길이가 4인 경우 IPv4 주소로 간주하여 로그 출력
 */
static void extract_ip_addresses(const unsigned char *dns_data, unsigned int dns_len) {
    unsigned int i = 12; // DNS 헤더는 12 바이트
    unsigned int answer_count;
	unsigned int j;
    
    if (!dns_data || dns_len <= 12) {
        //printk(KERN_INFO "DNS packet too short\n");
        return;
    }

    // DNS 헤더에서 응답 수를 가져옵니다.
    answer_count = (dns_data[6] << 8) | dns_data[7];

    // Question Section을 건너뜁니다.
    while (i < dns_len && dns_data[i] != 0) {
        i += dns_data[i] + 1; // 레이블 길이 + 레이블
    }
    i += 5; // null terminator + QTYPE(2 bytes) + QCLASS(2 bytes)

    // Answer Section에서 IP 주소를 추출합니다.
    for ( j = 0; j < answer_count; j++) {
        if (i >= dns_len) {
            //printk(KERN_INFO "No more data in DNS packet\n");
            return;
        }

        // Answer Section의 이름 필드 (포인터일 수 있음)
        if (dns_data[i] & 0xC0) {
            // 포인터 처리
            i += 2; // 포인터는 2 바이트
        } else {
            // 이름 필드 건너뛰기
            while (i < dns_len && dns_data[i] != 0) {
                i += dns_data[i] + 1;
            }
            i++; // null terminator
        }

        // TYPE (2 bytes)
        i += 2;

        // CLASS (2 bytes)
        i += 2;

        // TTL (4 bytes)
        i += 4;

        // RDLENGTH (2 bytes)
        unsigned int rdlength = (dns_data[i] << 8) | dns_data[i + 1];
        i += 2;

        // IP 주소는 RDATA에 위치
        if (rdlength == 4) { // IPv4 주소의 길이
            unsigned char ip[4];
            memcpy(ip, dns_data + i, 4);
            ND_LOG(LOG_DBG, "DEBUG: Extracted IP Address: %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
        }

        i += rdlength; // RDATA 길이만큼 이동
    }
}

#endif //_DNS_QUERY_SUPPORT

/**
 * nd_nix_hook_inbound_func - Netfilter HOOK(INBOUND) 함수
 * @priv: 사용자 정의 private 데이터 (사용되지 않음)
 * @skb: 현재 처리 중인 소켓 버퍼
 * @state: Netfilter 훅 상태 정보 (입출력 인터페이스 등 포함)
 *
 * 설명:
 *   - 조건에 따라 패킷의 TCP 포트를 수정 (테스트 용도)
 *   - 이후 로직에서는 5-tuple 추출, 룰 검사 등 보안 처리를 수행할 수 있음
 *
 * 반환값:
 *   - NF_ACCEPT: 패킷 통과 허용
 *   - (향후 NF_DROP 등으로 확장 가능)
 */
unsigned int nd_nix_hook_inbound_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	__sum16 original_checksum, calculated_checksum;

	unsigned char *h;
	struct tcphdr *tcph;
	struct in_ifaddr *ifa;
	uint16_t sport = 0, dport = 0, datalen = 0;
	int nChkRuleResult = ND_ACT_FLOWRULE_NOTFOUND;
	int ret = 0;

    /*
     * if you use dns query..
     */
	/*
	char *dns_query;
    unsigned short dns_length;
    struct udphdr *udp_header;
	*/

	struct nd_modifled_packet_result *collect_data;
	struct nd_5tuple_data current_5tuple;
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
	struct net_device *dev = skb->dev;

    /*
	ND_LOG(LOG_DBG, "Original checksum: 0x%04x\n", ntohs(original_checksum));
    ND_LOG(LOG_DBG, "Calculated checksum: 0x%04x\n", ntohs(calculated_checksum));
    */

	if (!iph) {

            ND_LOG(LOG_DBG, "Inbound packet dropped: Failed to extract IP header from skb (dev: %s)", dev ? dev->name : "unknown");
        	return NF_ACCEPT;
    	}	

	if (g_nLkmMode != MODE_ON)
	{
		goto InboundExit;
	}

	if (dev)
	{
		if (dev->ip_ptr)
		{
			for (ifa = dev->ip_ptr->ifa_list; ifa; ifa = ifa->ifa_next)	{
				ret = nd_nfm_chk_nic_rule (ifa);
				if (ret != ND_CHECK_OK)
				{
                     ND_LOG(LOG_DBG, "Inbound packet dropped: NIC rule check failed on interface [%s], IP: %pI4", dev->name, &ifa->ifa_address);
                     
                     goto InboundExit;
				}
			}
		}
	}


	switch (iph->protocol)
	{
		case IPPROTO_TCP:
		{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
			if (likely(skb_transport_header(skb) == (unsigned char *)iph)) )
			{
                //printk("transport_header is not set for kernel 0x%x\n", LINUX_VERSION_CODE);
#else
			if (!skb_transport_header_was_set(skb))
			{
#endif
				h = (unsigned char *)iph + (iph->ihl << 2);
			}
			else
			{
				h = skb_transport_header(skb);
			}

			if (skb_linearize(skb) != 0)
			{
                 ND_LOG(LOG_ERR, "Failed to linearize skb: dropping packet on interface [%s]", skb->dev ? skb->dev->name : "unknown");
			     return NF_DROP;
			}

			iph = ip_hdr(skb);

			tcph = (struct tcphdr *)h;
			sport = (unsigned int)ntohs(tcph->source);
			dport = (unsigned int)ntohs(tcph->dest);

			memset(&current_5tuple, 0x00, sizeof(current_5tuple));
			current_5tuple = (struct nd_5tuple_data){
				.sport = sport,
				.dport = dport,
				.saddr = iph->saddr,
				.daddr = iph->daddr,
				.hook = state->hook};

			collect_data = (struct nd_modifled_packet_result *)kmalloc(sizeof(struct nd_modifled_packet_result), GFP_KERNEL);
			nChkRuleResult = nd_nfm_comfirm_the_policy_for_incoming_packet(current_5tuple, &collect_data);

			if (dport != 22) 
			 	ND_LOG (LOG_DBG, "DEBUG: inbound packet information -> source ip:%pI4(%u),dest ip: %pI4(%u),sport: %u,  dport : %u \n", &iph->saddr,iph->saddr, &iph->daddr,iph->daddr, sport, dport);

			if (nChkRuleResult == ND_ACT_FLOWRULE_APPLY)
			{

				if (iph->saddr == ND_LOOPBACK && iph->daddr == ND_LOOPBACK && (iph->saddr == iph->daddr))
				{
					ND_LOG(LOG_DBG, "Both source and destination are loopback addresses, skipping processing");

					if (collect_data)
						kfree(collect_data);

					ND_LOG(LOG_TRC, "Exiting nd_nix_hook_inbound_func: Loopback addresses");

					goto InboundExit;
				}

				ND_LOG(LOG_DBG, "DEBUG: [inbound packet] [nd_nix_nfm] forwarding destination port [%u] -> [%u].", ntohs(tcph->dest), collect_data->forwardport);


				tcph->dest = htons(collect_data->forwardport);
				__sum16 original_ip_checksum, original_tcp_checksum;
				__sum16 calculated_ip_checksum, calculated_tcp_checksum;

				original_ip_checksum = iph->check;

				iph->check = 0;
				iph->check = ip_fast_csum(iph, iph->ihl);
				calculated_ip_checksum = iph->check;

				original_tcp_checksum = tcph->check;
				tcph->check = 0;
				tcph->check = tcp_v4_check(skb->len - ip_hdrlen(skb), iph->saddr, iph->daddr, csum_partial(tcph, skb->len - ip_hdrlen(skb), 0));
				calculated_tcp_checksum = tcph->check;

				skb->ip_summed = CHECKSUM_NONE;


				ND_LOG (LOG_DBG, "#### [IN IP CHECKSUM] - (old)0x%04x/ (new)0x%04x", original_ip_checksum, calculated_ip_checksum);
				ND_LOG (LOG_DBG, "#### [IN TCP CHECKSUM] - (old)0x%04x/ (new)0x%04x", original_tcp_checksum, calculated_tcp_checksum);
			}
			else
			{
				if (dport != 22)
				 	ND_LOG (LOG_DBG, "DEBUG: inbound packet information NOT MATCH RULE -> source ip:%pI4(%u),dest ip: %pI4(%u),sport: %u,  dport : %u \n", &iph->saddr,iph->saddr, &iph->daddr,iph->daddr, sport, dport);
			}

			if (collect_data)
				kfree(collect_data);

			break;
		}

		case IPPROTO_UDP:
		{
#ifdef _DNS_QUERY_SUPPORT
            unsigned char *dns_data;
            unsigned int dns_len;
            struct udphdr *udph;

            udph = udp_hdr(skb);
            if (!udph)
                return NF_ACCEPT;

            // DNS 데이터 및 길이 계산
            dns_data = (unsigned char *)udph + sizeof(struct udphdr);
            dns_len = ntohs(udph->len) - sizeof(struct udphdr);

            // 포트 정보 추출
            uint16_t sport = ntohs(udph->source);
            uint16_t dport = ntohs(udph->dest);

            // 도메인 이름 및 응답 IP 추출 (내부 로그 출력한다고 가정)
            extract_domain_name(dns_data, dns_len);
            extract_ip_addresses(dns_data, dns_len);

            // 패킷 정보 로그 출력
            ND_LOG(LOG_DBG,
                "Inbound UDP packet → src_ip: %pI4, dst_ip: %pI4, sport: %u, dport: %u",
                &iph->saddr, &iph->daddr, sport, dport);

            return NF_ACCEPT;
#endif //_DNS_QUERY_SUPPORT

			break;
		}

		default:
		{
			break;
		}
	};

InboundExit:

	return NF_ACCEPT;

}


/**
 * nd_nix_hook_outbound_func - Netfilter HOOK(OUTBOUND) 함수
 * @priv: 사용자 정의 private 데이터 (사용되지 않음)
 * @skb: 현재 처리 중인 소켓 버퍼
 * @state: Netfilter 훅 상태 정보
 *
 * 설명:
 *   - 패킷 송신 전단계에서 5-tuple 추출, 룰 검사, TCP 체크섬 검증 등을 수행
 *   - g_nLkmMode가 OFF 상태면 즉시 NF_ACCEPT
 *   - 이후 동작: 포트 필터링, 체크섬 검증, 로그 기록 등 확장 가능
 *
 * 반환값:
 *   - NF_ACCEPT: 패킷을 계속 허용
 *   - 향후 조건에 따라 NF_DROP 또는 NF_STOLEN 반환 가능
 */
unsigned int nd_nix_hook_outbound_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    __sum16 original_checksum, calculated_checksum;
	unsigned char *h;
	struct tcphdr *tcph = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);;
	struct in_ifaddr *ifa;
	uint16_t sport = 0, dport = 0;
	uint16_t datalen = 0;
	int nChkRuleResult = 0, ret = 0;
	int ip_header_len = 0, tcp_header_len = 0, tcp_payload_len = 0;
	__wsum tcp_csum ;

	struct nd_modifled_packet_result *collect_data;
	struct nd_5tuple_data current_5tuple;
	struct net_device *dev;

	if (g_nLkmMode != MODE_ON)
	{
		return NF_ACCEPT;
	}

	dev = skb->dev;
	if (dev)
	{
        if (dev->ip_ptr)
        {
            /*
             *  nic card rule : dose not use now...
             */
            for (ifa = dev->ip_ptr->ifa_list; ifa; ifa = ifa->ifa_next)     {
                //printk (KERN_INFO  "%s has ipaddress [%pI4]",dev->name, &ifa->ifa_address);
                ret = nd_nfm_chk_nic_rule (ifa);
                if (ret != ND_CHECK_OK)
                {
                        //goto InboundExit;
                        //printk (KERN_INFO "nd_nfm_chk_nic_rule ret != ND_CHECK_OK");
                }
                else
                {
                        //printk (KERN_INFO "nd_nfm_chk_nic_rule ret == ND_CHECK_OK");
                }
            }
        }
	}

	switch (iph->protocol)
	{
		case IPPROTO_TCP:
		{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
            if (likely(skb_transport_header(skb) == (unsigned char *)iph)) )
            {
                //printk("transport_header is not set for kernel 0x%x\n", LINUX_VERSION_CODE);
#else
            if (!skb_transport_header_was_set(skb))
            {
#endif
                h = (unsigned char *)iph + (iph->ihl << 2);
            }
            else
            {
                h = skb_transport_header(skb);
            }

            if (skb_linearize(skb) != 0)
            {
                return NF_DROP;
            }
            
			sport = (unsigned int)ntohs(tcph->source);
			dport = (unsigned int)ntohs(tcph->dest);

			memset(&current_5tuple, 0x00, sizeof(current_5tuple));
			current_5tuple = (struct nd_5tuple_data){
				.sport = sport,
				.dport = dport,
				.saddr = iph->saddr,
				.daddr = iph->daddr,
				.hook = state->hook};

			collect_data = (struct nd_modifled_packet_result *)kmalloc(sizeof(struct nd_modifled_packet_result), GFP_KERNEL);
			nChkRuleResult = nd_nfm_comfirm_the_policy_for_incoming_packet(current_5tuple, &collect_data);

			if (sport != 22)
			{
				 ND_LOG (LOG_DBG, "DEBUG: outbound packet information -> source ip:%pI4(%u),dest ip: %pI4(%u),sport: %u,  dport : %u \n", &iph->saddr,iph->saddr, &iph->daddr,iph->daddr, sport, dport);
			}

			if (nChkRuleResult == ND_ACT_FLOWRULE_APPLY)
			{

				if (iph->saddr == ND_LOOPBACK && iph->daddr == ND_LOOPBACK)
				{
					ND_LOG(LOG_DBG, "Both source and destination are loopback addresses, skipping processing");

					if (collect_data)
						kfree(collect_data);

					ND_LOG(LOG_TRC, "Exiting nd_nix_hook_outbound_func: Loopback addresses");

					goto Exit_function;
				}

				ND_LOG(LOG_DBG, "DEBUG: The packet complies with the audit policy. - [outbound packet] [nd_nix_nfm] forwarding source port [%u] -> [%u].", ntohs(tcph->source), collect_data->forwardport);

				tcph = (struct tcphdr *) (skb->data+ iph->ihl *4);
				

				ND_LOG (LOG_DBG, "#### [OUT TCP CHECKSUM - org] - 0x%04x", ntohs(tcph->check));

				tcph->source = htons(collect_data->forwardport);

				__sum16 original_ip_checksum, original_tcp_checksum;
				__sum16 calculated_ip_checksum, calculated_tcp_checksum;


				original_ip_checksum = iph->check;

				iph->check = 0;
				iph->check = ip_fast_csum(iph, iph->ihl);

				calculated_ip_checksum = iph->check;
				original_tcp_checksum = tcph->check;
				

				ip_header_len = iph->ihl * 4;
				tcp_header_len = tcph->doff * 4;
				tcp_payload_len = ntohs(iph->tot_len) - ip_header_len - tcp_header_len;

				tcph->check = 0;

				// TCP 페이로드의 길이 계산

				//__wsum pseudo_header_csum = csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_payload_len, IPPROTO_TCP, 0);

				tcp_csum = csum_partial(tcph, tcp_header_len + tcp_payload_len, 0);
				tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_header_len + tcp_payload_len, IPPROTO_TCP, tcp_csum);

				calculated_tcp_checksum = tcph->check;

				// CHECKSUM_NONE 설정
				skb->ip_summed = CHECKSUM_NONE;

				ND_LOG (LOG_DBG, "#### [OUT IP CHECKSUM] - (old)0x%04x/ (new)0x%04x", ntohs(original_ip_checksum) ,ntohs(calculated_ip_checksum));
				ND_LOG (LOG_DBG, "#### [OUT TCP CHECKSUM] - (old)0x%04x/ (new)0x%04x", ntohs(original_tcp_checksum ), ntohs(calculated_tcp_checksum));
 			
			}

			if (collect_data)
				kfree(collect_data);

			break;
		}
		default:
		{
			break;
		}
	}
Exit_function:
	return NF_ACCEPT;
}

/*
 *
 */
unsigned int nd_nix_hook_postrouting_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

static int nd_ioctl_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int nd_ioctl_close(struct inode *inode, struct file *file)
{
	return 0;
}

#ifdef _MON_SESSION
static struct nf_hook_ops nf_monitor_hook = {
	.hook = monitor_conntrack_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST + 1, // 우선순위 설정
};
#endif

/**
 * nf_inbound_hook - Netfilter 훅 구조체 (Inbound 패킷용)
 *
 * 설명:
 *   - IPv4 기반 패킷에 대해 PREROUTING 단계에서 Inbound 훅 함수(nd_nix_hook_inbound_func)를 호출
 *   - 패킷이 라우팅되기 전에 들어오는 인터페이스에서 잡아냄
 */
static struct nf_hook_ops nf_inbound_hook = {

	.hook = nd_nix_hook_inbound_func,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};


/**
 * nf_outbound_hook - Netfilter 훅 구조체 (Outbound 패킷용)
 *
 * 설명:
 *   - 로컬 시스템에서 생성된 IPv4 패킷이 실제 송신되기 전 단계에서
 *     nd_nix_hook_outbound_func 훅 함수를 호출
 *   - 예: 사용자 공간 애플리케이션에서 발생한 패킷 가로채기 용도
 */
static struct nf_hook_ops nf_outbound_hook = {
	.hook = nd_nix_hook_outbound_func,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
};


/**
 * fops - 디바이스 파일과 연관된 file_operations 구조체
 *
 * 설명:
 *   - 이 구조체는 사용자 공간에서 디바이스 파일에 대해 수행하는 open/close/ioctl 등의
 *     작업을 처리할 콜백 함수들을 정의함
 *   - 이 구조체는 register_chrdev() 또는 misc_register() 등에 전달되어 디바이스에 연결됨
 */
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = nd_ioctl_open,
	.release = nd_ioctl_close,
	.unlocked_ioctl = nd_device_ioctl,
};


/**
 * nd_nix_nfm_chardev_init - 문자 디바이스 초기화 함수
 *
 * 설명:
 *   - register_chrdev()를 통해 major number를 동적으로 할당받고,
 *     디바이스 클래스 및 노드를 생성하여 /dev/ 디바이스 파일을 등록한다.
 *
 * 반환값:
 *   - 0: 성공
 *   - 음수: 에러 코드 반환 (등록 실패, 클래스 생성 실패 등)
 */
static int nd_nix_nfm_chardev_init(void)
{
	ND_LOG(LOG_DBG, "Initializing character device...");
	nd_major_number = register_chrdev(0, ND_DEVICE_NAME, &fops);

	ND_LOG(LOG_DBG, "Attempting to register char device with major number: %d", nd_major_number);

	if (nd_major_number < 0)
	{
		ND_LOG(LOG_ERR, "Registering char device failed with error code: %d", nd_major_number);
		return nd_major_number;
	}

	ND_LOG(LOG_DBG, "Successfully registered char device with major number: %d", nd_major_number);

	chardev_class = class_create(THIS_MODULE, ND_DEVICE_NAME);
	ND_LOG(LOG_DBG, "Creating device class...");
	if (IS_ERR(chardev_class))
	{
		unregister_chrdev(nd_major_number, ND_DEVICE_NAME);
		//printk("Failed to create class\n");
		return PTR_ERR(chardev_class);
	}

	ND_LOG(LOG_DBG, "Device class created successfully.");

	if (device_create(chardev_class, NULL, MKDEV(nd_major_number, 0), NULL, ND_DEVICE_NAME) == NULL)
	{
		class_destroy(chardev_class);
		unregister_chrdev(nd_major_number, ND_DEVICE_NAME);

		return -1;
	}

	ND_LOG(LOG_DBG, "Device created on /dev/%s", ND_DEVICE_NAME);
	ND_LOG(LOG_INF, "Device created on /dev/%s", ND_DEVICE_NAME);

	return 0;
}

/**
 * nd_nix_nfm_chardev_exit - 문자 디바이스 및 클래스 해제 함수
 *
 * 설명:
 *   - device_destroy(): /dev 노드 제거
 *   - class_destroy(): sysfs에서 클래스 제거
 *   - unregister_chrdev(): 문자 디바이스 등록 해제
 *   - 커널 모듈 제거 시 호출되어 리소스를 정리함
 */
static void nd_nix_nfm_chardev_exit(void)
{
	if (chardev_class)
	{
		device_destroy(chardev_class, MKDEV(nd_major_number, 0));
		class_destroy(chardev_class);
	}

	if (nd_major_number >= 0)
	{

		unregister_chrdev(nd_major_number, ND_DEVICE_NAME);
	}
}


/**
 * nd_nix_nfm_init - 커널 모듈 초기화 함수 (__init)
 *
 * 설명:
 *   - 로그 및 룰 관련 리스트 초기화
 *   - Netfilter 훅 (inbound, outbound) 등록
 *   - 문자 디바이스 초기화
 *   - 커널 모듈이 로드될 때 호출됨
 *
 * 반환값:
 *   0 성공
 *  -1 실패 (Netfilter 훅 등록 실패 등)
 */
static int __init nd_nix_nfm_init(void)
{
	int ret = 0;
	mutex_init(&log_mutex);

	INIT_LIST_HEAD(&log_list.list);
	INIT_LIST_HEAD(&nd_list_nic_rules.list);
	INIT_LIST_HEAD(&nd_list_service_rules_new.list);
	INIT_LIST_HEAD(&nd_list_bypass_rules.list);
	INIT_LIST_HEAD(&nd_sessions.list);

	ND_LOG(LOG_INF, "ND Network Driver starts...");
	ND_LOG(LOG_DBG, "entering nd_nix_nfm_init function");

	ret = nf_register_net_hook(&init_net, &nf_inbound_hook);
	if (ret < 0)
	{
		return -1;
	}

	ret = nf_register_net_hook(&init_net, &nf_outbound_hook);
	if (ret < 0)
	{
		return -1;
	}
	
	// register_pernet_subsys(&net_ops);
	nd_nix_nfm_chardev_init();

	return 0;
}


/**
 * nd_nix_nfm_exit - 커널 모듈 종료 함수 (__exit)
 *
 * 설명:
 *   - 등록된 Netfilter 훅 제거
 *   - 문자 디바이스 및 클래스 제거
 *   - 해시 테이블과 로그 리스트 정리
 *   - 동적 메모리 해제 및 커널 자원 해방
 */
static void __exit nd_nix_nfm_exit(void)
{
	int i;
	struct port_info *info;
	struct hlist_node *tmp;

	struct log_entry *log, *ltmp;

	nd_reset_all_rule();

	nf_unregister_net_hook(&init_net, &nf_inbound_hook);
	nf_unregister_net_hook(&init_net, &nf_outbound_hook);
	// nf_unregister_net_hook(&init_net, &nf_monitor_hook);
	// nf_unregister_net_hook (&init_net, &nf_postrouting_hook);

	// unregister_pernet_subsys(&net_ops);
	nd_nix_nfm_chardev_exit();

	for (i = 0; i < PORT_TABLE_SIZE; i++)
	{
		hlist_for_each_entry_safe(info, tmp, &port_table[i], node)
		{
			hlist_del(&info->node);
			kfree(info);
		}
	}

	mutex_lock(&log_mutex);

	list_for_each_entry_safe(log, ltmp, &log_list.list, list)
	{
		list_del(&log->list);
		kfree(log);
	}

	mutex_unlock(&log_mutex);
	// unregister_chrdev(nd_major_number, ND_DEVICE_NAME);

	return;
}

module_init(nd_nix_nfm_init);
module_exit(nd_nix_nfm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTH);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION("1.0.0");
