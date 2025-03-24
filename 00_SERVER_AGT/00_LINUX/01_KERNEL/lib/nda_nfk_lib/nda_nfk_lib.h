#ifndef ND_NIX_NFM_LIB_H
#define ND_NIX_NFM_LIB_H

#include <errno.h>
#include <stdbool.h> 
#include <linux/types.h>
#include <net/if.h>

#define ND_IOCTL_MAGIC          'N'
#define MAX_STRING_LENGTH       1024
#define MAX_VERSION_LENGTH	    16

#define ND_TYPE_STRUCT          1
#define ND_TYPE_STRING          2

#define ND_IOCTL_TYPE           ND_TYPE_STRUCT

#define MAX_LOGS                256
#define LOG_MSG_SIZE            256

#define MAX_SERVICE_LENGTH      6

#define MAX_BUFFER_SIZE (MAX_LOGS * (LOG_MSG_SIZE +1))


#define IOCTL_ADD_SERVICE_POLICY                _IOWR(ND_IOCTL_MAGIC, 1,        struct cmd_service_rule_pars_data)
#define IOCTL_ADD_ACTION_POLICY                 _IOWR(ND_IOCTL_MAGIC, 2,        struct cmd_service_sub_rule_pars_data)
#define IOCTL_ADD_DROPEXCEPT_POLICY             _IOWR(ND_IOCTL_MAGIC, 3,        struct cmd_service_sub_rule_pars_data)

#define IOCTL_MOD_SERVICE_POLICY                _IOWR(ND_IOCTL_MAGIC, 4,        struct cmd_service_rule_pars_data)
#define IOCTL_MOD_ACTION_POLICY                 _IOWR(ND_IOCTL_MAGIC, 5,        struct cmd_service_sub_rule_pars_data)
#define IOCTL_MOD_DROPEXCEPT_POLICY             _IOWR(ND_IOCTL_MAGIC, 7,        struct cmd_service_sub_rule_pars_data)

#define IOCTL_DEL_SERVICE_POLICY                _IOWR(ND_IOCTL_MAGIC, 8,        char [MAX_SERVICE_LENGTH])
#define IOCTL_DEL_ACTION_POLICY                 _IOWR(ND_IOCTL_MAGIC, 9,        struct cmd_service_sub_rule_pars_data)
#define IOCTL_DEL_DROPEXCEPT_POLICY             _IOWR(ND_IOCTL_MAGIC, 11,       struct cmd_service_sub_rule_pars_data)

#define IOCTL_RESET_POLICY                      _IO(ND_IOCTL_MAGIC,   12)

#define IOCTL_GET_POLICY                        _IOR(ND_IOCTL_MAGIC,  13,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_SERVICE_POLICY_INDEX          _IOR(ND_IOCTL_MAGIC,  14,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_ACTION_POLICY_INDEX           _IOWR(ND_IOCTL_MAGIC, 15,       struct cmd_service_sub_rule_pars_data)

#define IOCTL_GET_SERVICE_POLICY                _IOR(ND_IOCTL_MAGIC,  17,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_ACTION_POLICY                 _IOR(ND_IOCTL_MAGIC,  18,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_DROPEXCEPT_POLICY             _IOR(ND_IOCTL_MAGIC,  20,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_CONNECTSESSIONCNT             _IOR(ND_IOCTL_MAGIC,  21,        char [MAX_STRING_LENGTH])
///
#define IOCTL_ON_MODE                           _IO(ND_IOCTL_MAGIC,   30)
#define IOCTL_OFF_MODE                          _IO(ND_IOCTL_MAGIC,   31)
#define IOCTL_GET_MODE                          _IOR(ND_IOCTL_MAGIC,  32,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_VERSION                       _IOR(ND_IOCTL_MAGIC,  40,        char [MAX_VERSION_LENGTH])
#define IOCTL_GET_LOG                           _IOR(ND_IOCTL_MAGIC,  41,        char *)
#define IOCTL_SET_LOG_SETTINGS                  _IOW(ND_IOCTL_MAGIC,  42,        struct st_log_config)
#define IOCTL_GET_LOG_SETTINGS                  _IOR(ND_IOCTL_MAGIC,  43,        struct st_log_config)
#define IOCTL_ADD_NIC_RULE                      _IOW(ND_IOCTL_MAGIC,  45,        struct cmd_nic_rule_pars_data)
#define IOCTL_DEL_NIC_RULE                      _IOW(ND_IOCTL_MAGIC,  46,        struct cmd_nic_rule_pars_data)
#define IOCTL_RESET_NIC_RULE                    _IO(ND_IOCTL_MAGIC,   47)

#define IOCTL_ADD_BYPASS_RULE                   _IOW(ND_IOCTL_MAGIC,  50,        struct cmd_bypass_rule_pars_data)
#define IOCTL_DEL_BYPASS_RULE                   _IOW(ND_IOCTL_MAGIC,  51,        struct cmd_bypass_rule_pars_data)
#define IOCTL_RESET_PYPASS_RULE                 _IO(ND_IOCTL_MAGIC,   52)


#define ND_DEVICE_NAME "nd_nix_chardev"
#define DEVICE_PATH "/dev/nd_nix_chardev"

struct cmd_service_rule_pars_data
{
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

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/**
 * @brief 드라이버의 버전 문자열을 조회합니다.
 *
 * 이 함수는 사용자 공간에서 커널 드라이버와 통신하여,
 * 현재 로드된 드라이버의 버전 정보를 문자열 형태로 획득합니다.
 *
 * - 디바이스 경로: /dev/nd_nix_chardev
 * - IOCTL 명령: IOCTL_GET_VERSION
 *
 * ----------------------------
 * IOCTL 정의:
 * #define IOCTL_GET_VERSION _IOR(ND_IOCTL_MAGIC, 40, char [MAX_VERSION_LENGTH])
 *
 * 의미:
 * - 사용자 공간으로 문자열(char[MAX_VERSION_LENGTH])을 읽어오는 ioctl 명령
 * - 드라이버는 내부적으로 보유한 버전 문자열을 해당 버퍼에 복사하여 반환
 * ----------------------------
 *
 * @param version 드라이버 버전 문자열을 저장할 버퍼 포인터
 *                버퍼 크기는 최소 MAX_VERSION_LENGTH 이상이어야 함
 *
 * @return 성공 시 0, 실패 시 -1
 *
 * ⚠️ 본 함수 및 관련 인터페이스는 내부 시스템 전용이며, 외부 문서화 또는 공개 금지
 */
int sdk_get_NdaNfkDrv_version (char * version);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK that activates the operating mode
 */
/**
 * @brief 드라이버의 동작 모드를 활성화합니다.
 *
 * 이 함수는 사용자 공간에서 커널 드라이버와 통신하여,
 * 드라이버 내부의 동작 모드를 '활성화(ON)' 상태로 전환합니다.
 *
 * - 디바이스 파일: /dev/nd_nix_chardev
 * - IOCTL 명령: IOCTL_ON_MODE
 *
 * ----------------------------
 * IOCTL 정의:
 * #define IOCTL_ON_MODE _IO(ND_IOCTL_MAGIC, 30)
 *
 * 의미:
 * - 사용자 데이터 없이 실행되는 제어 명령
 * - 드라이버 내부 상태를 ENABLE 상태로 전환시키기 위한 트리거 역할
 * ----------------------------
 *
 * @return 성공 시 0, 실패 시 -1
 *
 * ⚠️ 본 함수는 시스템 내부 제어 목적으로만 사용되며,
 * ⚠️ 외부 문서화, 코드 공개, API 연동은 허용되지 않습니다.
 */
int sdk_NdaNfkDrv_start (void);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK that changes the operating mode to cleanup
 */
/**
 * @brief 드라이버의 동작 모드를 비활성화(OFF)합니다.
 *
 * 이 함수는 사용자 공간에서 커널 드라이버와 통신하여,
 * 현재 활성화된 드라이버 기능을 중지시키기 위한 제어 명령을 전달합니다.
 *
 * - 디바이스 파일: /dev/nd_nix_chardev
 * - IOCTL 명령: IOCTL_OFF_MODE
 *
 * ----------------------------
 * IOCTL 정의:
 * #define IOCTL_OFF_MODE _IO(ND_IOCTL_MAGIC, 31)
 *
 * 의미:
 * - 사용자 데이터 없이 커널에 명령 전달
 * - 드라이버 내부 플래그나 상태를 OFF로 변경
 * - 관련 기능 동작 정지 및 정책 초기화 가능성 있음
 * ----------------------------
 *
 * @return 성공 시 0, 실패 시 -1
 */
int sdk_NdaNfkDrv_stop (void);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK to obtain current operating mode information
 */
/**
 * @brief 드라이버의 현재 동작 상태(ON/OFF)를 조회합니다.
 *
 * 이 함수는 사용자 영역에서 커널 드라이버로 IOCTL 요청을 보내,
 * 드라이버가 현재 활성화되어 있는지(ON) 또는 비활성화 상태인지(OFF)를 확인합니다.
 *
 * - 디바이스 경로: /dev/nd_nix_chardev
 * - IOCTL 명령: IOCTL_GET_MODE
 *
 * ----------------------------
 * IOCTL 정의:
 * #define IOCTL_GET_MODE _IOR(ND_IOCTL_MAGIC, 32, char [MAX_STRING_LENGTH])
 *
 * 의미:
 * - 사용자 공간으로 드라이버 상태 문자열을 읽어오는 명령
 * - 드라이버는 내부 상태(예: "on", "off")를 문자열 형태로 전달
 * - 반환값은 sStatus 버퍼에 저장되며, 이후 비교를 통해 상태 판단 가능
 * ----------------------------
 *
 * @param sStatus 드라이버 상태 문자열을 저장할 버퍼
 *                버퍼 크기는 최소 MAX_STRING_LENGTH 이상이어야 함
 *
 * @return 성공 시 0, 실패 시 -1
 */
int sdk_get_NdaNfkDrv_state (char * sStatus );

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK for adding service policies to the driver
 */
/**
 * @brief 커널 드라이버에 서비스 정책을 추가합니다.
 *
 * 본 함수는 사용자 공간에서 `cmd_service_rule_pars_data` 구조체를 이용해
 * 커널 드라이버에 하나의 서비스 정책을 등록합니다. 등록된 정책은
 * 드라이버 내부에서 서비스 식별자와 연결된 제어 규칙으로 저장되며,
 * 향후 패킷 필터링 또는 세션 제어에 사용될 수 있습니다.
 *
 * - 디바이스 경로: /dev/nd_nix_chardev
 * - IOCTL 명령: IOCTL_ADD_SERVICE_POLICY
 *
 * ----------------------------
 * IOCTL 정의:
 * #define IOCTL_ADD_SERVICE_POLICY _IOWR(ND_IOCTL_MAGIC, 1, struct cmd_service_rule_pars_data)
 *
 * 구조체 정의:
 * struct cmd_service_rule_pars_data {
 *     __u16 service;   // 서비스 식별자
 *     __u16 forward;   // forward 여부 (0: block, 1: allow 등)
 *     __u32 data;      // 추가 서비스 관련 데이터 (context-dependent)
 *     __u32 ret;       // 커널 처리 후 결과 코드 또는 정책 ID 등
 * };
 *
 * 설명:
 * - 호출자는 `service`, `forward`, `data` 필드를 설정하여 전달
 * - 드라이버는 내부 정책 등록 후 `ret` 필드에 처리 결과를 채워서 반환
 * - 정책 추가 실패 시 `ret` 값으로 구체적인 실패 사유 전달 가능
 * ----------------------------
 *
 * @param service 정책 내용을 담은 구조체 포인터
 *                모든 필드가 사전에 올바르게 세팅되어야 함
 *
 * @return 성공 시 0, 실패 시 -1
 *
 * ⚠️ 내부 보안 구성 요소와 연계되므로, 본 함수 및 구조체에 대한 외부 노출 금지
 */
int sdk_add_NdaNfkDrv_service_policy(const struct cmd_service_rule_pars_data * service);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK for adding action service policies to the driver
 * [add 2024-10-10]
 */
/**
 * @brief 드라이버에 서비스 하위 액션 정책을 등록합니다.
 *
 * 전달된 `cmd_service_sub_rule_pars_data` 구조체를 사용하여,
 * 드라이버 내부의 특정 서비스 정책에 대응하는 액션 룰을 등록합니다.
 *
 * 구조체 형식: struct cmd_service_sub_rule_pars_data
 * 사용 IOCTL: IOCTL_ADD_ACTION_POLICY
 *
 * ----------------------------
 * #define IOCTL_ADD_ACTION_POLICY \
 *     _IOWR(ND_IOCTL_MAGIC, 2, struct cmd_service_sub_rule_pars_data)
 *
 * struct cmd_service_sub_rule_pars_data {
 *     __u16 service;   // 대상 서비스 ID
 *     __u32 type;      // 액션 타입 (허용, 차단 등)
 *     __u32 saddr;     // 시작 IP 주소
 *     __u32 s_range;   // 시작 IP 범위
 *     __u32 eaddr;     // 종료 IP 주소
 *     __u32 ret;       // 처리 결과 또는 내부 상태값
 * };
 * ----------------------------
 *
 * @param action 하위 정책 정보를 담은 구조체 포인터
 * @return       0: 성공 / -1: 실패
 */
int sdk_add_NdaNfkDrv_action_policy(const struct cmd_service_sub_rule_pars_data * action);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK for modifying service policies in the driver
 */
/**
 * @brief 기존 서비스 정책 항목을 인덱스를 기준으로 수정합니다.
 *
 * 본 함수는 사용자 영역에서 `cmd_service_rule_pars_data` 구조체를 이용해
 * 이미 등록된 서비스 정책 중 특정 인덱스에 해당하는 항목의 값을 수정합니다.
 *
 * 수정 대상은 구조체 내 식별 필드(`service` 등)를 기반으로 드라이버에서 탐색되며,
 * 기존 정책의 일부 속성(`forward`, `data` 등)을 업데이트하는 방식입니다.
 *
 * 구조체 형식: struct cmd_service_rule_pars_data
 * 사용 IOCTL: IOCTL_MOD_SERVICE_POLICY
 *
 * ----------------------------
 * #define IOCTL_MOD_SERVICE_POLICY \
 *     _IOWR(ND_IOCTL_MAGIC, 4, struct cmd_service_rule_pars_data)
 *
 * struct cmd_service_rule_pars_data {
 *     __u16 service;   // 정책 대상 서비스 ID
 *     __u16 forward;   // 수정될 정책 방향
 *     __u32 data;      // 부가 데이터 (옵션)
 *     __u32 ret;       // 결과 코드 또는 수정 처리 결과
 * };
 * ----------------------------
 *
 * @param service 수정할 정책 정보를 담고 있는 구조체 포인터
 * @return        0: 성공 / -1: 실패
 */
int sdk_mod_NdaNfkDrv_service_policy_to_index(const struct cmd_service_rule_pars_data * service);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK for modifying action service policies in the driver
 * [add 2024-10-10]
 */
/**
 * @brief 기존 하위 액션 정책을 인덱스를 기준으로 수정합니다.
 *
 * 이 함수는 `cmd_service_sub_rule_pars_data` 구조체를 기반으로,
 * 드라이버에 등록된 특정 하위 액션 정책을 수정합니다. 수정 대상은
 * 구조체 내 식별 필드(예: service, saddr 등)를 기준으로 매칭됩니다.
 *
 * 구조체 형식: struct cmd_service_sub_rule_pars_data
 * 사용 IOCTL: IOCTL_MOD_ACTION_POLICY
 *
 * ----------------------------
 * #define IOCTL_MOD_ACTION_POLICY \
 *     _IOWR(ND_IOCTL_MAGIC, 5, struct cmd_service_sub_rule_pars_data)
 *
 * struct cmd_service_sub_rule_pars_data {
 *     __u16 service;   // 정책 소속 서비스 ID
 *     __u32 type;      // 정책 타입 (허용, 차단 등)
 *     __u32 saddr;     // 시작 IP 주소
 *     __u32 s_range;   // 시작 범위 (서브넷 등)
 *     __u32 eaddr;     // 종료 IP 주소
 *     __u32 ret;       // 커널 처리 결과 또는 상태
 * };
 * ----------------------------
 *
 * @param action 수정할 액션 정책 데이터 포인터
 * @return       0: 성공 / -1: 실패
 */
int sdk_mod_NdaNfkDrv_action_policy_to_index(const struct cmd_service_sub_rule_pars_data * action);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK to delete service policy from driver
 */
#ifdef _SERVICE_STRUCT_TYPE
/**
 * @brief 등록된 서비스 정책 항목을 삭제합니다.
 *
 * 이 함수는 사용자 공간에서 `cmd_service_rule_pars_data` 구조체를 기반으로,
 * 드라이버에 등록된 서비스 정책을 식별하여 제거합니다.
 *
 * 구조체의 `service` 필드를 기준으로 정책이 검색되며,
 * 해당 항목이 존재하는 경우 커널 내부에서 삭제 처리됩니다.
 *
 * 구조체 형식: struct cmd_service_rule_pars_data
 * 사용 IOCTL: IOCTL_DEL_SERVICE_POLICY
 *
 * ----------------------------
 * #define IOCTL_DEL_SERVICE_POLICY \
 *     _IOWR(ND_IOCTL_MAGIC, 8, char [MAX_SERVICE_LENGTH])
 *
 * struct cmd_service_rule_pars_data {
 *     __u16 service;   // 삭제 대상 서비스 ID
 *     __u16 forward;
 *     __u32 data;
 *     __u32 ret;
 * };
 * ----------------------------
 *
 * @param service 삭제할 정책의 서비스 정보를 담고 있는 구조체 포인터
 *                최소한 `service` 필드는 유효하게 설정되어야 함
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_del_NdaNfkDrv_service_policy(const struct cmd_service_rule_pars_data * service );

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */
#else

/**
 * @brief 등록된 서비스 정책을 서비스 이름으로 삭제합니다.
 *
 * 해당 함수는 사용자 공간에서 문자열 형태의 서비스 식별자(`char *`)를 전달하여,
 * 커널 드라이버에 등록된 해당 서비스 정책을 제거합니다.
 *
 * 구조체가 아닌 서비스명 문자열을 직접 IOCTL에 전달하며, 커널 내부에서
 * 해당 문자열을 기반으로 정책 검색 및 삭제가 이루어집니다.
 *
 * 사용 IOCTL: IOCTL_DEL_SERVICE_POLICY
 *
 * ----------------------------
 * #define IOCTL_DEL_SERVICE_POLICY \
 *     _IOWR(ND_IOCTL_MAGIC, 8, char [MAX_SERVICE_LENGTH])
 *
 * 의미:
 * - 사용자로부터 `char[MAX_SERVICE_LENGTH]` 크기의 서비스명 문자열을 전달받음
 * - 내부적으로 문자열 비교 기반 정책 삭제
 * ----------------------------
 *
 * @param service 삭제 대상 서비스명 문자열 (NULL 불가)
 * @return        0: 성공 / -1: 실패
 */
int sdk_del_NdaNfkDrv_service_policy(const char * service );
#endif //_SERVICE_STRUCT_TYPE

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK for deleting action service policies from the driver
 * [add 2024-10-10]
 */
/**
 * @brief 등록된 하위 액션 정책을 삭제합니다.
 *
 * 전달된 `cmd_service_sub_rule_pars_data` 구조체를 기반으로,
 * 커널 드라이버에 등록되어 있는 특정 액션 정책을 찾아 삭제합니다.
 *
 * 정책 삭제는 구조체 내 주요 필드(`service`, `type`, `saddr`, `eaddr` 등)를
 * 기준으로 수행되며, 동일 조건을 만족하는 항목이 있을 경우 제거됩니다.
 *
 * 구조체 형식: struct cmd_service_sub_rule_pars_data
 * 사용 IOCTL: IOCTL_DEL_ACTION_POLICY
 *
 * ----------------------------
 * #define IOCTL_DEL_ACTION_POLICY \
 *     _IOWR(ND_IOCTL_MAGIC, 9, struct cmd_service_sub_rule_pars_data)
 *
 * struct cmd_service_sub_rule_pars_data {
 *     __u16 service;   // 정책 소속 서비스 ID
 *     __u32 type;      // 액션 정책 타입
 *     __u32 saddr;     // 시작 IP 주소
 *     __u32 s_range;   // 서브넷 범위 또는 포트 범위
 *     __u32 eaddr;     // 종료 IP 주소
 *     __u32 ret;       // 삭제 처리 결과 또는 내부 상태 코드
 * };
 * ----------------------------
 *
 * @param action 삭제할 하위 액션 정책 데이터 포인터 (NULL 불가)
 * @return       0: 성공 / -1: 실패
 */
int sdk_del_NdaNfkDrv_action_policy(const struct cmd_service_sub_rule_pars_data * action );

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * sdk to delete all policies from driver
 */
/**
 * @brief 커널 드라이버에 등록된 모든 정책을 초기화합니다.
 *
 * 본 함수는 사용자 공간에서 드라이버에 IOCTL 요청을 전달하여,
 * 서비스, 액션, 드롭예외 등 모든 등록된 정책 항목을 삭제하고
 * 초기 상태로 리셋합니다.
 *
 * 정책 초기화는 전체 설정을 제거하는 위험 작업이므로,
 * 이 함수는 내부 제어 목적 또는 명시적인 재구성 시에만 호출되어야 합니다.
 *
 * 사용 IOCTL: IOCTL_RESET_POLICY
 *
 * ----------------------------
 * #define IOCTL_RESET_POLICY \
 *     _IO(ND_IOCTL_MAGIC, 12)
 *
 * 의미:
 * - 사용자로부터 별도의 데이터 전달 없이 커널에 명령만 전달
 * - 커널 내부에서 정책 테이블/리스트 전체 초기화 수행
 * ----------------------------
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_reset_NdaNfkDrv_policy (void);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */


/*
 * SDK for retrieving service policies from the driver
 * [add 2024-10-10]
 */
/**
 * @brief 주어진 서비스 정책 조건에 해당하는 인덱스를 조회합니다.
 *
 * 구조체에 포함된 필드(`service` 등)를 기준으로 커널 드라이버에서
 * 등록된 정책을 검색하고, 해당 정책의 인덱스를 구조체 내 `ret` 필드에 반환합니다.
 *
 * IOCTL 호출 후 별도로 `ret` 필드를 해석하여 인덱스 값을 얻어야 합니다.
 *
 * 사용 IOCTL: IOCTL_GET_SERVICE_POLICY_INDEX
 *
 * ----------------------------
 * #define IOCTL_GET_SERVICE_POLICY_INDEX \
 *     _IOR(ND_IOCTL_MAGIC, 14, char [MAX_STRING_LENGTH])
 *
 * (※ 구조체 기반 전달이지만, IOCTL 정의는 문자열 기반인 것으로 추정됨.
 *     실제 커널 구현에 따라 `cmd_service_rule_pars_data` 사용 가능)
 *
 * struct cmd_service_rule_pars_data {
 *     __u16 service;
 *     __u16 forward;
 *     __u32 data;
 *     __u32 ret;   // 커널이 반환한 인덱스
 * };
 * ----------------------------
 *
 * @param service 정책 조건을 담은 구조체 포인터
 *                IOCTL 호출 후 service->ret 에 인덱스가 설정됨
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_get_NdaNfkDrv_service_policy_index(struct cmd_service_rule_pars_data * service);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK for retrieving action service policies from the driver
 */
/**
 * @brief 하위 액션 정책의 인덱스를 조회합니다.
 *
 * 주어진 조건(`cmd_service_sub_rule_pars_data` 구조체)에 부합하는
 * 등록된 액션 정책을 검색하고, 해당 항목의 인덱스를 반환받습니다.
 *
 * IOCTL 호출 결과는 구조체 내 `ret` 필드에 설정되어 돌아오며,
 * 실제 반환값은 이 `ret` 값을 기준으로 합니다.
 *
 * 사용 IOCTL: IOCTL_GET_ACTION_POLICY
 *
 * ----------------------------
 * #define IOCTL_GET_ACTION_POLICY \
 *     _IOWR(ND_IOCTL_MAGIC, 15, struct cmd_service_sub_rule_pars_data)
 *
 * 구조체:
 * struct cmd_service_sub_rule_pars_data {
 *     __u16 service;
 *     __u32 type;
 *     __u32 saddr;
 *     __u32 s_range;
 *     __u32 eaddr;
 *     __u32 ret;   // 커널이 반환한 인덱스 값 또는 상태 코드
 * };
 * ----------------------------
 *
 * @param action 정책 조건 정보가 담긴 구조체 포인터
 *               호출 후 action->ret 에 인덱스 값이 저장됨
 *
 * @return 인덱스 (0 이상) 또는 음수 값 (에러 코드)
 */
int sdk_get_NdaNfkDrv_action_policy_index(const struct cmd_service_sub_rule_pars_data * action );

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK that retrieves all service policy from driver
 */
/**
 * @brief 커널 드라이버에 등록된 전체 정책 정보를 조회합니다.
 *
 * 이 함수는 IOCTL 명령을 통해 커널 드라이버로부터 정책 정보를 문자열 형태로 전달받습니다.
 * 반환된 데이터는 `char` 배열 형태의 버퍼에 저장되며, 포맷은 내부 정의에 따릅니다.
 * 일반적으로 JSON, CSV, 또는 내부 전용 포맷 문자열로 구성될 수 있습니다.
 *
 * 사용 IOCTL: IOCTL_GET_POLICY
 *
 * ----------------------------
 * #define IOCTL_GET_POLICY \
 *     _IOR(ND_IOCTL_MAGIC, 13, char [MAX_STRING_LENGTH])
 *
 * 의미:
 * - 사용자 공간 버퍼로 드라이버의 정책 상태를 문자열 형태로 전달
 * - 정책의 전체 요약 또는 나열 정보 포함 가능
 * ----------------------------
 *
 * @param data 정책 정보를 수신할 사용자 공간 버퍼 포인터
 *             최소 MAX_STRING_LENGTH 크기를 보장해야 함
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_get_NdaNfkDrv_policy (char * data);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK that retrieves service policy from driver
 */
/**
 * @brief 등록된 서비스 정책 정보를 문자열 형식으로 조회합니다.
 *
 * 이 함수는 사용자 공간에서 커널 드라이버에 IOCTL 요청을 전달하여,
 * 현재 등록되어 있는 서비스 정책 목록을 문자열로 받아옵니다.
 *
 * 반환된 문자열은 호출자가 전달한 `data` 버퍼에 저장되며,
 * 버퍼의 크기는 최소 `MAX_STRING_LENGTH` 이상이어야 합니다.
 *
 * 사용 IOCTL: IOCTL_GET_SERVICE_POLICY
 *
 * ----------------------------
 * #define IOCTL_GET_SERVICE_POLICY \
 *     _IOR(ND_IOCTL_MAGIC, 17, char [MAX_STRING_LENGTH])
 *
 * 의미:
 * - 커널 → 사용자 방향으로 서비스 정책 전체 정보를 문자열로 전달
 * - 문자열 포맷은 내부 전용 형식 (예: JSON, key-value, CSV 등)
 * ----------------------------
 *
 * @param data 정책 정보를 저장할 버퍼 포인터 (NULL 불가)
 *             호출 후 정책 정보 문자열이 이 버퍼에 기록됨
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_get_NdaNfkDrv_service_policy (char *data);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 * SDK for retrieving stored logs from the driver
 */

/**
 * @brief 커널 드라이버의 로그 데이터를 문자열 형식으로 조회합니다.
 *
 * 이 함수는 사용자 공간에서 커널 드라이버로 IOCTL 요청을 보내,
 * 드라이버 내부에 저장된 로그 메시지를 문자열로 받아옵니다.
 *
 * 로그 내용은 `char` 버퍼에 저장되며, 드라이버 내부에서 정의된
 * 순서와 포맷(예: 시간, 레벨, 메시지 형식)에 따라 구성됩니다.
 *
 * 사용 IOCTL: IOCTL_GET_LOG
 *
 * ----------------------------
 * #define IOCTL_GET_LOG \
 *     _IOR(ND_IOCTL_MAGIC, 41, char *)
 *
 * 의미:
 * - 커널 → 사용자 방향으로 로그 버퍼 전달
 * - 포인터 기반으로 문자열 로그 목록을 전달받음
 * - 출력 버퍼는 MAX_BUFFER_SIZE 이상이어야 함
 * ----------------------------
 *
 * @param data 로그 내용을 저장할 사용자 공간 버퍼 (NULL 불가)
 *             최소 크기: MAX_BUFFER_SIZE
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_get_NdaNfkDrv_logs(char *data);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 *
 */
/**
 * @brief 드라이버의 로그 출력 설정을 적용합니다.
 *
 * 이 함수는 지정된 로그 레벨을 기준으로 내부 로그 설정 구조체를 구성하여,
 * IOCTL 명령을 통해 커널 드라이버에 전달합니다.
 *
 * 레벨별로 개별 로그 항목을 선택적으로 활성화하며,
 * 예를 들어 `LOG_LEVEL_ERR`이면 warning 및 error 로그가 출력되도록 설정합니다.
 *
 * 사용 IOCTL: IOCTL_SET_LOG_SETTINGS
 *
 * ----------------------------
 * #define IOCTL_SET_LOG_SETTINGS \
 *     _IOW(ND_IOCTL_MAGIC, 42, struct st_log_config)
 *
 * struct st_log_config {
 *     bool debug_log_enabled;
 *     bool warn_log_enabled;
 *     bool error_log_enabled;
 *     bool trace_log_enabled;
 *     bool info_log_enabled;
 * };
 *
 * enum log_level_index {
 *     LOG_LEVEL_NONE  = 0,
 *     LOG_LEVEL_WARN,
 *     LOG_LEVEL_ERR,
 *     LOG_LEVEL_INFO,
 *     LOG_LEVEL_DEBUG,
 *     LOG_LEVEL_TRACE,
 *     LOG_LEVEL_MAX
 * };
 * ----------------------------
 *
 * @param nLogLevel 설정할 로그 출력 레벨 (0 ~ LOG_LEVEL_MAX - 1)
 * @return          0: 성공 / -1: 실패
 */
int sdk_set_NdaNfkDrv_log_setting(int nLogLevel);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 *
 */

/**
 * @brief 커널 드라이버의 현재 로그 출력 설정을 조회합니다.
 *
 * 이 함수는 IOCTL 요청을 통해 커널 드라이버로부터 현재 설정된 로그 출력
 * 상태를 구조체 형식(`st_log_config`)으로 전달받습니다.
 *
 * 커널은 각 로그 항목별 설정 상태를 구조체 필드에 기록하여,
 * 어떤 로그 수준이 활성화되어 있는지 사용자 공간에 알려줍니다.
 *
 * 사용 IOCTL: IOCTL_GET_LOG_SETTINGS
 *
 * ----------------------------
 * #define IOCTL_GET_LOG_SETTINGS \
 *     _IOR(ND_IOCTL_MAGIC, 43, struct st_log_config)
 *
 * struct st_log_config {
 *     bool debug_log_enabled;
 *     bool warn_log_enabled;
 *     bool error_log_enabled;
 *     bool trace_log_enabled;
 *     bool info_log_enabled;
 * };
 * ----------------------------
 *
 * @param pconfig 드라이버의 로그 설정을 저장할 구조체 포인터
 *                호출 전에 zero-initialized 되어야 함
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_get_NdaNfkDrv_log_setting(struct st_log_config * pconfig);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 *
 */
/**
 * @brief NIC 주소 기반 제어 정책을 드라이버에 등록합니다.
 *
 * 해당 함수는 지정된 NIC 주소 정보를 커널 드라이버에 전달하여,
 * 해당 NIC(IP 주소)에 대한 트래픽 제어 정책을 추가합니다.
 *
 * 이 기능은 특정 NIC에서 유입되는 패킷을 제어하거나 필터링하기 위한
 * 보안 정책 또는 허용 정책의 일부로 사용됩니다.
 *
 * 사용 IOCTL: IOCTL_ADD_NIC_RULE
 *
 * ----------------------------
 * #define IOCTL_ADD_NIC_RULE \
 *     _IOW(ND_IOCTL_MAGIC, 45, struct cmd_nic_rule_pars_data)
 *
 * struct cmd_nic_rule_pars_data {
 * #ifdef _OLD_SRC
 *     char name[IFNAMSIZ];          // (구버전 인터페이스명, 현재는 미사용)
 *     unsigned char mac_addr[6];    // (구버전 MAC 주소 필드)
 * #endif
 *     __u32 address;                // NIC의 IPv4 주소 (host byte order)
 * };
 * ----------------------------
 *
 * @param pNicData NIC 주소 정보를 담은 구조체 포인터 (NULL 불가)
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_add_NdaNfkDrv_nic_rule (struct cmd_nic_rule_pars_data * pNicData);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 *
 */

/**
 * @brief 드라이버에 등록된 NIC 제어 정책을 삭제합니다.
 *
 * 이 함수는 `cmd_nic_rule_pars_data` 구조체를 이용하여,
 * 특정 NIC(IP 주소)에 해당하는 제어 정책을 삭제합니다.
 *
 * 커널 드라이버는 전달받은 IP 주소를 기반으로 기존 정책과 매칭하여
 * 일치하는 항목이 있을 경우 해당 정책을 제거합니다.
 *
 * 사용 IOCTL: IOCTL_DEL_NIC_RULE
 *
 * ----------------------------
 * #define IOCTL_DEL_NIC_RULE \
 *     _IOW(ND_IOCTL_MAGIC, 46, struct cmd_nic_rule_pars_data)
 *
 * struct cmd_nic_rule_pars_data {
 * #ifdef _OLD_SRC
 *     char name[IFNAMSIZ];
 *     unsigned char mac_addr[6];
 * #endif
 *     __u32 address;  // 삭제 대상 NIC의 IPv4 주소
 * };
 * ----------------------------
 *
 * @param pNicData 삭제 대상 NIC 정보를 담은 구조체 포인터
 * @return         0: 성공 / -1: 실패
 */
int sdk_del_NdaNfkDrv_nic_rule (struct cmd_nic_rule_pars_data * pNicData);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */


/*
 *
 */
/**
 * @brief 드라이버에 등록된 모든 NIC 제어 정책을 초기화합니다.
 *
 * 본 함수는 커널 드라이버로 IOCTL 요청을 보내 NIC 관련 제어 정책을 모두 삭제하고,
 * 초기 상태로 재설정합니다. 즉, 등록된 모든 NIC 필터 규칙이 제거됩니다.
 *
 * 이 명령은 전체 NIC 정책을 삭제하는 고위험 작업으로,
 * 정책 재구성 또는 보안 초기화 시에만 사용되어야 합니다.
 *
 * 사용 IOCTL: IOCTL_RESET_NIC_RULE
 *
 * ----------------------------
 * #define IOCTL_RESET_NIC_RULE \
 *     _IO(ND_IOCTL_MAGIC, 47)
 *
 * 의미:
 * - 사용자 → 커널 방향의 단순 제어 명령 (데이터 전달 없음)
 * - 내부 NIC 정책 테이블 초기화 수행
 * ----------------------------
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_reset_NdaNfkDrv_nic_rule (void);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 *
 */

/**
 * @brief 드라이버에 IP 우회 정책을 추가합니다.
 *
 * 해당 함수는 `cmd_bypass_rule_pars_data` 구조체를 통해 지정된 IP 범위에 대해
 * 드라이버가 필터링 또는 제어를 우회(bypass)하도록 설정하는 정책을 등록합니다.
 *
 * 등록된 우회 규칙은 해당 IP 대역의 트래픽을 필터링 로직에서 제외시키는 데 사용됩니다.
 *
 * 사용 IOCTL: IOCTL_ADD_BYPASS_RULE
 *
 * ----------------------------
 * #define IOCTL_ADD_BYPASS_RULE \
 *     _IOW(ND_IOCTL_MAGIC, 50, struct cmd_bypass_rule_pars_data)
 *
 * struct cmd_bypass_rule_pars_data {
 *     __u32 saddr;  // 시작 IP 주소
 *     __u32 eaddr;  // 종료 IP 주소
 * };
 * ----------------------------
 *
 * @param pBypassData 우회할 IP 범위 정보를 담고 있는 구조체 포인터
 * @return            0: 성공 / -1: 실패
 */
int sdk_add_NdaNfkDrv_bypass_rule (struct cmd_bypass_rule_pars_data* pBypassData);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */

/*
 *
 */
/**
 * @brief 드라이버에 등록된 특정 IP 우회 정책을 제거합니다.
 *
 * 해당 함수는 `cmd_bypass_rule_pars_data` 구조체로 지정된 IP 범위를 기준으로,
 * 커널 드라이버에 등록된 우회 정책 중 일치하는 항목을 찾아 삭제합니다.
 *
 * 지정된 범위는 시작 주소(saddr)와 종료 주소(eaddr)를 기준으로 평가되며,
 * 정확히 일치하는 정책이 존재할 경우에만 삭제가 수행됩니다.
 *
 * 사용 IOCTL: IOCTL_DEL_BYPASS_RULE
 *
 * ----------------------------
 * #define IOCTL_DEL_BYPASS_RULE \
 *     _IOW(ND_IOCTL_MAGIC, 51, struct cmd_bypass_rule_pars_data)
 *
 * struct cmd_bypass_rule_pars_data {
 *     __u32 saddr;  // 시작 IP 주소
 *     __u32 eaddr;  // 종료 IP 주소
 * };
 * ----------------------------
 *
 * @param pBypassData 삭제 대상 IP 범위를 담은 구조체 포인터
 * @return            0: 성공 / -1: 실패
 */
int sdk_del_NdaNfkDrv_bypass_rule (struct cmd_bypass_rule_pars_data * pBypassData);

/*
 * -------------------------------------------------------------------------------------------------------------------------
 */


/*
 *
 */
/**
 * @brief 드라이버에 등록된 모든 우회(bypass) 정책을 초기화합니다.
 *
 * 이 함수는 커널 드라이버에 IOCTL 명령을 전달하여,
 * 현재 등록된 모든 bypass 정책(IP 범위 기반 예외 처리 목록)을 제거합니다.
 *
 * 시스템 재설정, 정책 재구성, 보안 재시작 등의 상황에서 전체 우회 정책을
 * 빠르게 초기화하기 위해 사용됩니다.
 *
 * 사용 IOCTL: IOCTL_RESET_PYPASS_RULE
 *
 * ----------------------------
 * #define IOCTL_RESET_PYPASS_RULE \
 *     _IO(ND_IOCTL_MAGIC, 52)
 *
 * 의미:
 * - 사용자 → 커널로 단순 제어 명령 전달 (데이터 없음)
 * - 커널 내부에서 우회 정책 테이블 초기화
 * ----------------------------
 *
 * @return 0: 성공 / -1: 실패
 */
int sdk_reset_NdaNfkDrv_bypass_rule (void );

#endif
