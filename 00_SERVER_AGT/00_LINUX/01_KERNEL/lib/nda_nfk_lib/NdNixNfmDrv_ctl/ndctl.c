#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "nda_nfk_lib.h"

#define MODULE_NAME "nda_nfk"


/*
	//IP CHANGE : INT -> STRING
*/
void int_to_ip_string(unsigned int ip_num, char *ip_str) {
	struct in_addr addr;
    	addr.s_addr = htonl(ip_num);
    	inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN); 
}

/*
	//IP CHANGE : STRING -> INT
*/
unsigned int ip_string_to_int(const char *ip_str) {
    	struct in_addr addr;
    	if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        	fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
        	return 0; 
    	}
   	// return ntohl(addr.s_addr); 
	return addr.s_addr;
}


/*
	//
*/
int is_module_loaded(const char *module_name) {
	FILE *fp;
	char line[256];

	fp = fopen("/proc/modules", "r");
	if (fp == NULL) {
        	perror("Failed to open /proc/modules");
        	return -1; 
    	}

    	while (fgets(line, sizeof(line), fp)) {
        	if (strstr(line, module_name) != NULL) {
            		fclose(fp);
            		return 1; 
        	}
    	}

    	fclose(fp);
    	return 0;
}

/*
	//
*/
void output_message(char ** argv)
{
	printf ("usage:  %s rule add service <parameter...>\t:Adding a service policy.\n \
	./ndctl rule del service <parameter...>\t:Deleting a service policy.\n \
	./ndctl rule reset\t:Resetting the service policy.\n \
	./ndctl rule add action <parameter...>\t:Adding the action rules of the service policy.\n \
	./ndctl rule del action <parameter...>\t:Deleting the action rules of the service policy.\n \
	./ndctl rule add nic <parameter...>\t:Adding the NIC policy.\n \
	./ndctl rule del nic <parameter...>\t:Deleting the NIC policy.\n \
	./ndctl rule add bypass <parameter...>\t:Adding the Bypass policy.\n \
	./ndctl rule del bypass <parameter...>\t:Deleting the Bypass Policy.\n \
	./ndctl mode get\t:Querying the operating mode.\n \
	./ndctl mode on or off\t:Turning the operating mode ON or OFF.\n \
	./ndctl logs\t:Retrieving the saved logs.\n \
	./ndctl logs set <parameter...>\t:Setting the log collection policy.\n \t\t# ./ndctl logs set 1 >> [WARN] \n\t\t# ./ndctl logs set 2 >> [WARN + ERROR] \n\t\t# ./ndctl logs set 3 >> [WARN + ERROR + INFO] \n\t\t# ./ndctl logs set 4 >> [WARN + ERROR + INFO + DEBUG]  \n\t\t# ./ndctl logs set 5 >> [WARN + ERROR + INFO + DEBUG + TRACE]\n \
	./ndctl logs get\t:Querying the log collection policy.\n \
	\n\n", argv[0]);
}

/*
	//
*/
int main(int argc, char** argv)	{

	char szVersion[16] = {0,};
	char log_buffer[MAX_BUFFER_SIZE];
	int ndata = 0;
	
	/*
		// log config struct
		struct st_log_config {
			bool debug_log_enabled;
			bool warn_log_enabled;
			bool error_log_enabled;
			bool trace_log_enabled;
			bool info_log_enabled;
		};

		* debug_log_enabled : debug log setting config
		* warn_log_enabled  : warr  log setting config
		* error_log_enabled : error log setting config
		* trace_log_enabled : trace log setting config
		* info_log_enabled  : info log setting config

	*/
	struct st_log_config log_config;

	/*
		//service 정책 추가를 위한 구조체 정보 
		struct cmd_service_rule_pars_data
		{
        		__u16 service;
        		__u16 forward;
        		__u32 data;
        		__u32 ret;
		};

		* service : monitoring target database lintern port
		* forward : dac lintern port
		* data : fix "1"
		* ret  : response return data
	*/
	struct cmd_service_rule_pars_data policy[5] = {{3306, 10000, 1},{7001, 7002, 1},{1430, 1431, 1},{1440, 1441, 1},{1450, 1451, 1}} ;

	/*
		// nic 정책 추가를 위한 구조체 정보 
		struct cmd_nic_rule_pars_data
		{
		#ifdef _OLD_SRC
			char name[IFNAMSIZ];
			unsigned char mac_addr[6];
		#endif //_OLD_SRC
			__u32 address; 
		};

		<NOT USE..>
		* name 		: nic device name (ex : eth0, eth1..)
		* mac_addr 	: nic Mac address (ex : 00:15:5d:07:64:14 )

		* address 	: Expressed as a 32-bit number ipaddress (ex :3232235777 (192.168.1.1))

	*/
	struct cmd_nic_rule_pars_data nicrule = {.address = ip_string_to_int("172.31.103.87")};

	/*
		// gateway .. exception
		struct cmd_bypass_rule_pars_data
		{
       	 		__u32 saddr;
        		__u32 eaddr;
		};

		* saddr :	start source ipaddress
		* eaddr :	end source ipaddress
		
		** gateway 이나 hiware 등 접근 시 정책이 부여되는 접근이지만 정책적용을 제외 해야 하는 경우
	*/
	struct cmd_bypass_rule_pars_data bypass_rule[3];
	

	/*
		// kernel 과 구조체를 이용한 정책 통신을 진행하기위한 가장 기본적인 구조체임
		// IOCTL 통신 시 kernel에게 데이터를 전달하고 결과를 회신받는 용도로 사용
		struct cmd_service_sub_rule_pars_data
		{
			__u16 service;
			__u32 type;
			__u32 saddr;
			__u32 s_range;
			__u32 eaddr;
			__u32 ret;
		};

	*/
	struct cmd_service_sub_rule_pars_data subpolecyitm[3];
	
	/*
		// kernel에게 action 정책(소스아이피 기반 동작)을 추가하기위한 데이터 준비
	*/
	subpolecyitm[0] = (struct cmd_service_sub_rule_pars_data) {

		.service = 3306,
		.type = 0,
		.saddr = ip_string_to_int("172.21.16.1"),
		.s_range = 0,
		.eaddr = ip_string_to_int("172.21.16.1")
	};

	subpolecyitm[1] = (struct cmd_service_sub_rule_pars_data) {

                .service = 7001,
                .type = 0,
                .saddr = ip_string_to_int("192.168.15.193"),
                .s_range = 0,
                .eaddr = ip_string_to_int("192.168.15.193")
        };

	subpolecyitm[2] = (struct cmd_service_sub_rule_pars_data){

                .service = 7001,
                .type = 0,
                .saddr = ip_string_to_int("192.168.3.120"),
                .s_range = 0,
                .eaddr = ip_string_to_int("192.168.3.120")
        };

	/*
		//bypass 정책을 3개 추가하기위한 데이터 준비
	*/
	bypass_rule[0] = (struct cmd_bypass_rule_pars_data){
		.saddr = ip_string_to_int("192.168.137.20"),
		.eaddr = ip_string_to_int("192.168.137.20")
	};

	bypass_rule[1] = (struct cmd_bypass_rule_pars_data){
                .saddr = ip_string_to_int("192.168.137.20"),
                .eaddr = ip_string_to_int("192.168.137.25")
        };

	bypass_rule[2] = (struct cmd_bypass_rule_pars_data){
                .saddr = ip_string_to_int("192.168.137.30"),
                .eaddr = ip_string_to_int("192.168.137.35")
        };


	if (argc > 1 )			
	{
		if (argc == 2 )
		{
			/*
				//Version 정보는 Kernel 내부에 static 으로 선언되어 있다, 버전 변경을 위해서는 소스변경이 필요
			*/
			if (strcmp (argv[1], "version") == 0 )
			{
				/*
					//#define IOCTL_GET_VERSION      _IOR(ND_IOCTL_MAGIC, 40,        char [MAX_VERSION_LENGTH])
					// 버전 요층 작업을 위해서는 char* 버퍼를 전달한다(_IOR 설정으로 설정 작업 없이 조회만 진행)
				*/
				sdk_get_NdaNfkDrv_version(szVersion);
				printf ("Version : %s\n", szVersion);
			}

			/*
				// 모듈의 상태를 조회한다. (load, unload)
				// 상태 조회는 /proc/modules 에 등록된 내용을 확인 한다
			*/
			else if (strcmp (argv[1], "status") == 0 )
			{
				/*
					//상태 조회는 /proc/modules 에 등록된 내용을 확인 한다(MODULE_NAME 내용과 동일한 등록 정보를 찾는다)
				*/
				if (is_module_loaded (MODULE_NAME) <= 0 )	{
					printf ("Status : Unloaded.\n");
				}
				else
					printf ("Status : loaded.\n");
			}
#ifdef _SUPP_SESSION_MON
			else if (strcmp (argv[1], "session") == 0 )
			{
				sdk_get_NdaNfkDrv_ManagedSessionCnt(szSessionCnt);
				printf ("Now Managed Session Cou:nt: %s\n", szSessionCnt);
			}
#endif //_SUPP_SESSION_MON
			
			/*
				//
			*/
			else if (strcmp (argv[1], "logs") == 0 )
			{
				/*
					// kernel 에서 저장하고 있는 log 를 요청한다.
					// kernel 에서 저장하는 로그는 각 로그가 최대 256 사이즈이며 256 개 까지 저장한다
					// MAX_LOG_COUNT에 도달하면 가장 오래된 로그를 삭제하고 신규로그를 저장한다.
					// 로그 요청 시 전달한 로그는 삭제 한다
				*/
				sdk_get_NdaNfkDrv_logs(log_buffer);
				printf ("%s\n", log_buffer);
			}
		}

		if (argc >= 3 )
		{
			/*
				// 운영모드는 커널 모듈의 가장 상단의 정책이며 ON/OFF로 구성된다
				// OFF 시 정책에 상관없이 커널 기능을 중지한다
			*/
			if (strcmp (argv[1], "mode") == 0)
			{
				if (strcmp (argv[2], "on") == 0 )
				{
					printf ("Mode info : on\n");
					sdk_NdaNfkDrv_start();
				}
				else if (strcmp (argv[2], "off") == 0 )
				{
					printf ("Mode info : off\n");
					sdk_NdaNfkDrv_stop();
				}
				else if (strcmp (argv[2], "get") == 0 )
				{
					sdk_get_NdaNfkDrv_state(szVersion);
					printf ("Status : %s\n", szVersion);
				} 
			}

			if (strcmp (argv[1], "logs") == 0)
			{
				if (strcmp (argv[2], "get") == 0)
				{
					sdk_get_NdaNfkDrv_log_setting(&log_config);
					printf ("WARN:[%d], ERROR[%d], INFO[%d], DEBUG[%d], TRACE[%d]\n", log_config.warn_log_enabled, log_config.error_log_enabled, log_config.info_log_enabled, log_config.debug_log_enabled, log_config.trace_log_enabled);
				}
				
				else if (strcmp (argv[2], "set") == 0 )
				{
					ndata = atoi(argv[3]);
					sdk_set_NdaNfkDrv_log_setting(ndata);
					printf ("log config setting level [%d]\n", ndata);
				}
			}
			
			/*
				//
			*/
			if (strcmp (argv[1], "rule") == 0 )
			{
				/*
					//
				*/
				if (strcmp(argv[2], "add") == 0 )
				{
					/*
						//
					*/
					if (strcmp(argv[3], "service") == 0 )
					{
						/*
							//
						*/
						for (int i = 0 ; i < 5 ; i ++ )		
						{
							sdk_add_NdaNfkDrv_service_policy(&policy[i]);
							printf ("add service rule...[%d][0x%x]\n",policy[i].ret, policy[i].ret);

						}
					}

					/*
						//
					*/
					else if (strcmp (argv[3], "action") == 0 )
					{
						/*

						*/
						for (int i = 0 ; i < 3; i ++ )
							sdk_add_NdaNfkDrv_action_policy(&subpolecyitm[i]);
					}

					/*
						//
					*/
					else if (strcmp (argv[3], "nic") == 0 )
					{
						/*
							//
						*/
						sdk_add_NdaNfkDrv_nic_rule(&nicrule);
					}

					/*
						//
					*/
					else if (strcmp (argv[3], "bypass") == 0 )
					{
						/*
							//
						*/
						for (int i = 0 ; i < 3 ; i ++ )
							sdk_add_NdaNfkDrv_bypass_rule(&bypass_rule[i]);
					}

				}
#ifdef _SUPP_MOD
				else if (strcmp (argv[2], "mod") == 0 )
				{
					if (strcmp (argv[3], "service") == 0 )
					{
						
						ret = sdk_get_NdaNfkDrv_service_policy_index(&policy);
						if (ret >= 0)		{
							ret = sdk_mod_NdaNfkDrv_service_policy_to_index(&policy);
							if (ret == 0)		{
								printf ("success modify service rule...\n");
							}
						}
					}
				}
#endif //_SUPP_MOD
				/*
					//
				*/
				else if (strcmp (argv[2], "del") == 0 )
				{
					/*
						//
					*/
					if (strcmp (argv[3], "service") == 0 )
					{
						/*
							// delete list
						*/
						/*
						for (int i = 0 ; i < 3 ; i ++ )	{
							sdk_del_NdaNfkDrv_service_policy(&policy[i]);
						}
						*/

						/*
							// delete target service rule set
						*/
						sdk_del_NdaNfkDrv_service_policy("7002");
					}

					/*
						//
					*/
					else if (strcmp (argv[3], "action") == 0 )
					{
						for (int i = 0 ; i < 3 ; i ++ )
							sdk_del_NdaNfkDrv_action_policy (&subpolecyitm[i]);
					}

					/*
						//
					*/
					else if (strcmp (argv[3], "nic") == 0 )
					{
						sdk_del_NdaNfkDrv_nic_rule(&nicrule);
					}

					/*
                                                //
                                        */
                                        else if (strcmp (argv[3], "bypass") == 0 )
                                        {
                                                /*
                                                        //
                                                */
                                                for (int i = 0 ; i < 3 ; i ++ )
                                                        sdk_del_NdaNfkDrv_bypass_rule(&bypass_rule[i]);
                                        }

				}
#ifdef _SUPP_RULE_GET
				else if (strcmp (argv[2], "get") == 0 )
				{
					if (strcmp (argv[3], "service") == 0 )
					{
						sdk_get_NdaNfkDrv_service_policy(szCmdRet);
						printf ("[service rule]\n%s\n", szCmdRet);
					}
				}
#endif //_SUPP_RULE_GET
				/*
					//
				*/
				else if (strcmp (argv[2], "reset") == 0 )
				{
					/*
						//
					*/
					sdk_reset_NdaNfkDrv_policy();
					sdk_reset_NdaNfkDrv_nic_rule();
					sdk_reset_NdaNfkDrv_bypass_rule();
				}

			}
		}
	}
	else
	{
		output_message(argv);
	}

	return 0;

}
