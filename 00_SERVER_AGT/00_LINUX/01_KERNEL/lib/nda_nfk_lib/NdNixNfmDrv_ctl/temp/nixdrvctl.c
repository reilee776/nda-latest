#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

#include "nd_nix_nfm_lib.h"

#define MODULE_NAME "nd_nix_nfm"

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

int main(int argc, char** argv)	{

	char szVersion[16] = {0,};
	char szCmdRet[1024] = {0,};
	int ret = 0;
	struct cmd_service_rule_pars_data policy = {1,1031, 2031, 1};
	struct cmd_service_sub_rule_pars_data subpolicy[] = {{1031, 0, 3232300517, 0, 0},{1031, 0,3232300518,0,0},{1031, 1,32513195,32513197,0}}; 
	struct cmd_service_sub_rule_pars_data subpolecyitm = {1031, 1, 32513195, 32513197, 0};

	struct cmd_service_sub_rule_pars_data subpolecy_sourceip = {1031, 0, 32513196, 0, 0};

	size_t excount = sizeof(subpolicy) / sizeof(subpolicy[0]);

	if (argc == 2 )
	{
		if (strcmp (argv[1], "version") == 0 )
		{

			sdk_get_NdNixNfmDrv_version(szVersion);
			printf ("Version : %s\n", szVersion);
		}

		else if (strcmp (argv[1], "status") == 0 )
		{
			if (is_module_loaded (MODULE_NAME) <= 0 )	{
				printf ("Status : Unloaded.\n");
			}
			else
				printf ("Status : loaded.\n");
		}
	}

	if (argc >= 3 )
	{
		if (strcmp (argv[1], "mode") == 0)
		{
			if (strcmp (argv[2], "on") == 0 )
			{
				printf ("Mode info : on\n");
				sdk_NdNixNfmDrv_start();
			}
			else if (strcmp (argv[2], "off") == 0 )
			{
				printf ("Mode info : off\n");
				sdk_NdNixNfmDrv_stop();
			}
			else if (strcmp (argv[2], "get") == 0 )
			{
				sdk_get_NdNixNfmDrv_state(szVersion);
				printf ("Status : %s\n", szVersion);
			} 
		}
	
		if (strcmp (argv[1], "rule") == 0 )
		{
			if (strcmp(argv[2], "add") == 0 )
			{
				if (strcmp(argv[3], "service") == 0 )
                        	{
                                	sdk_add_NdNixNfmDrv_service_policy(&policy);
					printf ("add service rule...[%d][0x%x]\n",policy.ret, policy.ret);
                        	}

				else if (strcmp(argv[3], "except") == 0 )
                        	{
					for (int i = 0 ; i < excount ; i ++ )	{
                                		sdk_add_NdNixNfmDrv_fakeExcept_policy(&subpolicy[i]);
						printf ("add service fake except rule...[%d][0x%x]\n",subpolicy[i].ret, subpolicy[i].ret);
					}
					//printf ("add service fake except rule...[%d][0x%x]\n",subpolicy[i].ret, subpolicy[i].ret);
                        	}

			}

			else if (strcmp (argv[2], "mod") == 0 )
			{
				if (strcmp (argv[3], "service") == 0 )
				{
					ret = sdk_get_NdNixNfmDrv_service_policy_index(&policy);
					if (ret >= 0)		{
						ret = sdk_mod_NdNixNfmDrv_service_policy_to_index(&policy);
						if (ret == 0)		{
							printf ("success modify service rule...\n");
						}
					}
				}

				else if (strcmp (argv[3], "except") == 0 )
				{
					ret = sdk_get_NdNixNfmDrv_fakeexcept_policy_index(&subpolecyitm);
					if (ret >= 0)		{
						ret = sdk_mod_NdNixNfmDrv_fakeexcept_policy_to_index(&subpolecyitm);
						if (ret == 0)		{
							printf ("success modify forward except rule...\n");
						}
					}
				}

				else if (strcmp (argv[3], "sourceip") == 0 )
				{
					ret = sdk_mod_NdNixNfmDrv_fakeexcept_policy_to_index(&subpolecy_sourceip);
					if (ret >= 0 )		{
						ret = sdk_mod_NdNixNfmDrv_sourceips_policy_to_index(&subpolecy_sourceip);
						if (ret == 0 )		{
							printf ("success modify sourceip rule...\n");
						}
					}
				}
			}

			else if (strcmp (argv[2], "del") == 0 )
			{
				if (strcmp (argv[3], "service") == 0 )
				{
					sdk_del_NdNixNfmDrv_service_policy(&policy);
				}

				else if (strcmp (argv[3], "except") == 0 )
				{
					sdk_del_NdNixNfmDrv_fakeexcept_policy(&subpolecyitm);
				}
			}

			else if (strcmp (argv[2], "get") == 0 )
			{
				if (strcmp (argv[3], "service") == 0 )
				{
					sdk_get_NdNixNfmDrv_service_policy(szCmdRet);
					printf ("[service rule]\n%s\n", szCmdRet);
				}

				else if (strcmp (argv[3], "except") == 0 )
				{
					sprintf (szCmdRet, "%d", policy.service);
					sdk_get_NdNixNfmDrv_fakeexcept_policy(szCmdRet);
					printf ("[service %d except rule]\n%s\n", policy.service,szCmdRet);
				}

				else if (strcmp (argv[3], "exceptI") == 0 )
				{
					sdk_get_NdNixNfmDrv_fakeexcept_policy_index(&subpolecyitm);
					printf ("FakeExcept Rule index is [%d]\n", subpolecyitm.ret);
				}
			}

			else if (strcmp (argv[2], "reset") == 0 )
			{
				sdk_reset_NdNixNfmDrv_policy();
			}

		}
	}

	return 0;
#ifdef _OLD_TEST
	server_mode_on();

	add_service_policy(&policy);

	 char getruledatas[1024] = {0,};
        if (get_service_policy(getruledatas) < 0)
        {
                printf ("failed to get service rules..\n");
                return -1;
        }

        printf ("success get service rule data...\n%s\n", getruledatas);

//	server_mode_off();

/*
	struct cmd_service_rule_pars_data policy[8] = {	{1,2032,1032,1},
							{1,2033,1033,1},
							{1,2034,1034,1},
							{1,2035,1035,1},
							{1,2036,1036,1},
							{1,2037,1037,1},
							{1,2038,1038,1},
							{1,2039,1039,1}
	};

	struct cmd_service_sub_rule_pars_data fakeexcept[] = { 
								{2032,1,3232300812,3232300815},
								{2032,0,3232300517,0},
								{2032,0,3232300519,0},
								{2033,0,3232300813,0},
								{2033,1,3232300517,3232300527},
								{2034,0,3232300814,0},
								{2035,0,3232300815,0},
								{2036,1,3232300816,3232300820},
								{2037,0,3232300817,0},
								{2038,0,3232300818,0},
								{2039,0,3232300819,0}
	};




	size_t count = sizeof(policy) / sizeof(policy[0]);
	size_t excount = sizeof(fakeexcept) / sizeof(fakeexcept[0]);
	for (int i = 0 ; i < count ; i ++)	{
		if (add_service_policy(&policy[i]) < 0 )	{

			printf ("failed to add policy...\n");
			return -1;
		}
		printf ("success to add policy...[%d]\n",i);

	}
	
	for (int i = 0 ; i < excount ; i ++ )		{

		if (add_fakeexcept_policy(&fakeexcept[i]) < 0)	{
			printf ("failed to add fakeexcept policy...\n");
			return -1;
		}

		printf ("success to add fakeexcept policy...[%d]\n",i);		
	}
*/
/*
	char data[1024] = {0,};
	if (get_policy(data) > 0 )			{
		printf ("failed to get policy...\n");
		return -1;
	}

	printf ("success to get policy..\n%s\n", data);
*/
/*
	if (del_service_policy(&policy[i]) < 0 )	{
		printf ("failed to del policy...\n");
		return -1;
	}

	printf ("success to del policy...\n");
*/
	//printf ("i count is [%d]\n", i);
	///sleep(10);
/*

	char getruledatas[1024] = {0,};
	if (get_service_policy(getruledatas) < 0)
	{
		printf ("failed to get service rules..\n");
		return -1;
	}

	printf ("success get service rule data...\n%s\n", getruledatas);

	for (int i = 0 ; i < count ; i ++ )
	{
		memset (&getruledatas, 0, sizeof(getruledatas));
		sprintf (getruledatas, "%u",policy[i].service); 
		if (get_fakeexcept_policy(getruledatas) < 0 )	{
			printf ("failed to get fakeexcept rules...\n");
			return -1;
		}

		printf ("success get fakeexcept rule data...\n%s\n", getruledatas);
	}

	if (reset_policy() < 0 )
	{
		printf ("failed to reset policy...\n");
		return -1;
	}

	printf ("success reset policy..\n");
*/
/*
	if (add_policy(policy) < 0 )    {

                printf ("failed to add policy...\n");
                return -1;
        }

        printf ("success to add policy...\n");
           
	if (reset_policy() < 0 )	{
		printf ("failed to reset policy...\n");
		return -1;
	}

	printf ("success to reset policy...\n");

*/
#endif //_OLD_TEST
	return 0;

}
