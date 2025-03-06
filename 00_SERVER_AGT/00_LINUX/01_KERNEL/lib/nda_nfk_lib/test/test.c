#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

#include "nd_nix_nfm_lib.h"

int main(int argc, char** argv)	{

	struct cmd_service_rule_pars_data policy = {1,1031, 2031, 1};

	if (argc == 3 )
	{
		if (strcmp (argv[1], "mode") == 0)
		{
			if (strcmp (argv[2], "on") == 0 )
			{
				printf ("mode on\n");
				sdk_NdNixNfmDrv_start();
			}
			else if (strcmp (argv[2], "off") == 0 )
			{
				printf ("mode off\n");
				sdk_NdNixNfmDrv_stop();
			}
		}

		if (strcmp (argv[1], "rule") == 0 )
		{
			if (strcmp(argv[2], "add") == 0 )
			{
				sdk_add_NdNixNfmDrv_service_policy(&policy);
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
