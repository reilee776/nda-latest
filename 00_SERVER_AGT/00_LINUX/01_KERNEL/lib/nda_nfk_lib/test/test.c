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
}
