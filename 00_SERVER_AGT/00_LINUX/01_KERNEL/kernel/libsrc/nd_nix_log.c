#include "nd_nix_log.h"
#include <linux/list.h>
#include <linux/mutex.h>

struct st_log_level nd_log_level[] = {{LOG_INF, "INF"},{LOG_WAN,"WAN"},{LOG_DBG,"DBG"},{LOG_TRC,"TRC"},{LOG_ERR,"ERR"},};

static void get_timestamp(char *buffer, size_t size) {
    	struct timespec64 ts;
    	ktime_get_real_ts64(&ts); 

    	// yyyy-mm-dd hh:mm:ss.ffffff 
    	snprintf(buffer, size, "[%04lld%02lld%02lld %02lld%02lld%02lld.%06lld]",
             	(long long) ts.tv_sec / 86400 + 1970, 
             	((long long) ts.tv_sec / 3600 % 24) + 1, 
             	((long long) ts.tv_sec / 86400 % 30) + 1, 
             	(long long) (ts.tv_sec / 3600) % 24, 
             	(long long) (ts.tv_sec / 60) % 60, 
             	(long long) ts.tv_sec % 60, 
             	(long long) ts.tv_nsec / 1000); 
}


void nd_add_log (int level, char* filename, int line, const char *fmt, ...)	{

	struct log_entry *entry;
	char timestamp[50];
	va_list args;
	size_t len;
	char sLogMsg[LOG_MSG_SIZE] = {0,}, sBakStr[LOG_MSG_SIZE] = {0,};

	if ( 	(level == LOG_WAN && global_log_settings.warn_log_enabled 	== false)	||
	   	(level == LOG_DBG && global_log_settings.debug_log_enabled 	== false)	||
		(level == LOG_TRC && global_log_settings.trace_log_enabled 	== false) 	||
		(level == LOG_ERR && global_log_settings.error_log_enabled 	== false)	||
		(level == LOG_INF && global_log_settings.info_log_enabled	== false)
	)	
	{
		return;
	}
	


    	get_timestamp(timestamp, sizeof(timestamp));

    	va_start(args, fmt);

	vsnprintf (sBakStr, sizeof (sBakStr), fmt, args);

	va_end (args);

	len = strlen(sBakStr);

	if (len == 0 || sBakStr[len - 1] != '\n') {
		snprintf (sLogMsg, sizeof (sLogMsg), "%s(%s) <%s:%d>	%s\n",timestamp, nd_log_level[level].stLevel, filename, line, sBakStr);
	}else	{
		snprintf (sLogMsg, sizeof (sLogMsg), "%s(%s) <%s:%d> %s",timestamp, nd_log_level[level].stLevel, filename, line, sBakStr);
	}
	
	mutex_lock(&log_mutex);
	
	if (nd_log_count >= MAX_LOGS)	{
		struct log_entry * old_entry = list_first_entry (&log_list.list, struct log_entry, list);
		list_del (&old_entry->list);
		kfree (old_entry);
		nd_log_count --;
	}

	entry = kmalloc (sizeof (struct log_entry), GFP_KERNEL);
	if (entry)	{

		strncpy (entry->message, sLogMsg , LOG_MSG_SIZE -1 );
		entry->message[LOG_MSG_SIZE -1] = '\0';
		list_add_tail (&entry->list, &log_list.list);
		nd_log_count ++;
	}

	mutex_unlock(&log_mutex);
}

ssize_t nd_get_logs (char __user *buf , size_t count)	{

	struct log_entry *entry/*, *tmp*/;
	struct list_head *pos, *next;
	int processed_logs = 0;


	size_t total_length = 0;
	//char temp_buffer[MAX_BUFFER_SIZE];

	if (buf == NULL || count == 0)	{
		printk ("nd_get_logs :: buf is NULL");
		return -EINVAL;
	}

	if (!access_ok(buf, count)) {
        	printk("nd_get_logs: User buffer access is invalid.");
        	return -EFAULT;
    	}


	while (processed_logs < MAX_LOGS)	{
		
		mutex_lock(&log_mutex);

		if (list_empty(&log_list.list))		{

			mutex_unlock(&log_mutex);
			break;
		}

		list_for_each_safe (pos, next, &log_list.list)	{
			entry = list_entry (pos, struct log_entry, list);
			if (entry)	{
				size_t entry_length = strlen(entry->message);

				if (total_length + entry_length + (total_length > 0 ? 1 : 0) > count)	{
					mutex_unlock(&log_mutex);
					goto exit;
				}

				if (copy_to_user (buf + total_length, entry->message, entry_length))    {
					printk ("nd_get_log: test 008\n");
					mutex_unlock (&log_mutex);
					return -EFAULT;
				}

				total_length += entry_length;

				list_del(pos);
				kfree(entry);
				nd_log_count--;

				processed_logs++;

				if (processed_logs >= MAX_LOGS)		{
					mutex_unlock (&log_mutex);
					break;
				}
			}
		}
		mutex_unlock(&log_mutex);

	}

exit:


	return total_length;
}

void set_debug_log_enabled(bool enabled)	{

	mutex_lock(&log_mutex);
	global_log_settings.debug_log_enabled = enabled;
	mutex_unlock(&log_mutex);
}

void set_warn_log_enabled(bool enabled)		{

	mutex_lock(&log_mutex);
	global_log_settings.warn_log_enabled = enabled;
	mutex_unlock(&log_mutex);
}

void set_trace_log_enabled(bool enabled)	{

	mutex_lock(&log_mutex);
	global_log_settings.trace_log_enabled = enabled;
	mutex_unlock(&log_mutex);
}

void set_info_log_enabled(bool enabled)		{

	mutex_lock(&log_mutex);
	global_log_settings.info_log_enabled = enabled;
	mutex_unlock(&log_mutex);
}

void set_error_log_enabled(bool enabled)		{

	mutex_lock(&log_mutex);
        global_log_settings.error_log_enabled = enabled;
        mutex_unlock(&log_mutex);
}

bool get_debug_log_enabled(void)		{

	bool enabled;
	mutex_lock(&log_mutex);
	enabled = global_log_settings.debug_log_enabled;
        mutex_unlock(&log_mutex);
	return enabled;
}

bool get_warn_log_enabled(void)			{

	bool enabled;
	mutex_lock(&log_mutex);
	enabled = global_log_settings.warn_log_enabled;
        mutex_unlock(&log_mutex);
	return enabled;
}

bool get_trace_log_enabled(void)		{

	bool enabled;
	mutex_lock(&log_mutex);
	enabled = global_log_settings.trace_log_enabled;
        mutex_unlock(&log_mutex);
	return enabled;
}

bool get_info_log_enabled(void)			{

	bool enabled;
	mutex_lock(&log_mutex);
	enabled = global_log_settings.info_log_enabled;
        mutex_unlock(&log_mutex);
	return enabled;
}

bool get_error_log_enabled(void)		{

	bool enabled;
	mutex_lock(&log_mutex);
        enabled = global_log_settings.error_log_enabled;
        mutex_unlock(&log_mutex);
        return enabled;

}
