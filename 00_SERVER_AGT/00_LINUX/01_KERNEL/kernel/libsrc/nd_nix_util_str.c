#include "nd_nix_util_str.h"

/*
 *
 */
int check_delimiters(char *input) {
    char *pipe, *comma;

    pipe = strchr(input, '|');
    comma = strchr(input, ',');

    if (pipe == NULL || comma == NULL) {
        return -1;
    }

    return 0;
}

/*
 *
 */
int check_pipes(char *input)    {
        char *pipe;

        pipe = strchr(input, '|');

        if (pipe == NULL)       {
                return -1;
        }

        return 0;
}


/*
 *
 */
int check_commas(char *input)   {
        char *comma;

        comma = strchr(input, ',');

        if (comma == NULL)      {
                return -1;
        }

        return 0;
}


int strcat_safe(char *dest, const char *src, size_t dest_size)
{
    size_t dest_len = strlen(dest);
    size_t src_len = strlen(src);

    if (dest_len + src_len >= dest_size) {
        return -1; // 버퍼 오버플로우 방지
    }

    strncat(dest, src, dest_size - dest_len - 1);
    return 0;
}

__u32 string_to_u32(const char *str)
{
    char *endptr;
    unsigned long value;

    // 문자열을 unsigned long으로 변환
    value = simple_strtoul(str, &endptr, 10);

    // 변환된 값이 유효한지 확인
    if (*endptr != '\0') {
        //printk(KERN_ERR "Invalid input: %s\n", str);
        return 0; // 변환 실패 시 0 반환
    }

    // _u32로 변환
    if (value > UINT_MAX) {
        //printk(KERN_ERR "Value out of range: %lu\n", value);
        return 0; // 범위를 초과할 경우 0 반환
    }

    return (__u32)value;
}

