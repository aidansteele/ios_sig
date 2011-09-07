#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#pragma pack(1)
struct sc_info_record
{
    uint32_t length;
    uint8_t key[4];
    union {
        uint8_t *data;
        struct
        {
            uint32_t count;
            struct sc_info_record **records;
        } children;        
    } value;
};
#pragma pack()

int key_is_aggregate(uint8_t *key);
struct sc_info_record *sc_info_record_alloc(void *ptr);
void sc_info_record_free(struct sc_info_record *record);
void sc_info_record_printf(struct sc_info_record *record, int depth);
void hex_print(uint8_t *bytes, int length);

int key_is_aggregate(uint8_t *key)
{
    char *aggrs[] = 
    {
        "sinf",
        "schi",
    };
    
    int count = sizeof(aggrs)/sizeof(*aggrs);
    for (int i = 0; i < count; i++)
    {
        if (memcmp(key, aggrs[i], 4) == 0) return 1;
    }
    
    return 0;
}

struct sc_info_record *sc_info_record_alloc(void *ptr)
{
    struct sc_info_record *record = calloc(1, sizeof(struct sc_info_record));
    struct sc_info_record *src = ptr;
    
    record->length = __builtin_bswap32(src->length);
    memcpy(record->key, src->key, sizeof(record->key));
    
    if (key_is_aggregate(record->key))
    {
        ptr += 8;        
        while (ptr < (void *)src + record->length)
        {
            struct sc_info_record *child_record = sc_info_record_alloc(ptr);
            ptr += child_record->length;
            
            int idx = record->value.children.count++;
            record->value.children.records = realloc(record->value.children.records, record->value.children.count*sizeof(struct sc_info_record *));
            record->value.children.records[idx] = child_record;
        }
    }
    else
    {
        record->value.data = malloc(record->length - 8);
        memcpy(record->value.data, &src->value.data, record->length - 8);
    }
    
    return record;
}

void sc_info_record_free(struct sc_info_record *record)
{
    if (key_is_aggregate(record->key))
    {
        for (int i = 0; i < record->value.children.count; i++)
        {
            sc_info_record_free(record->value.children.records[i]);
        }
        
        free(record->value.children.records);
    }
    else
    {
        free(record->value.data);
    }
    
    free(record);
}

void hex_print(uint8_t *bytes, int length)
{
    for (uint8_t *iter = bytes; iter < bytes + length; iter++)
    {
        printf("%02x", *iter);
    }
}

void sc_info_record_printf(struct sc_info_record *record, int depth)
{
    for (int i = 0; i < depth; i++) printf("\t");
    printf("%.*s: ", (int)sizeof(record->key), record->key);
    
    if (key_is_aggregate(record->key))
    {
        printf("\n");
        for (int i = 0; i < record->value.children.count; i++)
        {
            sc_info_record_printf(record->value.children.records[i], depth + 1);
        }
    }
    else
    {
        int length = record->length - 8;
        if (length > 16) length = 16;
        
        hex_print(record->value.data, length);
        printf("\n");
    }
}

int main (int argc, const char * argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "[usage:] ios_sig <file>.sinf\n");
        return 1;
    }
    else
    {
        const char *path = argv[1];
        int fd = open(path, O_RDONLY);
        
        char *file = mmap(0, 1032, PROT_READ, MAP_PRIVATE, fd, 0);
        struct sc_info_record *record = sc_info_record_alloc(file);
        sc_info_record_printf(record, 0);
        sc_info_record_free(record);
        
        munmap(file, 1032);
        close(fd);
        
        return 0;
    }
}
