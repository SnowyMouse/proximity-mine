// SPDX-License-Identifier: GPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef int8_t fbyte;

static fbyte *read_file(const char *path, size_t *size);
static bool write_file(const char *path, const fbyte *data, size_t size);
static void verify_map(fbyte *data, size_t size, const char *path);

// Hold our file offsets
struct FileOffset {
    uint32_t *offset; // pointer to offset
    uint32_t size; // size of pointed data
};
struct FileOffsetArray {
    size_t size; // number of offsets that are valid
    struct FileOffset *offsets; // offsets to store
    size_t allocated; // size of array
};

static void push_to_array(struct FileOffsetArray *array, uint32_t *offset, uint32_t size);
static void initialize_array(struct FileOffsetArray *array);
static void free_array(struct FileOffsetArray *array);

static const uint32_t TAG_DATA_OFFSET = 0x10;
static const uint32_t TAG_DATA_LENGTH = 0x14;
static const uint32_t UNCOMPRESSED_FILE_SIZE = 0x8;
static const uint32_t HEADER_SIZE = 0x800;

#define TRANSLATE_POINTER(what) (tag_data + ((what) - 0x40440000))
#define TRANSLATE_POINTER_PTR(what) TRANSLATE_POINTER(*(const uint32_t *)(what))

static void handle_scenario(fbyte *tag_data, fbyte *tag, struct FileOffsetArray *array);
static void handle_sound(fbyte *tag_data, fbyte *tag, struct FileOffsetArray *array, const fbyte *sounds, const fbyte *data);
static void handle_bitmap(fbyte *tag_data, fbyte *tag, struct FileOffsetArray *array, const fbyte *bitmaps, const fbyte *data);

int main(int argc, const char **argv) {
    // Tell them what we need to know
    if(argc != 5 && argc != 3) {
        printf("Usage: %s <input-map> [<bitmaps.map> <sounds.map>] <output-map>\n", *argv);
        return EXIT_SUCCESS;
    }

    // Make an offset array
    struct FileOffsetArray array;
    initialize_array(&array);

    // Read the file
    int return_value = EXIT_SUCCESS;
    size_t data_size;
    fbyte *data;
    if((data = read_file(argv[1], &data_size)) == NULL) {
        return_value = EXIT_FAILURE;
        goto FAIL_DATA;
    }

    // Verify it
    verify_map(data, data_size, argv[1]);

    // Read the bitmap and sound stuff
    size_t bitmap_size, sound_size;
    fbyte *bitmaps = NULL, *sounds = NULL;
    if(argc == 5) {
        if((bitmaps = read_file(argv[2], &bitmap_size)) == NULL || (sounds = read_file(argv[3], &sound_size)) == NULL) {
            return_value = EXIT_FAILURE;
            goto FAIL_BITMAP_SOUNDS;
        }
    }

    // Zero out file size so we don't have to deal with it
    *(uint32_t *)(data + UNCOMPRESSED_FILE_SIZE) = 0;

    // Get offsets
    fbyte *tag_data = data + *(uint32_t *)(data + TAG_DATA_OFFSET);
    uint32_t tag_data_size = *(uint32_t *)(data + TAG_DATA_LENGTH);

    // Add model data offsets
    const uint32_t MODEL_DATA_FILE_OFFSET = 0x14;
    const uint32_t MODEL_DATA_FILE_SIZE = 0x20;
    push_to_array(&array, (uint32_t *)(tag_data + MODEL_DATA_FILE_OFFSET), *(uint32_t *)(tag_data + MODEL_DATA_FILE_SIZE));

    // Get the tag count
    const uint32_t TAG_COUNT = *(uint32_t *)(tag_data + 0xC);
    const fbyte *TAG_ARRAY = TRANSLATE_POINTER_PTR(tag_data);

    // Go through each tag
    for(uint32_t i = 0; i < TAG_COUNT; i++) {
        const fbyte *tag = TAG_ARRAY + i * 0x20;

        // If the tag is indexed, ignore it
        if(*(const uint32_t *)(tag + 0x18)) {
            continue;
        }

        // Get the tag data
        fbyte *tag_data_d = TRANSLATE_POINTER_PTR(tag + 0x14);

        // Check the tag class
        switch(*(const uint32_t *)(tag + 0x0)) {
            // Scenario tag
            case 0x73636E72:
                handle_scenario(tag_data, tag_data_d, &array);
                break;

            // Sound tag
            case 0x736E6421:
                handle_sound(tag_data, tag_data_d, &array, sounds, data);
                break;

            // Bitmap tag
            case 0x6269746D:
                handle_bitmap(tag_data, tag_data_d, &array, bitmaps, data);
                break;
        }
    }

    // Get the maximum size possible so we know where to begin when we allocate
    size_t max_size = HEADER_SIZE + tag_data_size;
    for(size_t i = 0; i < array.size; i++) {
        max_size += array.offsets[i].size;
    }
    fbyte *final_data = malloc(max_size);
    size_t current_offset = HEADER_SIZE;

    // Go through each block
    for(size_t i = 0; i < array.size; i++) {
        // Can we dedupe?
        uint32_t *b_offset_i = array.offsets[i].offset;
        const fbyte *b_data_i = data + *b_offset_i;
        const size_t b_size_i = array.offsets[i].size;
        bool deduped = false;
        for(size_t j = 0; j < i; j++) {
            const uint32_t *b_offset_j = array.offsets[j].offset;
            const fbyte *b_data_j = data + *b_offset_j;
            const size_t b_size_j = array.offsets[j].size;

            // If it's the same size, we can dedupe this
            if(b_size_i == b_size_j && memcmp(b_data_i, b_data_j, b_size_i) == 0) {
                deduped = true;
                *b_offset_i = *b_offset_j;
                break;
            }
        }

        // If we deduped it, continue
        if(deduped) {
            continue;
        }

        // Copy it over and set the offset to the new one
        memcpy(final_data + current_offset, b_data_i, b_size_i);
        *b_offset_i = current_offset;
        current_offset += b_size_i;
    }

    // Finish assembling the data
    *(uint32_t *)(data + TAG_DATA_OFFSET) = current_offset;
    memcpy(final_data + current_offset, tag_data, tag_data_size);
    memcpy(final_data, data, HEADER_SIZE);

    // Write the data to disk
    write_file(argv[argc - 1], final_data, current_offset + tag_data_size);

    // Done
    FAIL_BITMAP_SOUNDS:
    free(bitmaps);
    free(sounds);

    FAIL_DATA:
    free(data);
    free_array(&array);
    return return_value;
}

static fbyte *read_file(const char *path, size_t *size) {
    // Open
    FILE *f = fopen(path, "rb");
    if(!f) {
        fprintf(stderr, "read_file(): Failed to read %s\n", path);
        return NULL;
    }

    // Get size
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Read it
    fbyte *data = malloc(*size);
    fread(data, *size, 1, f);
    fclose(f);

    return data;
}

static void verify_map(fbyte *data, size_t size, const char *path) {
    // Do some basic checks (NOT FOOLPROOF but it should fail most obvious non-maps)
    const uint32_t ENGINE_VERSION = 4;
    const uint32_t HEAD = 0x68656164;
    const uint32_t FOOT = 0x666F6F74;
    const uint32_t CUSTOM_ENGINE_VERSION = 609;
    const uint32_t RETAIL_ENGINE_VERSION = 7;
    if(
        size < HEADER_SIZE ||
        *(uint32_t *)(data + 0x0) != HEAD ||
        *(uint32_t *)(data + 0x7FC) != FOOT ||
        (*(uint32_t *)(data + ENGINE_VERSION) != RETAIL_ENGINE_VERSION && *(uint32_t *)(data + ENGINE_VERSION) != CUSTOM_ENGINE_VERSION) ||
        size < *(uint32_t *)(data + TAG_DATA_OFFSET) ||
        size < *(uint32_t *)(data + TAG_DATA_LENGTH) ||
        (uint64_t)size < (uint64_t)*(uint32_t *)(data + TAG_DATA_OFFSET) + (uint64_t)*(uint32_t *)(data + TAG_DATA_LENGTH)
    ) {
        free(data);
        fprintf(stderr, "verify_map(): %s has an invalid header or is not a Halo PC cache file\n", path);
        exit(EXIT_FAILURE);
    }
}

static void push_to_array(struct FileOffsetArray *array, uint32_t *offset, uint32_t size) {
    // Increment
    array->size++;

    // If we've hit capacity, reallocate
    if(array->size >= array->allocated) {
        array->allocated *= 2;
        array->offsets = realloc(array->offsets, sizeof(*array->offsets) * array->allocated);
    }

    // Set it
    array->offsets[array->size - 1].offset = offset;
    array->offsets[array->size - 1].size = size;
}

static void initialize_array(struct FileOffsetArray *array) {
    array->allocated = 64;
    array->size = 0;
    array->offsets = malloc(sizeof(*array->offsets) * array->allocated);
}

static void free_array(struct FileOffsetArray *array) {
    free(array->offsets);
}

static void handle_scenario(fbyte *tag_data, fbyte *tag, struct FileOffsetArray *array) {
    uint32_t bsp_count = *(uint32_t *)(tag + 0x5A4);
    fbyte *bsps = TRANSLATE_POINTER_PTR(tag + 0x5A4 + 0x4);

    // Add each BSP
    for(uint32_t i = 0; i < bsp_count; i++) {
        fbyte *bsp = bsps + i * 0x20;
        push_to_array(array, (uint32_t *)(bsp + 0x0), *(uint32_t *)(bsp + 0x4));
    }
}

static const fbyte *find_data(const fbyte *data, size_t size, const fbyte *resource) {
    uint32_t count = *(uint32_t *)(resource + 0xC);
    const fbyte *indices = resource + *(uint32_t *)(resource + 0x8);
    for(uint32_t i = 0; i < count; i++, indices += 0xC) {
        uint32_t index_size = *(uint32_t *)(indices + 0x4);
        const fbyte *index_data = resource + *(uint32_t *)(indices + 0x8);

        // Is this a match?
        if(index_size == size && memcmp(data, index_data, size) == 0) {
            return index_data;
        }
    }
    return NULL;
}

static void handle_sound(fbyte *tag_data, fbyte *tag, struct FileOffsetArray *array, const fbyte *sounds, const fbyte *data) {
    uint32_t pitch_range_count = *(uint32_t *)(tag + 0x98);
    fbyte *pitch_ranges = TRANSLATE_POINTER_PTR(tag + 0x98 + 0x4);

    // Add each bitmap data
    for(uint32_t pr = 0; pr < pitch_range_count; pr++) {
        fbyte *pitch_range = pitch_ranges + pr * 72;

        size_t permutation_count = *(uint32_t *)(pitch_range + 0x3C);
        fbyte *permutations = TRANSLATE_POINTER_PTR(pitch_range + 0x3C + 0x4);

        for(uint32_t p = 0; p < permutation_count; p++) {
            fbyte *permutation = permutations + p * 124;

            // Are we external? If so, skip...
            const uint16_t EXTERNAL_FLAG = 1;
            uint32_t *external = (uint32_t *)(permutation + 0x40 + 4);
            if(*external & EXTERNAL_FLAG) {
                continue;
            }

            // Next, look for it!
            uint32_t *offset = (uint32_t *)(permutation + 0x40 + 8);
            uint32_t *size = (uint32_t *)(permutation + 0x40);
            if(sounds) {
                const fbyte *res = find_data(data + *offset, *size, sounds);
                if(res) {
                    *external |= EXTERNAL_FLAG;
                    *offset = (res - sounds);
                    continue;
                }
            }

            // Not present? OK!
            push_to_array(array, offset, *size);
        }
    }
}

static void handle_bitmap(fbyte *tag_data, fbyte *tag, struct FileOffsetArray *array, const fbyte *bitmaps, const fbyte *data) {
    uint32_t bitmap_data_count = *(uint32_t *)(tag + 0x60);
    fbyte *bitmap_data = TRANSLATE_POINTER_PTR(tag + 0x60 + 0x4);

    // Add each bitmap data
    for(uint32_t i = 0; i < bitmap_data_count; i++) {
        fbyte *bitmap = bitmap_data + i * 0x30;

        // Are we external? If so, skip...
        const uint16_t EXTERNAL_FLAG = (1 << 8);
        uint16_t *external = (uint16_t *)(bitmap + 0xE);
        if(*external & EXTERNAL_FLAG) {
            continue;
        }

        // Next, look for it!
        uint32_t *offset = (uint32_t *)(bitmap + 0x18);
        uint32_t *size = (uint32_t *)(bitmap + 0x1C);
        if(bitmaps) {
            const fbyte *res = find_data(data + *offset, *size, bitmaps);
            if(res) {
                *external |= EXTERNAL_FLAG;
                *offset = (res - bitmaps);
                continue;
            }
        }

        // Not present? OK!
        push_to_array(array, offset, *size);
    }
}

static bool write_file(const char *path, const fbyte *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if(!f) {
        fprintf(stderr, "write_file(): Failed to open %s for writing\n", path);
        return false;
    }

    if(!fwrite(data, size, 1, f)) {
        fprintf(stderr, "write_file(): Failed to write %zu bytes to %s\n", size, path);
        return false;
    }

    fclose(f);
    return true;
}
