#define PATH_SEGMENTS 64
#define PATH_SEGMENT_LEN 255

#ifndef __PATH_ELEMENTS
#define __PATH_ELEMENTS

struct path_elements
{
    int path_elements_length;
    unsigned char path_elements[PATH_SEGMENT_LEN][PATH_SEGMENTS];
};

#endif