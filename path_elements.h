#define PATH_SEGMENTS 64
#define PATH_SEGMENT_LEN 255

#ifndef __PATH_ELEMENTS
#define __PATH_ELEMENTS

typedef unsigned char path_segment[PATH_SEGMENT_LEN];

struct path_elements
{
    unsigned int path_elements_length;
    path_segment path_elements[PATH_SEGMENTS]
    // unsigned char path_elements[PATH_SEGMENT_LEN][PATH_SEGMENTS];
};

#endif