struct ringbuf_event
{
    int path_elements_length;
    unsigned char path_elements[255][64];
};